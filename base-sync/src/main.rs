use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, BaseCommand, BaseCommandKind, BaseEvent, BaseEventKind, Broker,
        ConsumerError, ConsumerHandler,
    },
    db::{postgres::PostgresPool, Client as DatabaseClient, Pool as DatabasePool},
    domain::{Platform, Sync, SyncState},
    init_tracing,
    spotify::{rspotify::RSpotifyClient, Client as SpotifyClient},
};
use chrono::Utc;
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Sender},
};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use self::{
    cfg::Config,
    sync::{Error as SyncError, SpotifySynchronizer, Synchronizer},
};

// Error

#[derive(Debug)]
enum Error {
    BaseNotFound,
    DatabaseClient(Box<dyn StdError + Send + StdSync>),
    Sync(SyncError),
    SyncAlreadyRunning,
    UserNotFound(Uuid),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BaseNotFound => write!(f, "base doesn't exist"),
            Self::DatabaseClient(err) => write!(f, "{err}"),
            Self::Sync(err) => write!(f, "{err}"),
            Self::SyncAlreadyRunning => write!(f, "sync is already running"),
            Self::UserNotFound(id) => write!(f, "user {id} doesn't exist"),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match self {
            Self::BaseNotFound => None,
            Self::DatabaseClient(err) => Some(err.as_ref()),
            Self::Sync(err) => Some(err),
            Self::SyncAlreadyRunning => None,
            Self::UserNotFound(_) => None,
        }
    }
}

// Handler

struct Handler {
    db_pool: Arc<Box<dyn DatabasePool>>,
    spotify_synchronizer: Arc<Box<dyn Synchronizer>>,
}

impl Handler {
    #[inline]
    async fn handle(&self, base_id: &Uuid) -> Result<(), ConsumerError> {
        let db_client = self
            .db_pool
            .client()
            .await
            .map_err(ConsumerError::with_requeue)?;
        let repos = db_client.repositories();
        let base_repo = repos.base();
        match self.sync(base_id, db_client.as_ref()).await {
            Ok(mut sync) => {
                let res = base_repo
                    .delete_track_by_id_sync_not(base_id, &sync.last_id)
                    .await;
                if let Err(err) = res {
                    sync.last_err_msg = Some(err.to_string());
                    sync.state = SyncState::Failed;
                }
                self.update_sync(base_id, &sync, db_client.as_ref()).await
            }
            Err(err) => match err {
                Error::BaseNotFound => {
                    warn!("sync of base {base_id} is ignored: {err}");
                    Ok(())
                }
                Error::DatabaseClient(err) => Err(ConsumerError::with_requeue(err)),
                Error::Sync(err) => {
                    let err_str = err.to_string();
                    let mut sync = err.sync;
                    sync.last_err_msg = Some(err_str);
                    self.update_sync(base_id, &sync, db_client.as_ref()).await
                }
                Error::SyncAlreadyRunning => {
                    warn!("sync of base {base_id} is ignored: {err}");
                    Ok(())
                }
                Error::UserNotFound(_) => {
                    warn!("sync of base {base_id} is ignored: {err}");
                    Ok(())
                }
            },
        }
    }

    #[inline]
    async fn sync(&self, base_id: &Uuid, db_client: &dyn DatabaseClient) -> Result<Sync, Error> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let base = base_repo
            .get_by_id(base_id)
            .await
            .map_err(Error::DatabaseClient)?
            .ok_or(Error::BaseNotFound)?;
        let user = user_repo
            .get_by_id(&base.user_id)
            .await
            .map_err(Error::DatabaseClient)?
            .ok_or_else(|| Error::UserNotFound(base.user_id))?;
        let sync = base_repo
            .lock_sync(base_id, Uuid::new_v4(), Utc::now())
            .await
            .map_err(Error::DatabaseClient)?
            .ok_or(Error::SyncAlreadyRunning)?;
        match base.platform {
            Platform::Spotify => self
                .spotify_synchronizer
                .sync(&base, sync, &user.id)
                .await
                .map_err(Error::Sync),
        }
    }

    #[inline]
    async fn update_sync(
        &self,
        base_id: &Uuid,
        sync: &Sync,
        db_client: &dyn DatabaseClient,
    ) -> Result<(), ConsumerError> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        base_repo
            .update_sync(base_id, sync)
            .await
            .map_err(ConsumerError::with_requeue)
    }
}

#[async_trait]
impl ConsumerHandler<BaseCommand> for Handler {
    async fn handle(&self, cmd: BaseCommand) -> Result<(), ConsumerError> {
        match cmd.kind {
            BaseCommandKind::Sync => self.handle(&cmd.id).await,
        }
    }
}

#[async_trait]
impl ConsumerHandler<BaseEvent> for Handler {
    async fn handle(&self, event: BaseEvent) -> Result<(), ConsumerError> {
        match event.kind {
            BaseEventKind::Created => self.handle(&event.id).await,
        }
    }
}

// main

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    init_tracing("autoplaylist-base-sync")?;
    let res = run().await;
    if let Err(err) = &res {
        error!("{err}");
    }
    shutdown_tracer_provider();
    res
}

// signal_listener

#[inline]
fn signal_listener(kind: SignalKind) -> Result<Signal, Box<dyn StdError + Send + StdSync>> {
    trace!("creating UNIX signal listener on {kind:?}");
    signal(kind).map_err(|err| Box::new(err) as Box<dyn StdError + Send + StdSync>)
}

// run

#[inline]
async fn run() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    let mut sig_int = signal_listener(SignalKind::interrupt())?;
    let mut sig_term = signal_listener(SignalKind::terminate())?;
    let cfg = Config::from_env().map_err(Box::new)?;
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let db_pool: Arc<Box<dyn DatabasePool>> = Arc::new(Box::new(db_pool));
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let spotify_client = RSpotifyClient::new(cfg.spotify);
    let spotify_client: Arc<Box<dyn SpotifyClient>> = Arc::new(Box::new(spotify_client));
    let (stop_tx, stop_rx) = watch_channel(());
    let spotify_synchronizer = SpotifySynchronizer {
        db_pool: db_pool.clone(),
        spotify_client,
        stop_rx: stop_rx.clone(),
    };
    let spotify_synchronizer: Arc<Box<dyn Synchronizer>> = Arc::new(Box::new(spotify_synchronizer));
    let base_cmd_handler: Box<dyn ConsumerHandler<BaseCommand>> = Box::new(Handler {
        db_pool: db_pool.clone(),
        spotify_synchronizer: spotify_synchronizer.clone(),
    });
    let base_event_handler: Box<dyn ConsumerHandler<BaseEvent>> = Box::new(Handler {
        db_pool,
        spotify_synchronizer,
    });
    let base_cmd_csm = broker
        .start_base_command_consumer(cfg.queues.base_cmd, stop_rx.clone(), base_cmd_handler)
        .await?;
    let base_event_csm = broker
        .start_base_event_consumer(cfg.queues.base_event, stop_rx, base_event_handler)
        .await?;
    info!("synchronizer is started");
    select! {
        _ = sig_int.recv() => send_stop_signal(SignalKind::interrupt(), stop_tx).await,
        _ = sig_term.recv() => send_stop_signal(SignalKind::terminate(), stop_tx).await,
    }
    debug!("waiting for consumers shutdown");
    base_cmd_csm.wait_for_shutdown().await;
    base_event_csm.wait_for_shutdown().await;
    info!("synchronizer stopped");
    Ok(())
}

// send_stop_signal

#[inline]
async fn send_stop_signal(sig_kind: SignalKind, stop_sig_tx: Sender<()>) {
    debug!("{sig_kind:?} received, synchronizer will shutdown");
    trace!("sending stop signal");
    if let Err(err) = stop_sig_tx.send(()) {
        error!("sending stop signal to all consumers failed: {err}");
    }
}

// Mods

mod cfg;
mod sync;
