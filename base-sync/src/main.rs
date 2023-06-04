use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
    sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, BaseCommand, BaseCommandKind, BaseEvent, BaseEventKind, Broker,
        ConsumerError, ConsumerHandler,
    },
    db::{in_transaction, postgres::PostgresPool, Client, InTransactionError, Pool},
    domain::{Base, Platform, User},
    init_tracing,
};
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Sender},
};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use self::cfg::Config;

// Result

type Result<T> = StdResult<T, Box<dyn StdError + Send + Sync>>;

// Error

#[derive(Debug)]
pub enum Error {
    DatabaseClient(Box<dyn StdError + Send + Sync>),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::DatabaseClient(err) => write!(f, "{err}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::DatabaseClient(err) => Some(err.as_ref()),
        }
    }
}

// Handler

struct Handler(Arc<Box<dyn Pool>>);

impl Handler {
    #[inline]
    async fn start_spotify_sync(
        &self,
        base: Base,
        user: User,
        mut client: Box<dyn Client>,
    ) -> StdResult<(), ConsumerError> {
        let repos = client.repositories();
        let user_repo = repos.user();
        let auth = user_repo
            .get_spotify_auth_by_id(&user.id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let _auth = match auth {
            Some(auth) => auth,
            None => {
                warn!("ignoring synchronization of base {} because user {} is not authenticated with Spotify", base.id, user.id);
                return Ok(());
            }
        };
        drop(user_repo);
        drop(repos);
        let res = in_transaction(client.as_mut(), move |_tx| {
            Box::pin(async move { Ok::<(), Error>(()) })
        })
        .await;
        match res {
            Ok(()) => Ok(()),
            Err(err) => match err {
                InTransactionError::Client(err) => Err(ConsumerError::with_requeue(err)),
                InTransactionError::Execution(err) => match err {
                    Error::DatabaseClient(err) => Err(ConsumerError::with_requeue(err)),
                },
            },
        }
    }

    #[inline]
    async fn start_sync(&self, base_id: Uuid) -> StdResult<(), ConsumerError> {
        let client = self.0.client().await.map_err(ConsumerError::with_requeue)?;
        let repos = client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let base = base_repo
            .get_by_id(&base_id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let base = match base {
            Some(base) => base,
            None => {
                warn!("ignoring synchronization of base {base_id} because it doesn't exist");
                return Ok(());
            }
        };
        let user = user_repo
            .get_by_id(&base.user_id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let user = match user {
            Some(user) => user,
            None => {
                warn!(
                    "ignoring synchronization of base {base_id} because user {} doesn't exist",
                    base.user_id
                );
                return Ok(());
            }
        };
        drop(user_repo);
        drop(base_repo);
        drop(repos);
        match base.platform {
            Platform::Spotify => self.start_spotify_sync(base, user, client).await,
        }
    }
}

#[async_trait]
impl ConsumerHandler<BaseCommand> for Handler {
    async fn handle(&self, cmd: BaseCommand) -> StdResult<(), ConsumerError> {
        match cmd.kind {
            BaseCommandKind::Sync => self.start_sync(cmd.id).await,
        }
    }
}

#[async_trait]
impl ConsumerHandler<BaseEvent> for Handler {
    async fn handle(&self, event: BaseEvent) -> StdResult<(), ConsumerError> {
        match event.kind {
            BaseEventKind::Created => self.start_sync(event.id).await,
        }
    }
}

// main

#[tokio::main]
async fn main() -> Result<()> {
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
fn signal_listener(kind: SignalKind) -> Result<Signal> {
    trace!("creating UNIX signal listener on {kind:?}");
    signal(kind).map_err(|err| Box::new(err) as Box<dyn StdError + Send + Sync>)
}

// run

#[inline]
async fn run() -> Result<()> {
    let mut sig_int = signal_listener(SignalKind::interrupt())?;
    let mut sig_term = signal_listener(SignalKind::terminate())?;
    let cfg = Config::from_env().map_err(Box::new)?;
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let db_pool: Arc<Box<dyn Pool>> = Arc::new(Box::new(db_pool));
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let (stop_sig_tx, stop_sig_rx) = watch_channel(());
    let base_cmd_handler: Box<dyn ConsumerHandler<BaseCommand>> =
        Box::new(Handler(db_pool.clone()));
    let base_event_handler: Box<dyn ConsumerHandler<BaseEvent>> = Box::new(Handler(db_pool));
    let base_cmd_csm = broker
        .start_base_command_consumer(cfg.queues.base_cmd, stop_sig_rx.clone(), base_cmd_handler)
        .await?;
    let base_event_csm = broker
        .start_base_event_consumer(cfg.queues.base_event, stop_sig_rx, base_event_handler)
        .await?;
    info!("synchronizer is started");
    select! {
        _ = sig_int.recv() => send_stop_signal(SignalKind::interrupt(), stop_sig_tx).await,
        _ = sig_term.recv() => send_stop_signal(SignalKind::terminate(), stop_sig_tx).await,
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
