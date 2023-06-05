use std::{
    error::Error as StdError, marker::Sync as StdSync, result::Result as StdResult, sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, BaseCommand, BaseCommandKind, BaseEvent, BaseEventKind, Broker,
        ConsumerError, ConsumerHandler,
    },
    db::{postgres::PostgresPool, Client as DatabaseClient, Pool as DatabasePool},
    domain::{Base, BaseKind, Page, Platform, SpotifyToken, SpotifyTrack, Sync, SyncState, User},
    init_tracing,
    spotify::{rspotify::RSpotifyClient, Client as SpotifyClient},
};
use chrono::Utc;
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Receiver, Sender},
};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use self::cfg::Config;

// Consts

const PAGE_LIMIT: u32 = 50;

// Result

type Result<T> = StdResult<T, Box<dyn StdError + Send + StdSync>>;

// Handler

struct Handler {
    db_pool: Arc<Box<dyn DatabasePool>>,
    spotify_client: Arc<Box<dyn SpotifyClient>>,
    stop_rx: Receiver<()>,
}

impl Handler {
    #[inline]
    async fn fail_sync(
        base_id: &Uuid,
        err: &ConsumerError,
        sync: &mut Sync,
        db_client: &dyn DatabaseClient,
    ) -> StdResult<(), ConsumerError> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        sync.state = SyncState::Failed;
        sync.last_err_msg = Some(err.to_string());
        base_repo
            .update_sync(base_id, sync)
            .await
            .map_err(ConsumerError::with_requeue)?;
        error!("sync of base {base_id} failed: {err}");
        Ok(())
    }

    #[inline]
    async fn fetch_page(
        &self,
        base_kind: &BaseKind,
        offset: u32,
        token: &SpotifyToken,
    ) -> StdResult<Page<SpotifyTrack>, ConsumerError> {
        match base_kind {
            BaseKind::Likes => self
                .spotify_client
                .user_liked_tacks(PAGE_LIMIT, offset, token)
                .await
                .map_err(ConsumerError::with_requeue),
            BaseKind::Playlist(id) => self
                .spotify_client
                .playlist_tacks(id, PAGE_LIMIT, offset, token)
                .await
                .map_err(ConsumerError::with_requeue),
        }
    }

    #[inline]
    async fn handle_page(
        base_id: &Uuid,
        page: Page<SpotifyTrack>,
        sync: &mut Sync,
        db_client: &dyn DatabaseClient,
    ) -> StdResult<bool, ConsumerError> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        sync.last_err_msg = None;
        sync.last_total = page.total;
        for _ in page.items {
            sync.last_offset += 1;
        }
        let is_over = if page.is_last {
            sync.state = SyncState::Succeeded;
            sync.last_success_date = Some(Utc::now());
            sync.last_offset = 0;
            true
        } else {
            false
        };
        base_repo
            .update_sync(base_id, sync)
            .await
            .map_err(ConsumerError::with_requeue)?;
        Ok(is_over)
    }

    #[inline]
    async fn start_spotify_sync(
        &self,
        base: Base,
        user: User,
        db_client: Box<dyn DatabaseClient>,
    ) -> StdResult<(), ConsumerError> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let auth = user_repo
            .get_spotify_auth_by_id(&user.id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let auth = match auth {
            Some(auth) => auth,
            None => {
                warn!(
                    "ignoring sync of base {} because user {} is not authenticated with Spotify",
                    base.id, user.id
                );
                return Ok(());
            }
        };
        let sync = base_repo
            .lock_sync(&base.id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let mut sync = match sync {
            Some(sync) => sync,
            None => {
                info!(
                    "ignoring sync of base {} because it's already running",
                    base.id
                );
                return Ok(());
            }
        };
        let mut stop_rx = self.stop_rx.clone();
        info!("sync of base {} started", base.id);
        loop {
            select! {
                page = self.fetch_page(&base.kind, sync.last_offset, &auth.token) => {
                    match page {
                        Ok(page) => {
                            let is_over = Self::handle_page(
                                &base.id,
                                page,
                                &mut sync,
                                db_client.as_ref()
                            ).await;
                            match is_over {
                                Ok(true) => break,
                                Err(err) => {
                                    Self::fail_sync(
                                        &base.id,
                                        &err,
                                        &mut sync,
                                        db_client.as_ref()
                                    ).await?;
                                    break;
                                }
                                _ => (),
                            }
                        }
                        Err(err) => {
                            Self::fail_sync(&base.id, &err, &mut sync, db_client.as_ref()).await?;
                            break;
                        }
                    }
                }
                _ = stop_rx.changed() => {
                    debug!("stop signal received");
                    break;
                },
            }
        }
        Ok(())
    }

    #[inline]
    async fn start_sync(&self, base_id: Uuid) -> StdResult<(), ConsumerError> {
        let db_client = self
            .db_pool
            .client()
            .await
            .map_err(ConsumerError::with_requeue)?;
        let repos = db_client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let base = base_repo
            .get_by_id(&base_id)
            .await
            .map_err(ConsumerError::with_requeue)?;
        let base = match base {
            Some(base) => base,
            None => {
                warn!("ignoring sync of base {base_id} because it doesn't exist");
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
                    "ignoring sync of base {base_id} because user {} doesn't exist",
                    base.user_id
                );
                return Ok(());
            }
        };
        drop(user_repo);
        drop(base_repo);
        drop(repos);
        match base.platform {
            Platform::Spotify => self.start_spotify_sync(base, user, db_client).await,
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
    signal(kind).map_err(|err| Box::new(err) as Box<dyn StdError + Send + StdSync>)
}

// run

#[inline]
async fn run() -> Result<()> {
    let mut sig_int = signal_listener(SignalKind::interrupt())?;
    let mut sig_term = signal_listener(SignalKind::terminate())?;
    let cfg = Config::from_env().map_err(Box::new)?;
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let db_pool: Arc<Box<dyn DatabasePool>> = Arc::new(Box::new(db_pool));
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let spotify_client = RSpotifyClient::new(cfg.spotify);
    let spotify_client: Arc<Box<dyn SpotifyClient>> = Arc::new(Box::new(spotify_client));
    let (stop_tx, stop_rx) = watch_channel(());
    let base_cmd_handler: Box<dyn ConsumerHandler<BaseCommand>> = Box::new(Handler {
        db_pool: db_pool.clone(),
        stop_rx: stop_rx.clone(),
        spotify_client: spotify_client.clone(),
    });
    let base_event_handler: Box<dyn ConsumerHandler<BaseEvent>> = Box::new(Handler {
        db_pool: db_pool.clone(),
        stop_rx: stop_rx.clone(),
        spotify_client,
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
