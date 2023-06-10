use std::{error::Error as StdError, marker::Sync as StdSync, sync::Arc};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, Broker, ConsumerError, ConsumerHandler, PlaylistCommand,
        TrackEvent,
    },
    db::{postgres::PostgresPool, Pool as DatabasePool},
    init_tracing, shutdown_signal,
};
use opentelemetry::global::shutdown_tracer_provider;
use tokio::sync::watch::channel as watch_channel;
use tracing::{debug, error, info, trace};

use self::{
    cfg::Config,
    sync::{DefaultSynchronizer, Synchronizer},
};

// Handler

struct Handler {
    _db_pool: Arc<Box<dyn DatabasePool>>,
    _synchronizer: Arc<Box<dyn Synchronizer>>,
}

#[async_trait]
impl ConsumerHandler<PlaylistCommand> for Handler {
    async fn handle(&self, _cmd: PlaylistCommand) -> Result<(), ConsumerError> {
        todo!()
    }
}

#[async_trait]
impl ConsumerHandler<TrackEvent> for Handler {
    async fn handle(&self, _event: TrackEvent) -> Result<(), ConsumerError> {
        todo!()
    }
}

// main

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    init_tracing("autoplaylist-playlist-sync")?;
    let res = run().await;
    if let Err(err) = &res {
        error!("{err}");
    }
    shutdown_tracer_provider();
    res
}

// run

#[inline]
async fn run() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    let cfg = Config::from_env().map_err(Box::new)?;
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let db_pool: Arc<Box<dyn DatabasePool>> = Arc::new(Box::new(db_pool));
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let (stop_tx, stop_rx) = watch_channel(());
    let synchronizer = DefaultSynchronizer {
        db_pool: db_pool.clone(),
        stop_rx: stop_rx.clone(),
    };
    let synchronizer: Arc<Box<dyn Synchronizer>> = Arc::new(Box::new(synchronizer));
    let playlist_cmd_handler: Box<dyn ConsumerHandler<PlaylistCommand>> = Box::new(Handler {
        _db_pool: db_pool.clone(),
        _synchronizer: synchronizer.clone(),
    });
    let track_event_handler: Box<dyn ConsumerHandler<TrackEvent>> = Box::new(Handler {
        _db_pool: db_pool,
        _synchronizer: synchronizer,
    });
    let playlist_cmd_csm = broker
        .start_playlist_command_consumer(
            cfg.queues.track_cmd,
            stop_rx.clone(),
            playlist_cmd_handler,
        )
        .await?;
    let base_event_csm = broker
        .start_track_event_consumer(cfg.queues.track_event, stop_rx, track_event_handler)
        .await?;
    info!("synchronizer is started");
    shutdown_signal().await.map_err(Box::new)?;
    debug!("waiting for consumers shutdown");
    trace!("sending stop signal");
    if let Err(err) = stop_tx.send(()) {
        error!("sending stop signal to all consumers failed: {err}");
    }
    playlist_cmd_csm.wait_for_shutdown().await;
    base_event_csm.wait_for_shutdown().await;
    info!("synchronizer stopped");
    Ok(())
}

// Mods

mod cfg;
mod sync;
