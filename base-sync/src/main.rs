use std::{error::Error as StdError, result::Result as StdResult};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, BaseCommand, BaseEvent, Broker, ConsumerError, ConsumerHandler,
    },
    db::postgres::PostgresPool,
    init_tracing,
};
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Sender},
};
use tracing::{debug, error, info, trace};

use self::cfg::Config;

// Types

type Result<T> = StdResult<T, Box<dyn StdError + Send + Sync>>;

// Handler

struct Handler;

#[async_trait]
impl ConsumerHandler<BaseCommand> for Handler {
    async fn handle(&self, _cmd: BaseCommand) -> StdResult<(), ConsumerError> {
        debug!("ok");
        Ok(())
    }
}

#[async_trait]
impl ConsumerHandler<BaseEvent> for Handler {
    async fn handle(&self, _event: BaseEvent) -> StdResult<(), ConsumerError> {
        debug!("ok");
        Ok(())
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
    let _db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let (stop_sig_tx, stop_sig_rx) = watch_channel(());
    let base_cmd_handler: Box<dyn ConsumerHandler<BaseCommand>> = Box::new(Handler);
    let base_event_handler: Box<dyn ConsumerHandler<BaseEvent>> = Box::new(Handler);
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
