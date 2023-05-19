use std::{
    error::Error as StdError,
    result::Result as StdResult,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use autoplaylist_core::{
    broker::{open_channels, start_consumer, BaseEvent, Config as BrokerConfig, ConsumerError},
    init_tracing,
};
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
};
use tracing::{debug, error, info, trace};

// Types

type Result<T> = StdResult<T, Box<dyn StdError>>;

// Functions

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

// Functions - Utils

#[inline]
fn create_signal_listener(kind: SignalKind) -> Result<Signal> {
    trace!("creating UNIX signal listener on {kind:?}");
    signal(kind).map_err(|err| Box::new(err) as Box<dyn StdError>)
}

#[inline]
async fn handle_base_event(_event: BaseEvent) -> StdResult<(), ConsumerError> {
    Ok(())
}

#[inline]
async fn run() -> Result<()> {
    let mut sig_int = create_signal_listener(SignalKind::interrupt())?;
    let mut sig_term = create_signal_listener(SignalKind::terminate())?;
    let broker_cfg = BrokerConfig::from_env().map_err(Box::new)?;
    let channels = open_channels(broker_cfg).await.map_err(Box::new)?;
    let base_event_csm_running = start_consumer("base-sync", &channels, handle_base_event)
        .await
        .map_err(Box::new)?;
    info!("synchronizer is started");
    select! {
        _ = sig_int.recv() => shutdown(SignalKind::interrupt(), base_event_csm_running.clone()),
        _ = sig_term.recv() => shutdown(SignalKind::terminate(), base_event_csm_running),
    }
    info!("synchronizer stopped");
    Ok(())
}

#[inline]
fn shutdown(sig_kind: SignalKind, running: Arc<AtomicBool>) {
    debug!("{sig_kind:?} received, synchronizer will shutdown");
    running.store(false, Ordering::Relaxed)
}
