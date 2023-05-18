use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use autoplaylist_core::{
    broker::{create_base_event_consumer, open_channels, Config as BrokerConfig},
    init_tracing,
};
use futures::{FutureExt, StreamExt};
use lapin::options::{BasicAckOptions, BasicNackOptions};
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    spawn,
};
use tracing::{debug, error, info, trace};

// Types

type Result<T> = StdResult<T, Box<dyn StdError>>;

// Enums

#[derive(Debug)]
pub enum ErrorKind {}

// Struct

#[derive(Debug)]
pub struct Error {
    _kind: ErrorKind,
    should_requeue: bool,
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, _f: &mut Formatter) -> FmtResult {
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

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
async fn handle_base_event(_payload: &[u8]) -> StdResult<(), Error> {
    Ok(())
}

#[inline]
async fn run() -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let mut sig_int = create_signal_listener(SignalKind::interrupt())?;
    let mut sig_term = create_signal_listener(SignalKind::terminate())?;
    let broker_cfg = BrokerConfig::from_env().map_err(Box::new)?;
    let channels = open_channels(broker_cfg).await.map_err(Box::new)?;
    let mut base_event_csm = create_base_event_consumer("base-sync", &channels)
        .await
        .map_err(Box::new)?;
    spawn({
        let running = running.clone();
        async move {
            debug!("base event consumer started");
            while running.load(Ordering::Relaxed) {
                if let Some(Some(delivery)) = base_event_csm.next().now_or_never() {
                    match delivery {
                        Ok(delivery) => {
                            trace!("starting worker to handle {delivery:?}");
                            spawn(async move {
                                match handle_base_event(&delivery.data).await {
                                    Ok(()) => {
                                        debug!("sending acknowledgement to broker");
                                        if let Err(err) =
                                            delivery.ack(BasicAckOptions::default()).await
                                        {
                                            error!(
                                                "unable to send acknowledgement to borker: {err}"
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        error!("{err}");
                                        let opts = BasicNackOptions {
                                            requeue: err.should_requeue,
                                            ..Default::default()
                                        };
                                        if err.should_requeue {
                                            debug!("sending non-acknowledgement to broker with requeue option");
                                        } else {
                                            debug!("sending non-acknowledgement to broker");
                                        }
                                        if let Err(err) = delivery.nack(opts).await {
                                            error!("unable to send non-acknowledgement to broker: {err}");
                                        }
                                    }
                                }
                            });
                        }
                        Err(err) => error!("base event consumer failed: {err}"),
                    }
                }
            }
            debug!("base event consumer stopped");
        }
    });
    info!("synchronizer is started");
    select! {
        _ = sig_int.recv() => shutdown(SignalKind::interrupt(), running.clone()),
        _ = sig_term.recv() => shutdown(SignalKind::terminate(), running),
    }
    info!("synchronizer stopped");
    Ok(())
}

#[inline]
fn shutdown(sig_kind: SignalKind, running: Arc<AtomicBool>) {
    debug!("{sig_kind:?} received, synchronizer will shutdown");
    running.store(false, Ordering::Relaxed)
}
