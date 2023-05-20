use std::{error::Error as StdError, result::Result as StdResult};

use autoplaylist_core::{
    broker::{
        open_channels, start_base_command_consumer, start_base_event_consumer, BaseEvent,
        ConsumerError, ConsumerSignal,
    },
    db::init as init_database,
    init_tracing,
};
use futures::FutureExt;
use opentelemetry::global::shutdown_tracer_provider;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace};

use self::cfg::Config;

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
async fn handle_base_command(
    _event: BaseEvent,
    mut sig_rcv: Receiver<ConsumerSignal>,
) -> StdResult<(), ConsumerError> {
    loop {
        match sig_rcv.changed().now_or_never() {
            Some(Ok(())) => {
                let sig = *sig_rcv.borrow();
                trace!("base command worker received {sig:?}");
                if let ConsumerSignal::Stop = sig {
                    break;
                }
            }
            Some(Err(err)) => {
                error!("base command worker failed to listen consumer signal: {err}");
            }
            None => (),
        }
    }
    debug!("base command worker stopped");
    Ok(())
}

#[inline]
async fn handle_base_event(
    _event: BaseEvent,
    mut sig_rcv: Receiver<ConsumerSignal>,
) -> StdResult<(), ConsumerError> {
    loop {
        match sig_rcv.changed().now_or_never() {
            Some(Ok(())) => {
                let sig = *sig_rcv.borrow();
                trace!("base event worker received {sig:?}");
                if let ConsumerSignal::Stop = sig {
                    break;
                }
            }
            Some(Err(err)) => {
                error!("base event worker failed to listen consumer signal: {err}");
            }
            None => (),
        }
    }
    debug!("base event worker stopped");
    Ok(())
}

#[inline]
async fn run() -> Result<()> {
    let mut sig_int = create_signal_listener(SignalKind::interrupt())?;
    let mut sig_term = create_signal_listener(SignalKind::terminate())?;
    let cfg = Config::from_env().map_err(Box::new)?;
    let _db_pool = init_database(cfg.db).await.map_err(Box::new)?;
    let channels = open_channels(cfg.broker).await.map_err(Box::new)?;
    let (csm_sig_sdr, csm_sig_rcv) = watch_channel(ConsumerSignal::Start);
    let base_cmd_csm_handle = start_base_command_consumer(
        "base-sync_base-cmd",
        &channels.base_cmd,
        csm_sig_rcv.clone(),
        {
            let csm_sig_rcv = csm_sig_rcv.clone();
            move |event| {
                let csm_sig_rcv = csm_sig_rcv.clone();
                async move { handle_base_command(event, csm_sig_rcv).await }
            }
        },
    )
    .await
    .map_err(Box::new)?;
    let base_event_csm_handle = start_base_event_consumer(
        "base-sync_base-event",
        &channels.base_event,
        csm_sig_rcv.clone(),
        move |event| {
            let csm_sig_rcv = csm_sig_rcv.clone();
            async move { handle_base_event(event, csm_sig_rcv).await }
        },
    )
    .await
    .map_err(Box::new)?;
    info!("synchronizer is started");
    let handles = vec![base_cmd_csm_handle, base_event_csm_handle];
    select! {
        _ = sig_int.recv() => shutdown(SignalKind::interrupt(), csm_sig_sdr, handles).await,
        _ = sig_term.recv() => shutdown(SignalKind::terminate(), csm_sig_sdr, handles).await,
    }
    info!("synchronizer stopped");
    Ok(())
}

#[inline]
async fn shutdown(
    sig_kind: SignalKind,
    csm_sig_sdr: Sender<ConsumerSignal>,
    handles: Vec<JoinHandle<()>>,
) {
    debug!("{sig_kind:?} received, synchronizer will shutdown");
    let csm_sig = ConsumerSignal::Stop;
    trace!("sending {csm_sig:?} to all consumers");
    info!("waiting for consumers stop");
    match csm_sig_sdr.send(csm_sig) {
        Ok(()) => {
            for handle in handles {
                if let Err(err) = handle.await {
                    error!("waiting for consumer stop failed: {err}");
                }
            }
        }
        Err(err) => {
            error!("sending {csm_sig:?} to all consumers failed: {err}");
        }
    }
}

// Mods

mod cfg;
