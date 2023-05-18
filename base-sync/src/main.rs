use std::{error::Error as StdError, result::Result as StdResult};

use autoplaylist_core::{
    broker::{open_channels, Config as BrokerConfig},
    init_tracing,
};
use opentelemetry::global::shutdown_tracer_provider;
use tracing::error;

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
async fn run() -> Result<()> {
    let broker_cfg = BrokerConfig::from_env().map_err(Box::new)?;
    let _channels = open_channels(broker_cfg).await.map_err(Box::new)?;
    Ok(())
}
