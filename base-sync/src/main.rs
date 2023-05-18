use std::{error::Error as StdError, result::Result as StdResult};

use autoplaylist_core::init_tracing;
use opentelemetry::global::shutdown_tracer_provider;

// Types

type Result<T> = StdResult<T, Box<dyn StdError>>;

// Functions

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("autoplaylist-base-sync")?;
    shutdown_tracer_provider();
    Ok(())
}
