use std::{error::Error as StdError, ops::DerefMut, result::Result as StdResult};

use deadpool_postgres::{Client, Pool, PoolError};
use refinery::embed_migrations;
use tracing::{info, trace};

// Functions - Utils

#[inline]
pub async fn client_from_pool(pool: &Pool) -> StdResult<Client, PoolError> {
    trace!("getting database client from pool");
    pool.get().await
}

#[inline]
pub async fn run_migrations(pool: &Pool) -> StdResult<(), Box<dyn StdError>> {
    let mut client = client_from_pool(pool).await.map_err(Box::new)?;
    info!("running database migrations");
    migrations::runner()
        .run_async(client.deref_mut().deref_mut())
        .await
        .map_err(Box::new)?;
    Ok(())
}

// Mods

embed_migrations!("db/migrations");
