use std::{error::Error as StdError, ops::DerefMut, result::Result as StdResult};

use deadpool_postgres::{
    tokio_postgres::{Client, Error as TokioPostgresError},
    Object, Pool, PoolError,
};
use refinery::embed_migrations;
use tokio_postgres::Row;
use tracing::{debug, info, trace};

use crate::domain::{SpotifyAuth, User};

// Types

pub type Result<T> = StdResult<T, TokioPostgresError>;

// Impl - User

impl From<Row> for User {
    fn from(row: Row) -> Self {
        Self {
            creation_date: row.get("creation_date"),
            id: row.get("id"),
            role: row.get("role"),
        }
    }
}

// Functions - Queries

pub async fn insert_user(user: &User, client: &Client) -> Result<()> {
    debug!("inserting {user:?} into database");
    client
        .execute(
            include_str!("../db/queries/insert-user.sql"),
            &[&user.id, &user.creation_date, &user.role],
        )
        .await?;
    Ok(())
}

pub async fn upsert_spotify_auth(auth: &SpotifyAuth, client: &Client) -> Result<()> {
    debug!("upserting {auth:?} into database");
    client
        .execute(
            include_str!("../db/queries/upsert-spotify-auth.sql"),
            &[
                &auth.user_id,
                &auth.email,
                &auth.access_token,
                &auth.refresh_token,
            ],
        )
        .await?;
    Ok(())
}

pub async fn user_by_spotify_email(email: &str, client: &Client) -> Result<Option<User>> {
    debug!("fetching user by Spotify email `{email}` from database");
    client
        .query_opt(
            include_str!("../db/queries/user-by-spotify-email.sql"),
            &[&email],
        )
        .await
        .map(|row| row.map(User::from))
}

// Functions - Utils

#[inline]
pub async fn client_from_pool(pool: &Pool) -> StdResult<Object, PoolError> {
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
