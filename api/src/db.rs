use std::{error::Error as StdError, ops::DerefMut, result::Result as StdResult};

use deadpool_postgres::{
    tokio_postgres::{Client, Error as TokioPostgresError},
    Pool,
};
use postgres_types::{FromSql, ToSql};
use refinery::embed_migrations;
use tokio_postgres::Row;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::domain::{Base, BaseKind, Grouping, Platform, Query, SpotifyAuth, User};

// Types

pub type Result<T> = StdResult<T, TokioPostgresError>;

// Enums

#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "base_kind")]
enum BaseKindSql {
    #[postgres(name = "likes")]
    Likes,
    #[postgres(name = "playlist")]
    Playlist,
}

// Impl - Base

impl TryFrom<Row> for Base {
    type Error = TokioPostgresError;

    fn try_from(row: Row) -> StdResult<Self, Self::Error> {
        Ok(Self {
            creation_date: row.try_get("creation_date")?,
            id: row.try_get("id")?,
            kind: match row.try_get("kind")? {
                BaseKindSql::Likes => BaseKind::Likes,
                BaseKindSql::Playlist => BaseKind::Playlist(row.try_get("platform_id")?),
            },
            platform: row.try_get("platform")?,
            user_id: row.try_get("user_id")?,
        })
    }
}

// Impl - Query

impl TryFrom<Row> for Query {
    type Error = TokioPostgresError;

    fn try_from(row: Row) -> StdResult<Self, Self::Error> {
        Ok(Self {
            base_id: row.try_get("base_id")?,
            creation_date: row.try_get("creation_date")?,
            grouping: row.try_get("grouping")?,
            id: row.try_get("id")?,
            name_prefix: row.try_get("name_prefix")?,
        })
    }
}

// Impl - User

impl TryFrom<Row> for User {
    type Error = TokioPostgresError;

    fn try_from(row: Row) -> StdResult<Self, Self::Error> {
        Ok(Self {
            creation_date: row.try_get("creation_date")?,
            id: row.try_get("id")?,
            role: row.try_get("role")?,
        })
    }
}

// Functions - Queries

pub async fn base(
    user_id: &Uuid,
    kind: &BaseKind,
    platform: &Platform,
    client: &Client,
) -> Result<Option<Base>> {
    debug!("fetching base with {kind:?} owned by user {user_id} on {platform}");
    let (kind, platform_id) = kind_and_platform_id(kind);
    let res = client
        .query_opt(
            include_str!("../db/queries/base.sql"),
            &[user_id, platform, &kind, &platform_id],
        )
        .await;
    convert_opt_result(res)
}

pub async fn insert_base(base: &Base, client: &Client) -> Result<()> {
    debug!("inserting {base:?} into database");
    let (kind, platform_id) = kind_and_platform_id(&base.kind);
    client
        .execute(
            include_str!("../db/queries/insert-base.sql"),
            &[
                &base.id,
                &base.creation_date,
                &base.user_id,
                &base.platform,
                &kind,
                &platform_id,
            ],
        )
        .await?;
    Ok(())
}

pub async fn insert_query(query: &Query, client: &Client) -> Result<()> {
    debug!("inserting {query:?} into database");
    client
        .execute(
            include_str!("../db/queries/insert-query.sql"),
            &[
                &query.id,
                &query.creation_date,
                &query.base_id,
                &query.name_prefix,
                &query.grouping,
            ],
        )
        .await?;
    Ok(())
}

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

pub async fn query(
    base_id: &Uuid,
    name_prefix: Option<&String>,
    grouping: Option<&Grouping>,
    client: &Client,
) -> Result<Option<Query>> {
    debug!("fetching query on base {base_id} with {name_prefix:?} {grouping:?}");
    let res = client
        .query_opt(
            include_str!("../db/queries/query.sql"),
            &[base_id, &name_prefix, &grouping],
        )
        .await;
    convert_opt_result(res)
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

pub async fn user_by_id(id: &Uuid, client: &Client) -> Result<Option<User>> {
    debug!("fetching user with ID {id}");
    let res = client
        .query_opt(include_str!("../db/queries/user-by-id.sql"), &[id])
        .await;
    convert_opt_result(res)
}

pub async fn user_by_spotify_email(email: &str, client: &Client) -> Result<Option<User>> {
    debug!("fetching user with Spotify email `{email}` from database");
    let res = client
        .query_opt(
            include_str!("../db/queries/user-by-spotify-email.sql"),
            &[&email],
        )
        .await;
    convert_opt_result(res)
}

// Functions - Utils

#[inline]
fn convert_opt_result<T: TryFrom<Row, Error = TokioPostgresError>>(
    res: Result<Option<Row>>,
) -> Result<Option<T>> {
    match res {
        Ok(Some(row)) => row.try_into().map(Some),
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}

#[inline]
fn kind_and_platform_id(kind: &BaseKind) -> (BaseKindSql, Option<&String>) {
    match kind {
        BaseKind::Likes => (BaseKindSql::Likes, None),
        BaseKind::Playlist(platform_id) => (BaseKindSql::Playlist, Some(platform_id)),
    }
}

#[inline]
pub async fn run_migrations(db_pool: &Pool) -> StdResult<(), Box<dyn StdError>> {
    trace!("getting database client from pool");
    let mut db_client = db_pool.get().await.map_err(Box::new)?;
    info!("running database migrations");
    migrations::runner()
        .run_async(db_client.deref_mut().deref_mut())
        .await
        .map_err(Box::new)?;
    Ok(())
}

// Mods

embed_migrations!("db/migrations");
