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

// Traits

pub trait TryFromRow {
    fn try_from_row(row: &Row) -> Result<Self>
    where
        Self: Sized;
}

// Enums

#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "base_kind")]
enum BaseKindSql {
    #[postgres(name = "likes")]
    Likes,
    #[postgres(name = "playlist")]
    Playlist,
}

// Structs

#[derive(Debug)]
pub struct Page<T> {
    pub content: Vec<T>,
    pub total: i64,
}

// Impl - Base

impl TryFromRow for Base {
    fn try_from_row(row: &Row) -> Result<Self> {
        Ok(Self {
            creation_date: row.try_get("base_creation_date")?,
            id: row.try_get("base_id")?,
            kind: match row.try_get("base_kind")? {
                BaseKindSql::Likes => BaseKind::Likes,
                BaseKindSql::Playlist => BaseKind::Playlist(row.try_get("base_platform_id")?),
            },
            platform: row.try_get("base_platform")?,
            user_id: row.try_get("base_user_id")?,
        })
    }
}

// Impl - Page

impl<T: TryFromRow> Page<T> {
    fn try_from_rows(rows: Vec<Row>, total: i64) -> Result<Self> {
        Ok(Self {
            content: rows
                .iter()
                .map(T::try_from_row)
                .collect::<Result<Vec<T>>>()?,
            total,
        })
    }
}

// Impl - Query

impl TryFromRow for Query {
    fn try_from_row(row: &Row) -> Result<Self> {
        Ok(Self {
            base: Base::try_from_row(row)?,
            creation_date: row.try_get("query_creation_date")?,
            grouping: row.try_get("query_grouping")?,
            id: row.try_get("query_id")?,
            name_prefix: row.try_get("query_name_prefix")?,
            user_id: row.try_get("query_user_id")?,
        })
    }
}

// Impl - User

impl TryFromRow for User {
    fn try_from_row(row: &Row) -> Result<Self> {
        Ok(Self {
            creation_date: row.try_get("user_creation_date")?,
            id: row.try_get("user_id")?,
            role: row.try_get("user_role")?,
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
                &query.user_id,
                &query.base.id,
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

pub async fn list_queries(
    user_id: &Uuid,
    limit: i64,
    offset: i64,
    client: &Client,
) -> Result<Page<Query>> {
    debug!("listing queries of user {user_id} from offset {offset} limiting to {limit} entries");
    let total: i64 = client
        .query_one(
            include_str!("../db/queries/list-queries-total.sql"),
            &[user_id],
        )
        .await?
        .get(0);
    let rows = client
        .query(
            include_str!("../db/queries/list-queries-content.sql"),
            &[user_id, &limit, &offset],
        )
        .await?;
    Page::try_from_rows(rows, total)
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
fn convert_opt_result<T: TryFromRow>(res: Result<Option<Row>>) -> Result<Option<T>> {
    match res {
        Ok(Some(row)) => T::try_from_row(&row).map(Some),
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
