use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    ops::DerefMut,
    pin::Pin,
    result::Result as StdResult,
};

use deadpool_postgres::{
    tokio_postgres::{Client, Error as TokioPostgresError, NoTls, Row, Transaction},
    Config as DeadpoolPostgresConfig, CreatePoolError, Object, Pool, PoolError,
};
use postgres_types::{FromSql, ToSql};
use refinery::{embed_migrations, Error as RefineryError};
use securefmt::Debug as SecureDebug;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    domain::{Base, BaseKind, Platform, Playlist, SpotifyAuth, Sync, User},
    env_var, env_var_opt, env_var_or_default, ConfigError,
};

// Macros

macro_rules! sql {
    ($name:literal) => {
        include_str!(concat!("../db/queries/", $name, ".sql"))
    };
}

// Types

pub type Result<T> = StdResult<T, TokioPostgresError>;

// Traits

pub trait TryFromRow {
    fn try_from_row(row: &Row) -> Result<Self>
    where
        Self: Sized;
}

// Enums - Errors

#[derive(Debug)]
pub enum InTransactionError<E: StdError + 'static> {
    Client(TokioPostgresError),
    Execution(E),
}

#[derive(Debug)]
pub enum InitializationError {
    Migrations(Box<RefineryError>),
    PoolCreation(CreatePoolError),
    Pool(PoolError),
}

// Enums - SQL helpers

#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "base_kind")]
enum BaseKindSql {
    #[postgres(name = "likes")]
    Likes,
    #[postgres(name = "playlist")]
    Playlist,
}

// Structs

#[derive(Clone, SecureDebug)]
pub struct Config {
    pub host: String,
    pub name: String,
    pub port: Option<u16>,
    #[sensitive]
    pub pwd: String,
    pub user: String,
}

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
            sync: Sync {
                last_err_msg: row.try_get("base_last_sync_err_msg")?,
                last_start_date: row.try_get("base_last_sync_start_date")?,
                last_success_date: row.try_get("base_last_sync_success_date")?,
                state: row.try_get("base_sync_state")?,
            },
            user_id: row.try_get("base_user_id")?,
        })
    }
}

// Impl - Config

impl Config {
    pub fn from_env() -> StdResult<Self, ConfigError> {
        trace!("loading database configuration");
        let cfg = Self {
            host: env_var("DB_HOST")?,
            name: env_var_or_default("DB_NAME", || "autoplaylist".into())?,
            port: env_var_opt("DB_PORT")?,
            pwd: env_var("DB_PASSWORD")?,
            user: env_var_or_default("DB_USER", || "autoplaylist".into())?,
        };
        trace!("database configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// Impl - DeadpoolPostgresConfig

impl From<Config> for DeadpoolPostgresConfig {
    fn from(cfg: Config) -> Self {
        Self {
            dbname: Some(cfg.name),
            host: Some(cfg.host),
            password: Some(cfg.pwd),
            port: cfg.port,
            user: Some(cfg.user),
            ..Default::default()
        }
    }
}

// Impl - InTransactionError

impl<E: StdError> Display for InTransactionError<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Client(err) => write!(f, "{err}"),
            Self::Execution(err) => write!(f, "{err}"),
        }
    }
}

impl<E: StdError> StdError for InTransactionError<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Client(err) => Some(err),
            Self::Execution(err) => Some(err),
        }
    }
}

// Impl - InitializationError

impl Display for InitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Migrations(err) => write!(f, "database migrations failed: {err}"),
            Self::PoolCreation(err) => {
                write!(f, "database connection pool creation failed: {err}")
            }
            Self::Pool(err) => write!(f, "database connection pool error: {err}"),
        }
    }
}

impl StdError for InitializationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Migrations(err) => Some(err.as_ref()),
            Self::PoolCreation(err) => Some(err),
            Self::Pool(err) => Some(err),
        }
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

// Impl - Playlist

impl TryFromRow for Playlist {
    fn try_from_row(row: &Row) -> Result<Self> {
        Ok(Self {
            base: Base::try_from_row(row)?,
            creation_date: row.try_get("playlist_creation_date")?,
            id: row.try_get("playlist_id")?,
            name: row.try_get("playlist_name")?,
            user_id: row.try_get("playlist_user_id")?,
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

// Functions - Initializers

pub async fn init(cfg: Config) -> StdResult<Pool, InitializationError> {
    let cfg: DeadpoolPostgresConfig = cfg.into();
    trace!("creating database connection pool");
    let pool = cfg
        .create_pool(None, NoTls)
        .map_err(InitializationError::PoolCreation)?;
    let mut db_client = client_from_pool(&pool)
        .await
        .map_err(InitializationError::Pool)?;
    info!("running database migrations");
    migrations::runner()
        .run_async(db_client.deref_mut().deref_mut())
        .await
        .map_err(|err| InitializationError::Migrations(Box::new(err)))?;
    Ok(pool)
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
        .query_opt(sql!("base"), &[user_id, platform, &kind, &platform_id])
        .await;
    let res = convert_opt_result(res);
    if let Ok(base) = &res {
        debug!("base fetched: {base:?}");
    }
    res
}

pub async fn delete_playlist(id: &Uuid, client: &Client) -> Result<()> {
    debug!("deleting playlist {id}");
    client.execute(sql!("delete-playlist"), &[id]).await?;
    Ok(())
}

pub async fn insert_base(base: &Base, client: &Client) -> Result<()> {
    debug!("inserting {base:?} into database");
    let (kind, platform_id) = kind_and_platform_id(&base.kind);
    client
        .execute(
            sql!("insert-base"),
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

pub async fn insert_playlist(playlist: &Playlist, client: &Client) -> Result<()> {
    debug!("inserting {playlist:?} into database");
    client
        .execute(
            sql!("insert-playlist"),
            &[
                &playlist.id,
                &playlist.creation_date,
                &playlist.user_id,
                &playlist.base.id,
                &playlist.name,
            ],
        )
        .await?;
    Ok(())
}

pub async fn insert_user(user: &User, client: &Client) -> Result<()> {
    debug!("inserting {user:?} into database");
    client
        .execute(
            sql!("insert-user"),
            &[&user.id, &user.creation_date, &user.role],
        )
        .await?;
    Ok(())
}

pub async fn list_bases(
    user_id: &Uuid,
    limit: i64,
    offset: i64,
    client: &Client,
) -> Result<Page<Base>> {
    debug!("listing bases of user {user_id} from offset {offset} limiting to {limit} entries");
    let total: i64 = client
        .query_one(sql!("list-bases-total"), &[user_id])
        .await?
        .get(0);
    let rows = client
        .query(sql!("list-bases-content"), &[user_id, &limit, &offset])
        .await?;
    let res = Page::try_from_rows(rows, total);
    if let Ok(page) = &res {
        debug!("page fetched: {page:?}");
    }
    res
}

pub async fn list_playlists(
    user_id: &Uuid,
    limit: i64,
    offset: i64,
    client: &Client,
) -> Result<Page<Playlist>> {
    debug!("listing playlists of user {user_id} from offset {offset} limiting to {limit} entries");
    let total: i64 = client
        .query_one(sql!("list-playlists-total"), &[user_id])
        .await?
        .get(0);
    let rows = client
        .query(sql!("list-playlists-content"), &[user_id, &limit, &offset])
        .await?;
    let res = Page::try_from_rows(rows, total);
    if let Ok(page) = &res {
        debug!("page fetched: {page:?}");
    }
    res
}

pub async fn playlist_by_id(id: &Uuid, client: &Client) -> Result<Option<Playlist>> {
    debug!("fetching playlist with ID {id}");
    let res = client.query_opt(sql!("playlist-by-id"), &[id]).await;
    let res = convert_opt_result(res);
    if let Ok(playlist) = &res {
        debug!("playlist fetched: {playlist:?}");
    }
    res
}

pub async fn playlist_by_name(name: &str, client: &Client) -> Result<Option<Playlist>> {
    debug!("fetching playlist with name `{name}`");
    let res = client.query_opt(sql!("playlist-by-name"), &[&name]).await;
    let res = convert_opt_result(res);
    if let Ok(playlist) = &res {
        debug!("playlist fetched: {playlist:?}");
    }
    res
}

pub async fn upsert_spotify_auth(auth: &SpotifyAuth, client: &Client) -> Result<()> {
    debug!("upserting {auth:?} into database");
    client
        .execute(
            sql!("upsert-spotify-auth"),
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
    let res = client.query_opt(sql!("user-by-id"), &[id]).await;
    let res = convert_opt_result(res);
    if let Ok(user) = &res {
        debug!("user fetched: {user:?}");
    }
    res
}

pub async fn user_by_spotify_email(email: &str, client: &Client) -> Result<Option<User>> {
    debug!("fetching user with Spotify email `{email}` from database");
    let res = client
        .query_opt(sql!("user-by-spotify-email"), &[&email])
        .await;
    let res = convert_opt_result(res);
    if let Ok(user) = &res {
        debug!("user fetched: {user:?}");
    }
    res
}

// Functions - Utils

pub async fn client_from_pool(pool: &Pool) -> StdResult<Object, PoolError> {
    trace!("getting database connection from pool");
    pool.get().await
}

pub async fn in_transaction<
    'a,
    E: StdError + 'static,
    F: for<'b> FnOnce(&'b Transaction<'a>) -> Pin<Box<dyn Future<Output = StdResult<T, E>> + 'b>>,
    T,
>(
    client: &'a mut Client,
    f: F,
) -> StdResult<T, InTransactionError<E>> {
    trace!("opening database transaction");
    let tx = client
        .transaction()
        .await
        .map_err(InTransactionError::Client)?;
    match f(&tx).await {
        Ok(val) => {
            debug!("committing database transaction");
            tx.commit().await.map_err(InTransactionError::Client)?;
            Ok(val)
        }
        Err(err) => {
            debug!("rollbacking database transaction");
            if let Err(err) = tx.rollback().await {
                error!("database transaction rollback failed: {err}");
            }
            Err(InTransactionError::Execution(err))
        }
    }
}

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

// Mods

embed_migrations!("db/migrations");
