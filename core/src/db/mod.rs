use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    pin::Pin,
    result::Result as StdResult,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::Future;
use securefmt::Debug as SecureDebug;
use tracing::{error, trace};
use uuid::Uuid;

use crate::{
    domain::{
        Artist, Base, BaseKind, Page, Platform, Playlist, PlaylistFilter, SpotifyAuth, Sync, Track,
        User,
    },
    env_var, env_var_opt, env_var_or_default, ConfigError,
};

// Result

pub type Result<T> = StdResult<T, Box<dyn StdError + Send + StdSync>>;

// Client

#[async_trait]
pub trait Client: Send + StdSync {
    fn repositories(&self) -> Box<dyn Repositories + '_>;

    async fn transaction(&mut self) -> Result<Box<dyn Transaction + '_>>;
}

// Transaction

#[async_trait]
pub trait Transaction: Send + StdSync {
    async fn commit(self: Box<Self>) -> Result<()>;

    fn repositories(&self) -> Box<dyn Repositories + '_>;

    async fn rollback(self: Box<Self>) -> Result<()>;
}

// Repositories

pub trait Repositories: Send + StdSync {
    fn artist(&self) -> Box<dyn ArtistRepository + '_>;

    fn base(&self) -> Box<dyn BaseRepository + '_>;

    fn playlist(&self) -> Box<dyn PlaylistRepository + '_>;

    fn track(&self) -> Box<dyn TrackRepository + '_>;

    fn user(&self) -> Box<dyn UserRepository + '_>;
}

// BaseRepository

#[async_trait]
pub trait BaseRepository: Send + StdSync {
    async fn delete_track_by_id_sync_not(&self, id: &Uuid, sync_id: &Uuid) -> Result<()>;

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Base>>;

    async fn get_by_user_kind_platform(
        &self,
        user_id: &Uuid,
        kind: &BaseKind,
        platform: Platform,
    ) -> Result<Option<Base>>;

    async fn insert(&self, base: &Base) -> Result<()>;

    async fn list(&self, limit: u32, offset: u32) -> Result<Page<Base>>;

    async fn lock_sync(&self, id: &Uuid, sync_id: Uuid, now: DateTime<Utc>)
        -> Result<Option<Sync>>;

    async fn update_sync(&self, id: &Uuid, sync: &Sync) -> Result<()>;

    async fn upsert_track(&self, id: &Uuid, track_id: &Uuid, sync_id: &Uuid) -> Result<()>;
}

// PlaylistRepository

#[async_trait]
pub trait PlaylistRepository: Send + StdSync {
    async fn delete(&self, id: &Uuid) -> Result<()>;

    async fn delete_track_by_id_sync_not(&self, id: &Uuid, sync_id: &Uuid) -> Result<()>;

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Playlist>>;

    async fn get_by_user_name(&self, user_id: &Uuid, name: &str) -> Result<Option<Playlist>>;

    async fn insert(&self, playlist: &Playlist, filters: &[PlaylistFilter]) -> Result<()>;

    async fn list_by_user(&self, user_id: &Uuid, limit: u32, offset: u32)
        -> Result<Page<Playlist>>;

    async fn lock_sync(&self, id: &Uuid, sync_id: Uuid, now: DateTime<Utc>)
        -> Result<Option<Sync>>;

    async fn update_sync(&self, id: &Uuid, sync: &Sync) -> Result<()>;

    async fn upsert_track(&self, id: &Uuid, track_id: &Uuid, sync_id: &Uuid) -> Result<()>;
}

// UserRepository

#[async_trait]
pub trait UserRepository: Send + StdSync {
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<User>>;

    async fn get_by_spotify_email(&self, email: &str) -> Result<Option<User>>;

    async fn get_spotify_auth_by_id(&self, id: &Uuid) -> Result<Option<SpotifyAuth>>;

    async fn insert(&self, user: &User) -> Result<()>;

    async fn upsert_spotify_auth(&self, auth: &SpotifyAuth) -> Result<()>;
}

// ArtistRepository

#[async_trait]
pub trait ArtistRepository: Send + StdSync {
    async fn get_by_spotify_id(&self, id: &str) -> Result<Option<Artist>>;

    async fn insert(&self, artist: &Artist) -> Result<()>;
}

// TrackRepository

#[async_trait]
pub trait TrackRepository: Send + StdSync {
    async fn get_by_spotify_id(&self, id: &str) -> Result<Option<Track>>;

    async fn insert(&self, track: &Track, artist_ids: &[Uuid]) -> Result<()>;
}

// Pool

#[async_trait]
pub trait Pool: Send + StdSync {
    async fn client(&self) -> Result<Box<dyn Client>>;
}

// Config

#[derive(Clone, SecureDebug)]
pub struct Config {
    pub host: String,
    pub name: String,
    pub port: Option<u16>,
    #[sensitive]
    pub pwd: String,
    pub user: String,
}

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

// InTransactionError

#[derive(Debug)]
pub enum InTransactionError<E: StdError + Send + StdSync + 'static> {
    Client(Box<dyn StdError + Send + StdSync>),
    Execution(E),
}

impl<E: StdError + Send + StdSync + 'static> Display for InTransactionError<E> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Client(err) => write!(f, "{err}"),
            Self::Execution(err) => write!(f, "{err}"),
        }
    }
}

impl<E: StdError + Send + StdSync + 'static> StdError for InTransactionError<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Client(err) => Some(err.as_ref()),
            Self::Execution(err) => Some(err),
        }
    }
}

// in_transaction

pub async fn in_transaction<
    'a,
    E: StdError + Send + StdSync + 'static,
    F: for<'b> FnOnce(
        &'b (dyn Transaction + 'b),
    ) -> Pin<Box<dyn Future<Output = StdResult<T, E>> + Send + 'b>>,
    T,
>(
    client: &'a mut dyn Client,
    f: F,
) -> StdResult<T, InTransactionError<E>> {
    let tx = client
        .transaction()
        .await
        .map_err(InTransactionError::Client)?;
    match f(tx.as_ref()).await {
        Ok(val) => {
            tx.commit().await.map_err(InTransactionError::Client)?;
            Ok(val)
        }
        Err(err) => {
            if let Err(err) = tx.rollback().await {
                error!("database transaction rollback failed: {err}");
            }
            Err(InTransactionError::Execution(err))
        }
    }
}

// Mods

pub mod postgres;
