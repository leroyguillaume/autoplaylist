use std::{
    num::{ParseIntError, TryFromIntError},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptError, MagicCryptTrait};
use mockable::Env;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{migrate, migrate::MigrateError, pool::PoolConnection, PgPool, Postgres, Transaction};
use thiserror::Error;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::model::{
    Album, Credentials, Page, PageRequest, Platform, Playlist, Role, Source, SourceKind,
    SpotifyCredentials, SynchronizationStatus, Track, User,
};

use super::{
    DatabaseClient, DatabaseConnection, DatabaseError, DatabasePool, DatabaseResult,
    DatabaseTransaction, PlatformPlaylist, PlaylistCreation, SourceCreation, TrackCreation,
};

use self::{playlist::*, src::*, track::*, usr::*};

// Macros

macro_rules! client_impl {
    ($type:ty) => {
        #[async_trait]
        impl DatabaseClient for $type {
            async fn add_track_to_playlist(
                &mut self,
                playlist_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<()> {
                add_track_to_playlist(playlist_id, track_id, &mut self.conn).await?;
                Ok(())
            }

            async fn add_track_to_source(
                &mut self,
                src_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<()> {
                add_track_to_source(src_id, track_id, &mut self.conn).await?;
                Ok(())
            }

            fn as_client_mut(&mut self) -> &mut dyn DatabaseClient {
                self
            }

            async fn count_source_playlists(&mut self, id: Uuid) -> DatabaseResult<u32> {
                let count = count_source_playlists(id, &mut self.conn).await?;
                Ok(count)
            }

            async fn create_playlist(
                &mut self,
                creation: &PlaylistCreation,
            ) -> DatabaseResult<Playlist> {
                let playlist = create_playlist(creation, &self.key, &mut self.conn).await?;
                Ok(playlist)
            }

            async fn create_source(&mut self, creation: &SourceCreation) -> DatabaseResult<Source> {
                let src = create_source(creation, &self.key, &mut self.conn).await?;
                Ok(src)
            }

            async fn create_track(&mut self, creation: &TrackCreation) -> DatabaseResult<Track> {
                let track = create_track(creation, &mut self.conn).await?;
                Ok(track)
            }

            async fn create_user(&mut self, creds: &Credentials) -> DatabaseResult<User> {
                let user = create_user(creds, &self.key, &mut self.conn).await?;
                Ok(user)
            }

            async fn delete_playlist(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let deleted = delete_playlist(id, &mut self.conn).await?;
                Ok(deleted)
            }

            async fn delete_source(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let deleted = delete_source(id, &mut self.conn).await?;
                Ok(deleted)
            }

            async fn delete_track(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let deleted = delete_track(id, &mut self.conn).await?;
                Ok(deleted)
            }

            async fn delete_tracks_from_playlist(&mut self, id: Uuid) -> DatabaseResult<u64> {
                let count = delete_tracks_from_playlist(id, &mut self.conn).await?;
                Ok(count)
            }

            async fn delete_tracks_from_source(&mut self, id: Uuid) -> DatabaseResult<u64> {
                let count = delete_tracks_from_source(id, &mut self.conn).await?;
                Ok(count)
            }

            async fn delete_user(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let deleted = delete_user(id, &mut self.conn).await?;
                Ok(deleted)
            }

            async fn delete_user_platform_playlists(
                &mut self,
                id: Uuid,
                platform: Platform,
            ) -> DatabaseResult<u64> {
                let count = delete_user_platform_playlists(id, platform, &mut self.conn).await?;
                Ok(count)
            }

            async fn playlist_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Playlist>> {
                let playlist = playlist_by_id(id, &self.key, &mut self.conn).await?;
                Ok(playlist)
            }

            async fn playlist_contains_track(
                &mut self,
                playlist_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<bool> {
                let contains =
                    playlist_contains_track(playlist_id, track_id, &mut self.conn).await?;
                Ok(contains)
            }

            async fn playlist_exists(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let exists = playlist_exists(id, &mut self.conn).await?;
                Ok(exists)
            }

            async fn playlist_ids_by_source(
                &mut self,
                src_id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Uuid>> {
                let page = playlist_ids_by_source(src_id, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn playlist_tracks(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                let page = playlist_tracks(id, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn playlists(&mut self, req: PageRequest) -> DatabaseResult<Page<Playlist>> {
                let page = playlists(req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn save_user_platform_playlist(
                &mut self,
                id: Uuid,
                playlist: &PlatformPlaylist,
            ) -> DatabaseResult<()> {
                save_user_platform_playlist(id, playlist, &mut self.conn).await?;
                Ok(())
            }

            async fn search_playlist_tracks_by_title_artists_album(
                &mut self,
                id: Uuid,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                let page =
                    search_playlist_tracks_by_title_artists_album(id, q, req, &mut self.conn)
                        .await?;
                Ok(page)
            }

            async fn search_playlists_by_name(
                &mut self,
                name: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                let page = search_playlists_by_name(name, req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn search_source_tracks_by_title_artists_album(
                &mut self,
                id: Uuid,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                let page =
                    search_source_tracks_by_title_artists_album(id, q, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn search_tracks_by_title_artists_album(
                &mut self,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                let page = search_tracks_by_title_artists_album(q, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn search_user_platform_playlists_by_name(
                &mut self,
                id: Uuid,
                platform: Platform,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<PlatformPlaylist>> {
                let page =
                    search_user_platform_playlists_by_name(id, platform, q, req, &mut self.conn)
                        .await?;
                Ok(page)
            }

            async fn search_user_playlists_by_name(
                &mut self,
                id: Uuid,
                name: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                let page =
                    search_user_playlists_by_name(id, name, req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn search_users_by_email(
                &mut self,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<User>> {
                let page = search_users_by_email(q, req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn source_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Source>> {
                let src = source_by_id(id, &self.key, &mut self.conn).await?;
                Ok(src)
            }

            async fn source_by_owner_kind(
                &mut self,
                owner_id: Uuid,
                kind: &SourceKind,
            ) -> DatabaseResult<Option<Source>> {
                let src = source_by_owner_kind(owner_id, kind, &self.key, &mut self.conn).await?;
                Ok(src)
            }

            async fn source_contains_track(
                &mut self,
                src_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<bool> {
                let contains = source_contains_track(src_id, track_id, &mut self.conn).await?;
                Ok(contains)
            }

            async fn source_exists(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let exists = source_exists(id, &mut self.conn).await?;
                Ok(exists)
            }

            async fn source_ids_by_last_synchronization_date(
                &mut self,
                date: DateTime<Utc>,
                req: PageRequest,
            ) -> DatabaseResult<Page<Uuid>> {
                let page =
                    source_ids_by_last_synchronization_date(date, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn source_ids_by_synchronization_status(
                &mut self,
                status: SynchronizationStatus,
                req: PageRequest,
            ) -> DatabaseResult<Page<Uuid>> {
                let page =
                    source_ids_by_synchronization_status(status, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn source_tracks(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                let page = source_tracks(id, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn sources(&mut self, req: PageRequest) -> DatabaseResult<Page<Source>> {
                let page = sources(req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn track_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Track>> {
                let track = track_by_id(id, &mut self.conn).await?;
                Ok(track)
            }

            async fn track_by_platform_id(
                &mut self,
                platform: Platform,
                platform_id: &str,
            ) -> DatabaseResult<Option<Track>> {
                let track = track_by_platform_id(platform, platform_id, &mut self.conn).await?;
                Ok(track)
            }

            async fn tracks(&mut self, req: PageRequest) -> DatabaseResult<Page<Track>> {
                let page = tracks(req, &mut self.conn).await?;
                Ok(page)
            }

            async fn update_playlist(&mut self, playlist: &Playlist) -> DatabaseResult<bool> {
                let updated = update_playlist(playlist, false, &mut self.conn).await?;
                Ok(updated)
            }

            async fn update_playlist_safely(
                &mut self,
                playlist: &Playlist,
            ) -> DatabaseResult<bool> {
                let updated = update_playlist(playlist, true, &mut self.conn).await?;
                Ok(updated)
            }

            async fn update_source(&mut self, src: &Source) -> DatabaseResult<bool> {
                let updated = update_source(src, false, &mut self.conn).await?;
                Ok(updated)
            }

            async fn update_source_safely(&mut self, src: &Source) -> DatabaseResult<bool> {
                let updated = update_source(src, true, &mut self.conn).await?;
                Ok(updated)
            }

            async fn update_track(&mut self, track: &Track) -> DatabaseResult<bool> {
                let updated = update_track(track, &mut self.conn).await?;
                Ok(updated)
            }

            async fn update_user(&mut self, user: &User) -> DatabaseResult<bool> {
                let updated = update_user(user, &self.key, &mut self.conn).await?;
                Ok(updated)
            }

            async fn user_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<User>> {
                let user = user_by_id(id, &self.key, &mut self.conn).await?;
                Ok(user)
            }

            async fn user_by_spotify_id(&mut self, id: &str) -> DatabaseResult<Option<User>> {
                let user = user_by_spotify_id(id, &self.key, &mut self.conn).await?;
                Ok(user)
            }

            async fn user_exists(&mut self, id: Uuid) -> DatabaseResult<bool> {
                let exists = user_exists(id, &mut self.conn).await?;
                Ok(exists)
            }

            async fn user_platform_playlists(
                &mut self,
                id: Uuid,
                platform: Platform,
                req: PageRequest,
            ) -> DatabaseResult<Page<PlatformPlaylist>> {
                let page = user_platform_playlists(id, platform, req, &mut self.conn).await?;
                Ok(page)
            }

            async fn user_playlists(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                let page = user_playlists(id, req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn user_sources(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Source>> {
                let page = user_sources(id, req, &self.key, &mut self.conn).await?;
                Ok(page)
            }

            async fn users(&mut self, req: PageRequest) -> DatabaseResult<Page<User>> {
                let page = users(req, &self.key, &mut self.conn).await?;
                Ok(page)
            }
        }
    };
}

// Consts - Env var keys

pub const ENV_VAR_KEY_DB_HOST: &str = "DATABASE_HOST";
pub const ENV_VAR_KEY_DB_NAME: &str = "DATABASE_NAME";
pub const ENV_VAR_KEY_DB_PASSWORD: &str = "DATABASE_PASSWORD";
pub const ENV_VAR_KEY_DB_PORT: &str = "DATABASE_PORT";
pub const ENV_VAR_KEY_DB_SECRET: &str = "DATABASE_SECRET";
pub const ENV_VAR_KEY_DB_USER: &str = "DATABASE_USER";

// Consts - Defaults

pub const DEFAULT_DB_HOST: &str = "localhost";
pub const DEFAULT_DB_NAME: &str = "autoplaylist";
pub const DEFAULT_DB_PORT: u16 = 5432;
pub const DEFAULT_DB_USER: &str = "autoplaylist";

// Types

type PostgresResult<T> = Result<T, PostgresError>;

// PostgresConfigError

#[derive(Debug, Error)]
pub enum PostgresConfigError {
    #[error("invalid database port: {0}")]
    InvalidPort(
        #[from]
        #[source]
        ParseIntError,
    ),
    #[error("missing environment variable `{0}`")]
    MissingEnvVar(&'static str),
}

// PostgresError

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error("failed to cast integer: {0}")]
    Cast(
        #[from]
        #[source]
        TryFromIntError,
    ),
    #[error("{0}")]
    Client(
        #[from]
        #[source]
        sqlx::Error,
    ),
    #[error("failed to decrypt secret: {0}")]
    Decryption(
        #[from]
        #[source]
        MagicCryptError,
    ),
    #[error("JSON error: {0}")]
    Json(
        #[from]
        #[source]
        serde_json::Error,
    ),
}

// PostgresInitError

#[derive(Debug, Error)]
pub enum PostgresInitError {
    #[error("failed to run database migrations: {0}")]
    Migration(
        #[from]
        #[source]
        MigrateError,
    ),
    #[error("failed to create database connection pool: {0}")]
    PoolCreation(
        #[from]
        #[source]
        sqlx::Error,
    ),
}

// PostgresConfig

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresConfig {
    pub host: String,
    pub name: String,
    pub password: String,
    pub port: u16,
    pub secret: String,
    pub user: String,
}

impl PostgresConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, PostgresConfigError> {
        debug!("loading PostgreSQL configuration");
        let cfg = Self {
            host: env
                .string(ENV_VAR_KEY_DB_HOST)
                .unwrap_or_else(|| DEFAULT_DB_HOST.into()),
            name: env
                .string(ENV_VAR_KEY_DB_NAME)
                .unwrap_or_else(|| DEFAULT_DB_NAME.into()),
            password: env
                .string(ENV_VAR_KEY_DB_PASSWORD)
                .ok_or(PostgresConfigError::MissingEnvVar(ENV_VAR_KEY_DB_PASSWORD))?,
            port: env
                .u16(ENV_VAR_KEY_DB_PORT)
                .unwrap_or(Ok(DEFAULT_DB_PORT))?,
            secret: env
                .string(ENV_VAR_KEY_DB_SECRET)
                .ok_or(PostgresConfigError::MissingEnvVar(ENV_VAR_KEY_DB_SECRET))?,
            user: env
                .string(ENV_VAR_KEY_DB_USER)
                .unwrap_or_else(|| DEFAULT_DB_USER.into()),
        };
        debug!(
            pg.cfg.host = cfg.host,
            pg.cfg.name = cfg.name,
            pg.cfg.port = cfg.port,
            pg.cfg.user = cfg.user,
            "PostgreSQL configuration loaded"
        );
        Ok(cfg)
    }
}

// PostgresConnection

pub struct PostgresConnection {
    conn: PoolConnection<Postgres>,
    key: Arc<MagicCrypt256>,
}

client_impl!(PostgresConnection);

impl DatabaseConnection for PostgresConnection {}

// PostgresPool

#[allow(dead_code)]
pub struct PostgresPool {
    key: Arc<MagicCrypt256>,
    pool: PgPool,
}

impl PostgresPool {
    pub async fn init(cfg: PostgresConfig) -> Result<Self, PostgresInitError> {
        let url = format!(
            "postgres://{}:{}@{}:{}/{}",
            cfg.user, cfg.password, cfg.host, cfg.port, cfg.name
        );
        debug!("connecting to database");
        let pool = PgPool::connect(&url).await?;
        Self::from_pool(pool, &cfg.secret).await
    }

    pub async fn from_pool(pool: PgPool, secret: &str) -> Result<Self, PostgresInitError> {
        info!("running database migrations");
        migrate!("resources/main/db/pg/migrations")
            .run(&pool)
            .await?;
        info!("database migrations completed");
        let key = Arc::new(new_magic_crypt!(secret, 256));
        Ok(Self { key, pool })
    }
}

#[async_trait]
impl<'a> DatabasePool<PostgresConnection, PostgresTransaction<'a>> for PostgresPool {
    async fn acquire(&self) -> DatabaseResult<PostgresConnection> {
        trace!("acquiring connection from pool");
        let conn = self.pool.acquire().await?;
        Ok(PostgresConnection {
            conn,
            key: self.key.clone(),
        })
    }

    async fn begin(&self) -> DatabaseResult<PostgresTransaction<'a>> {
        trace!("beginning transaction");
        let conn = self.pool.begin().await?;
        Ok(PostgresTransaction {
            conn,
            key: self.key.clone(),
        })
    }
}

// PostgresTransaction

pub struct PostgresTransaction<'a> {
    conn: Transaction<'a, Postgres>,
    key: Arc<MagicCrypt256>,
}

client_impl!(PostgresTransaction<'_>);

#[async_trait]
impl<'a> DatabaseTransaction for PostgresTransaction<'a> {
    async fn commit(self) -> DatabaseResult<()> {
        trace!("committing transaction");
        self.conn.commit().await?;
        Ok(())
    }

    async fn rollback(self) -> DatabaseResult<()> {
        trace!("rolling back transaction");
        self.conn.rollback().await?;
        Ok(())
    }
}

// DatabaseError

impl From<PostgresError> for DatabaseError {
    fn from(err: PostgresError) -> Self {
        Self(Box::new(err))
    }
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        Self(Box::new(PostgresError::Client(err)))
    }
}

// PlatformPlaylistRecord

struct PlatformPlaylistRecord {
    platform_playlist_id: String,
    platform_playlist_name: String,
    platform_playlist_platform: Platform,
}

impl PlatformPlaylistRecord {
    fn into_entity(self) -> PlatformPlaylist {
        PlatformPlaylist {
            id: self.platform_playlist_id,
            name: self.platform_playlist_name,
            platform: self.platform_playlist_platform,
        }
    }
}

// PlaylistRecord

struct PlaylistRecord {
    owner_creation: DateTime<Utc>,
    owner_creds: String,
    owner_id: Uuid,
    owner_role: Role,
    playlist_creation: DateTime<Utc>,
    playlist_id: Uuid,
    playlist_name: String,
    playlist_predicate: Value,
    playlist_sync: Value,
    playlist_tgt: Value,
    src_creation: DateTime<Utc>,
    src_kind: Value,
    src_id: Uuid,
    src_sync: Value,
}

impl PlaylistRecord {
    fn into_entity(self, key: &MagicCrypt256) -> PostgresResult<Playlist> {
        let src_record = SourceRecord {
            owner_creation: self.owner_creation,
            owner_creds: self.owner_creds,
            owner_id: self.owner_id,
            owner_role: self.owner_role,
            src_creation: self.src_creation,
            src_id: self.src_id,
            src_kind: self.src_kind,
            src_sync: self.src_sync,
        };
        Ok(Playlist {
            creation: self.playlist_creation,
            id: self.playlist_id,
            name: self.playlist_name,
            predicate: serde_json::from_value(self.playlist_predicate)?,
            src: src_record.into_entity(key)?,
            sync: serde_json::from_value(self.playlist_sync)?,
            tgt: serde_json::from_value(self.playlist_tgt)?,
        })
    }
}

// SourceRecord

struct SourceRecord {
    owner_creation: DateTime<Utc>,
    owner_creds: String,
    owner_id: Uuid,
    owner_role: Role,
    src_creation: DateTime<Utc>,
    src_kind: Value,
    src_id: Uuid,
    src_sync: Value,
}

impl SourceRecord {
    fn into_entity(self, key: &MagicCrypt256) -> PostgresResult<Source> {
        let user_record = UserRecord {
            usr_creation: self.owner_creation,
            usr_creds: self.owner_creds,
            usr_id: self.owner_id,
            usr_role: self.owner_role,
        };
        Ok(Source {
            creation: self.src_creation,
            id: self.src_id,
            kind: serde_json::from_value(self.src_kind)?,
            owner: user_record.into_entity(key)?,
            sync: serde_json::from_value(self.src_sync)?,
        })
    }
}

// SpotifyPublicCredentials

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpotifyPublicCredentials {
    email: String,
    id: String,
}

impl From<SpotifyCredentials> for SpotifyPublicCredentials {
    fn from(creds: SpotifyCredentials) -> Self {
        Self {
            email: creds.email,
            id: creds.id,
        }
    }
}

// TrackRecord

struct TrackRecord {
    track_album: String,
    track_artists: Vec<String>,
    track_creation: DateTime<Utc>,
    track_from_compil: bool,
    track_id: Uuid,
    track_platform: Platform,
    track_platform_id: String,
    track_title: String,
    track_year: i32,
}

impl TrackRecord {
    fn into_entity(self) -> PostgresResult<Track> {
        Ok(Track {
            album: Album {
                compil: self.track_from_compil,
                name: self.track_album,
            },
            artists: self.track_artists.into_iter().collect(),
            creation: self.track_creation,
            id: self.track_id,
            platform: self.track_platform,
            platform_id: self.track_platform_id,
            title: self.track_title,
            year: self.track_year,
        })
    }
}

// UserRecord

struct UserRecord {
    usr_creation: DateTime<Utc>,
    usr_creds: String,
    usr_id: Uuid,
    usr_role: Role,
}

impl UserRecord {
    fn into_entity(self, key: &MagicCrypt256) -> PostgresResult<User> {
        trace!("decrypting user credentials");
        let creds = key.decrypt_base64_to_string(self.usr_creds)?;
        trace!("deserializing user credentials");
        let creds = serde_json::from_str(&creds)?;
        Ok(User {
            creation: self.usr_creation,
            creds,
            id: self.usr_id,
            role: self.usr_role,
        })
    }
}

// Mods

mod playlist;
mod src;
mod track;
mod usr;

// Tests

#[cfg(test)]
mod test {
    use std::{collections::BTreeSet, io::stderr};

    use mockable::{DefaultEnv, MockEnv};
    use mockall::predicate::eq;
    use sqlx::query_file;

    use crate::{
        model::{
            Credentials, Predicate, SourceKind, SourceSynchronizationStep, SpotifyCredentials,
            SpotifySourceKind, SpotifyToken, Synchronization, SynchronizationState, Target,
        },
        test_env_var, TracingConfig,
    };

    use super::*;

    // Data

    pub struct Data {
        pub playlists: Vec<Playlist>,
        pub srcs: Vec<Source>,
        pub tracks: Vec<Track>,
        pub usrs: Vec<FullUser>,
    }

    impl Data {
        pub fn new() -> Self {
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "dusty in memphis".into(),
                },
                artists: BTreeSet::from_iter(["dusty springfield".into()]),
                creation: DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xd16eb9f1cf4d4a419515e9a8125d7843),
                platform: Platform::Spotify,
                platform_id: "track_1".into(),
                title: "son of a preacher man".into(),
                year: 1969,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "st. louis to liverpool".into(),
                },
                artists: BTreeSet::from_iter(["chuck berry".into()]),
                creation: DateTime::parse_from_rfc3339("2023-01-02T00:01:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x9095b250d4ab427fb38f32aaf45afec5),
                platform: Platform::Spotify,
                platform_id: "track_2".into(),
                title: "you never can tell".into(),
                year: 1964,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the letter/neon rainbow".into(),
                },
                artists: BTreeSet::from_iter(["the box tops".into()]),
                creation: DateTime::parse_from_rfc3339("2023-01-02T00:02:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xf747ca3a0cc74d9fb38adc506f99f5df),
                platform: Platform::Spotify,
                platform_id: "track_3".into(),
                title: "the letter".into(),
                year: 1967,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "i/o".into(),
                },
                artists: BTreeSet::from_iter(["peter gabriel".into()]),
                creation: DateTime::parse_from_rfc3339("2023-01-02T00:03:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x38ac42e015794f3f9816081f4df0210a),
                platform: Platform::Spotify,
                platform_id: "track_4".into(),
                title: "panopticom".into(),
                year: 2023,
            };
            let usr_1 = FullUser {
                usr: User {
                    creation: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "user_1@test".into(),
                            id: "user_1".into(),
                            token: SpotifyToken {
                                access: "access".into(),
                                expiration: DateTime::parse_from_rfc3339("2023-01-01T03:00:00Z")
                                    .expect("failed to parse date")
                                    .into(),
                                refresh: "refresh".into(),
                            },
                        }),
                    },
                    id: Uuid::from_u128(0xee21186a990c42e9bcd269f9090a7736),
                    role: Role::Admin,
                },
                spotify_playlists: vec![
                    PlatformPlaylist {
                        id: "playlist_1".into(),
                        name: "playlist_1".into(),
                        platform: Platform::Spotify,
                    },
                    PlatformPlaylist {
                        id: "playlist_2".into(),
                        name: "playlist_2".into(),
                        platform: Platform::Spotify,
                    },
                    PlatformPlaylist {
                        id: "playlist_3".into(),
                        name: "playlist_3".into(),
                        platform: Platform::Spotify,
                    },
                    PlatformPlaylist {
                        id: "test".into(),
                        name: "test".into(),
                        platform: Platform::Spotify,
                    },
                ],
            };
            let usr_2 = FullUser {
                usr: User {
                    creation: DateTime::parse_from_rfc3339("2023-02-01T00:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "user_2@test".into(),
                            id: "user_2".into(),
                            token: SpotifyToken {
                                access: "access".into(),
                                expiration: DateTime::parse_from_rfc3339("2023-01-01T03:00:00Z")
                                    .expect("failed to parse date")
                                    .into(),
                                refresh: "refresh".into(),
                            },
                        }),
                    },
                    id: Uuid::from_u128(0xec1ca9f93c4744a295c7a13ff6de852d),
                    role: Role::User,
                },
                spotify_playlists: vec![PlatformPlaylist {
                    id: "playlist_4".into(),
                    name: "playlist_4".into(),
                    platform: Platform::Spotify,
                }],
            };
            let usr_3 = FullUser {
                usr: User {
                    creation: DateTime::parse_from_rfc3339("2023-03-01T00:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "test_3@test".into(),
                            id: "user_3".into(),
                            token: SpotifyToken {
                                access: "access".into(),
                                expiration: DateTime::parse_from_rfc3339("2023-01-01T03:00:00Z")
                                    .expect("failed to parse date")
                                    .into(),
                                refresh: "refresh".into(),
                            },
                        }),
                    },
                    id: Uuid::from_u128(0x8fc899c5f25449669b5ae8f1c4f97f7c),
                    role: Role::User,
                },
                spotify_playlists: vec![],
            };
            let usr_4 = FullUser {
                usr: User {
                    creation: DateTime::parse_from_rfc3339("2023-04-01T00:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                    creds: Default::default(),
                    id: Uuid::from_u128(0x83e3a7ed9d6c4e4fb7328a00cab3fcb5),
                    role: Role::User,
                },
                spotify_playlists: vec![],
            };
            let usr_5 = FullUser {
                usr: User {
                    creation: DateTime::parse_from_rfc3339("2023-05-01T00:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "user_5@test".into(),
                            id: "user_5".into(),
                            token: SpotifyToken {
                                access: "access".into(),
                                expiration: DateTime::parse_from_rfc3339("2023-01-01T03:00:00Z")
                                    .expect("failed to parse date")
                                    .into(),
                                refresh: "refresh".into(),
                            },
                        }),
                    },
                    id: Uuid::from_u128(0xee187392847143f4a3cde541fd7640f4),
                    role: Role::User,
                },
                spotify_playlists: vec![],
            };
            let src_1 = Source {
                creation: DateTime::parse_from_rfc3339("2023-01-05T01:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x911ca8e748744bf4b8e11ddd1b6cee41),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: usr_1.usr.clone(),
                sync: Synchronization::Succeeded {
                    end: DateTime::parse_from_rfc3339("2023-01-05T01:00:10Z")
                        .expect("failed to parse date")
                        .into(),
                    start: DateTime::parse_from_rfc3339("2023-01-05T01:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                },
            };
            let src_2 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T02:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xf1c418db13c047a79ecb9aa4cf4995eb),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_2".into())),
                owner: usr_1.usr.clone(),
                sync: Synchronization::Running(
                    DateTime::parse_from_rfc3339("2023-02-05T00:00:10Z")
                        .expect("failed to parse date")
                        .into(),
                ),
            };
            let src_3 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T03:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x12d423d13bc04eefb0c66748beb7d52e),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_3".into())),
                owner: usr_1.usr.clone(),
                sync: Synchronization::Succeeded {
                    end: DateTime::parse_from_rfc3339("2023-01-05T02:00:10Z")
                        .expect("failed to parse date")
                        .into(),
                    start: DateTime::parse_from_rfc3339("2023-01-05T02:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                },
            };
            let src_4 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T04:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xa23c9cc92b7246db9a52922f1c09db01),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_4".into())),
                owner: usr_2.usr.clone(),
                sync: Synchronization::Succeeded {
                    end: DateTime::parse_from_rfc3339("2023-01-05T03:00:10Z")
                        .expect("failed to parse date")
                        .into(),
                    start: DateTime::parse_from_rfc3339("2023-01-05T03:00:00Z")
                        .expect("failed to parse date")
                        .into(),
                },
            };
            let src_5 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T05:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x2d2e540155e1408499258fbea33cf9cf),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_5".into())),
                owner: usr_2.usr.clone(),
                sync: Synchronization::Succeeded {
                    end: DateTime::parse_from_rfc3339("2023-01-05T03:06:10Z")
                        .expect("failed to parse date")
                        .into(),
                    start: DateTime::parse_from_rfc3339("2023-01-05T03:06:00Z")
                        .expect("failed to parse date")
                        .into(),
                },
            };
            let src_6 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T06:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xb919d322823d4a4ebc3df7dfde83f698),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_6".into())),
                owner: usr_2.usr.clone(),
                sync: Synchronization::Aborted {
                    end: DateTime::parse_from_rfc3339("2023-01-05T03:06:10Z")
                        .expect("failed to parse date")
                        .into(),
                    state: SynchronizationState {
                        start: DateTime::parse_from_rfc3339("2023-01-05T03:06:00Z")
                            .expect("failed to parse date")
                            .into(),
                        step: SourceSynchronizationStep::Finished,
                    },
                },
            };
            let src_7 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T07:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xda933c0b5bc64eeaa96735e9c8636417),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_7".into())),
                owner: usr_2.usr.clone(),
                sync: Synchronization::Failed {
                    details: "error".into(),
                    end: DateTime::parse_from_rfc3339("2023-01-05T03:06:10Z")
                        .expect("failed to parse date")
                        .into(),
                    state: SynchronizationState {
                        start: DateTime::parse_from_rfc3339("2023-01-05T03:06:00Z")
                            .expect("failed to parse date")
                            .into(),
                        step: SourceSynchronizationStep::Finished,
                    },
                },
            };
            let src_8 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T08:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x5b21b979a37f40e893ec541e45c29847),
                kind: SourceKind::Spotify(SpotifySourceKind::Playlist("src_8".into())),
                owner: usr_2.usr.clone(),
                sync: Synchronization::Pending,
            };
            Self {
                playlists: vec![
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-01-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0xe1195b8b6a5d48968889137775fc8863),
                        name: "playlist_1".into(),
                        predicate: Predicate::YearIs(1993),
                        src: src_1.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_1".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-02-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0x58fb7bd7efe24346ac1f2f21b8c3dd7c),
                        name: "playlist_2".into(),
                        predicate: Predicate::YearIs(2013),
                        src: src_1.clone(),
                        sync: Synchronization::Running(
                            DateTime::parse_from_rfc3339("2023-02-05T00:00:10Z")
                                .expect("failed to parse date")
                                .into(),
                        ),
                        tgt: Target::Spotify("playlist_2".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-03-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0xa80267ba89be4350ac0d8ebecb88efa0),
                        name: "playlist_3".into(),
                        predicate: Predicate::YearIs(1961),
                        src: src_1.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_3".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-04-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0x36f24355f5064b40955ef42a1c49c138),
                        name: "playlist_4".into(),
                        predicate: Predicate::YearIs(1999),
                        src: src_4.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_4".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-05-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0x738c1907163042ee89b8bd28cd3701a5),
                        name: "test_5".into(),
                        predicate: Predicate::YearIs(1999),
                        src: src_4.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_5".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-06-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0x08310fbb14be4b00abf85a60e187b164),
                        name: "test_6".into(),
                        predicate: Predicate::YearIs(1999),
                        src: src_2.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_6".into()),
                    },
                ],
                srcs: vec![src_1, src_2, src_3, src_4, src_5, src_6, src_7, src_8],
                tracks: vec![track_1, track_2, track_3, track_4],
                usrs: vec![usr_1, usr_2, usr_3, usr_4, usr_5],
            }
        }
    }

    impl Default for Data {
        fn default() -> Self {
            Self::new()
        }
    }

    // FullUser

    #[derive(Debug, Clone)]
    pub struct FullUser {
        pub spotify_playlists: Vec<PlatformPlaylist>,
        pub usr: User,
    }

    // init

    pub async fn init(db: PgPool) -> PostgresPool {
        TracingConfig::new("autoplaylist-common", stderr).init(&DefaultEnv);
        let secret: String = test_env_var(ENV_VAR_KEY_DB_SECRET, || "changeit".into());
        let db = PostgresPool::from_pool(db, &secret)
            .await
            .expect("failed to initialize database client");
        let mut conn = db
            .begin()
            .await
            .expect("failed to begin database transaction");
        query_file!("resources/test/db/data.sql")
            .execute(&mut *conn.conn)
            .await
            .expect("failed to insert data");
        conn.commit()
            .await
            .expect("failed to commit database transaction");
        db
    }

    // Mods

    mod postgres_config {
        use super::*;

        // Mods

        mod from_env {
            use super::*;

            // Params

            struct Params {
                host: Option<String>,
                name: Option<String>,
                password: String,
                port: Option<u16>,
                secret: String,
                user: Option<String>,
            }

            // mock_optional_string

            fn mock_optional_string(key: &'static str, val: Option<String>, mock: &mut MockEnv) {
                mock.expect_string()
                    .with(eq(key))
                    .times(1)
                    .return_const(val);
            }

            // mock_string

            fn mock_string(key: &'static str, val: String, mock: &mut MockEnv) {
                mock.expect_string()
                    .with(eq(key))
                    .times(1)
                    .returning(move |_| Some(val.clone()));
            }

            // run

            fn run(params: Params, expected: PostgresConfig) {
                let mut env = MockEnv::new();
                mock_optional_string(ENV_VAR_KEY_DB_HOST, params.host, &mut env);
                mock_optional_string(ENV_VAR_KEY_DB_NAME, params.name, &mut env);
                mock_string(ENV_VAR_KEY_DB_PASSWORD, params.password, &mut env);
                env.expect_u16()
                    .with(eq(ENV_VAR_KEY_DB_PORT))
                    .times(1)
                    .returning(move |_| params.port.map(Ok));
                mock_string(ENV_VAR_KEY_DB_SECRET, params.secret, &mut env);
                mock_optional_string(ENV_VAR_KEY_DB_USER, params.user, &mut env);
                let cfg = PostgresConfig::from_env(&env)
                    .expect("failed to load PostgreSQL configuration");
                assert_eq!(cfg, expected);
            }

            // Tests

            #[test]
            fn default() {
                let expected = PostgresConfig {
                    host: DEFAULT_DB_HOST.into(),
                    name: DEFAULT_DB_NAME.into(),
                    password: "password".into(),
                    port: DEFAULT_DB_PORT,
                    secret: "secret".into(),
                    user: DEFAULT_DB_USER.into(),
                };
                let params = Params {
                    host: None,
                    name: None,
                    password: expected.password.clone(),
                    port: None,
                    secret: expected.secret.clone(),
                    user: None,
                };
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = PostgresConfig {
                    host: "host".into(),
                    name: "name".into(),
                    password: "password".into(),
                    port: 12345,
                    secret: "secret".into(),
                    user: "user".into(),
                };
                let params = Params {
                    host: Some(expected.host.clone()),
                    name: Some(expected.name.clone()),
                    password: expected.password.clone(),
                    port: Some(expected.port),
                    secret: expected.secret.clone(),
                    user: Some(expected.user.clone()),
                };
                run(params, expected);
            }
        }
    }
}
