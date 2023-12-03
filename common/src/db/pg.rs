use std::{
    collections::BTreeSet,
    num::{ParseIntError, TryFromIntError},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptError, MagicCryptTrait};
use mockable::Env;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{
    migrate, migrate::MigrateError, pool::PoolConnection, query_file, query_file_as, Acquire,
    PgConnection, PgPool, Postgres, Transaction,
};
use thiserror::Error;
use tracing::{debug, debug_span, info, trace, Instrument};
use uuid::Uuid;

use crate::model::{
    Album, Credentials, Page, PageRequest, Playlist, PlaylistSynchronization, Role, Source,
    SourceKind, SourceSynchronization, Synchronization, SynchronizationStep, Track, User,
};

use super::{
    DatabaseClient, DatabaseConnection, DatabaseError, DatabasePool, DatabaseResult,
    DatabaseTransaction, PlaylistCreation, SourceCreation, TrackCreation, UserCreation,
};

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

            async fn create_user(&mut self, creation: &UserCreation) -> DatabaseResult<User> {
                let user = create_user(creation, &self.key, &mut self.conn).await?;
                Ok(user)
            }

            async fn delete_playlist(&mut self, id: Uuid) -> DatabaseResult<()> {
                delete_playlist(id, &mut self.conn).await?;
                Ok(())
            }

            async fn delete_source(&mut self, id: Uuid) -> DatabaseResult<()> {
                delete_source(id, &mut self.conn).await?;
                Ok(())
            }

            async fn delete_tracks_from_playlist(&mut self, id: Uuid) -> DatabaseResult<()> {
                delete_tracks_from_playlist(id, &mut self.conn).await?;
                Ok(())
            }

            async fn delete_tracks_from_source(&mut self, id: Uuid) -> DatabaseResult<()> {
                delete_tracks_from_source(id, &mut self.conn).await?;
                Ok(())
            }

            async fn lock_playlist_synchronization(
                &mut self,
                id: Uuid,
            ) -> DatabaseResult<Option<PlaylistSynchronization>> {
                let sync = lock_playlist_synchronization(id, &mut self.conn).await?;
                Ok(sync)
            }

            async fn lock_source_synchronization(
                &mut self,
                id: Uuid,
            ) -> DatabaseResult<Option<SourceSynchronization>> {
                let sync = lock_source_synchronization(id, &mut self.conn).await?;
                Ok(sync)
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

            async fn track_by_title_artists_album_year(
                &mut self,
                title: &str,
                artists: &BTreeSet<String>,
                album: &str,
                year: i32,
            ) -> DatabaseResult<Option<Track>> {
                let track =
                    track_by_title_artists_album_year(title, artists, album, year, &mut self.conn)
                        .await?;
                Ok(track)
            }

            async fn tracks(&mut self, req: PageRequest) -> DatabaseResult<Page<Track>> {
                let page = tracks(req, &mut self.conn).await?;
                Ok(page)
            }

            async fn update_playlist(&mut self, playlist: &Playlist) -> DatabaseResult<()> {
                update_playlist(playlist, &mut self.conn).await?;
                Ok(())
            }

            async fn update_source(&mut self, src: &Source) -> DatabaseResult<()> {
                update_source(src, &mut self.conn).await?;
                Ok(())
            }

            async fn update_track(&mut self, track: &Track) -> DatabaseResult<()> {
                update_track(track, &mut self.conn).await?;
                Ok(())
            }

            async fn update_user(&mut self, user: &User) -> DatabaseResult<()> {
                update_user(user, &self.key, &mut self.conn).await?;
                Ok(())
            }

            async fn user_by_email(&mut self, email: &str) -> DatabaseResult<Option<User>> {
                let user = user_by_email(email, &self.key, &mut self.conn).await?;
                Ok(user)
            }

            async fn user_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<User>> {
                let user = user_by_id(id, &self.key, &mut self.conn).await?;
                Ok(user)
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
        Ok(Self {
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
        })
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

// PlaylistRecord

struct PlaylistRecord {
    owner_creation: DateTime<Utc>,
    owner_creds: String,
    owner_email: String,
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
            owner_email: self.owner_email,
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
    owner_email: String,
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
            usr_email: self.owner_email,
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

// SynchronizationRecord

struct SynchronizationRecord {
    sync: Value,
}

impl SynchronizationRecord {
    fn into_entity<S: SynchronizationStep + DeserializeOwned>(
        self,
    ) -> PostgresResult<Synchronization<S>> {
        let sync = serde_json::from_value(self.sync)?;
        Ok(sync)
    }
}

// TrackRecord

struct TrackRecord {
    track_album: String,
    track_artists: Vec<String>,
    track_creation: DateTime<Utc>,
    track_from_compil: bool,
    track_id: Uuid,
    track_spotify_id: Option<String>,
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
            spotify_id: self.track_spotify_id,
            title: self.track_title,
            year: self.track_year,
        })
    }
}

// UserRecord

struct UserRecord {
    usr_creation: DateTime<Utc>,
    usr_creds: String,
    usr_email: String,
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
            email: self.usr_email,
            id: self.usr_id,
            role: self.usr_role,
        })
    }
}

// add_track_to_playlist

#[inline]
async fn add_track_to_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "add_track_to_playlist",
        playlist.id = %playlist_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("adding track to playlist");
        query_file!(
            "resources/main/db/pg/queries/add-track-to-playlist.sql",
            playlist_id,
            track_id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// add_track_to_source

#[inline]
async fn add_track_to_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "add_track_to_source",
        src.id = %src_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("adding track to source");
        query_file!(
            "resources/main/db/pg/queries/add-track-to-source.sql",
            src_id,
            track_id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// count_source_playlists

#[inline]
async fn count_source_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<u32> {
    let span = debug_span!(
        "count_source_playlists",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting source playlists");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-playlists.sql",
            id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let count = record.count.unwrap_or(0).try_into()?;
        Ok(count)
    }
    .instrument(span)
    .await
}

// create_playlist

#[inline]
async fn create_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &PlaylistCreation,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Playlist> {
    let span = debug_span!(
        "create_playlist",
        playlist.name = creation.name,
        playlist.src.owner.email = creation.src.owner.email,
        playlist.src.owner.id = %creation.src.owner.id,
    );
    async {
        trace!("serializing playlist predicate");
        let predicate = serde_json::to_value(&creation.predicate)?;
        trace!("serializing playlist target");
        let tgt = serde_json::to_value(&creation.tgt)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating playlist");
        let record = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/create-playlist.sql",
            creation.name,
            &predicate,
            creation.src.id,
            &tgt,
        )
        .fetch_one(&mut *conn)
        .await?;
        let playlist = record.into_entity(key)?;
        debug!(%playlist.id, "playlist created");
        Ok(playlist)
    }
    .instrument(span)
    .await
}

// create_source

#[inline]
async fn create_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &SourceCreation,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Source> {
    let span = debug_span!(
        "create_source",
        src.owner.email = creation.owner.email,
        src.owner.id = %creation.owner.id,
    );
    async {
        trace!("serializing source kind");
        let kind = serde_json::to_value(&creation.kind)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/create-source.sql",
            creation.owner.id,
            &kind,
        )
        .fetch_one(&mut *conn)
        .await?;
        let src = record.into_entity(key)?;
        debug!(%src.id, "source created");
        Ok(src)
    }
    .instrument(span)
    .await
}

// create_track

#[inline]
async fn create_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &TrackCreation,
    conn: A,
) -> PostgresResult<Track> {
    let album = creation.album.name.to_lowercase();
    let artists = creation
        .artists
        .iter()
        .map(|artist| artist.to_lowercase())
        .collect::<Vec<_>>();
    let title = creation.title.to_lowercase();
    let span = debug_span!(
        "create_track",
        track.album.name = album,
        track.artists = ?artists,
        track.title = title,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/create-track.sql",
            title,
            &artists,
            album,
            creation.album.compil,
            creation.year,
            creation.spotify_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let track = record.into_entity()?;
        debug!(%track.id, "track created");
        Ok(track)
    }
    .instrument(span)
    .await
}

// create_user

#[inline]
async fn create_user<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    creation: &UserCreation,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<User> {
    let span = debug_span!("create_user", usr.email = creation.email,);
    async {
        let creds = encrypt_credentials(&creation.creds, key)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/create-user.sql",
            &creation.email,
            &creds,
        )
        .fetch_one(&mut *conn)
        .await?;
        let usr = record.into_entity(key)?;
        debug!(%usr.id, "user created");
        Ok(usr)
    }
    .instrument(span)
    .await
}

// delete_playlist

#[inline]
async fn delete_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "delete_playlist",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting playlist");
        query_file!("resources/main/db/pg/queries/delete-playlist.sql", id,)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// delete_source

#[inline]
async fn delete_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "delete_source",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting source");
        query_file!("resources/main/db/pg/queries/delete-source.sql", id,)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// delete_tracks_from_playlist

#[inline]
async fn delete_tracks_from_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "delete_tracks_from_playlist",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting tracks");
        query_file!(
            "resources/main/db/pg/queries/delete-tracks-from-playlist.sql",
            id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// delete_tracks_from_source

#[inline]
async fn delete_tracks_from_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "delete_tracks_from_source",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting tracks");
        query_file!(
            "resources/main/db/pg/queries/delete-tracks-from-source.sql",
            id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// encrypt_credentials

#[inline]
fn encrypt_credentials(creds: &Credentials, key: &MagicCrypt256) -> PostgresResult<String> {
    trace!("serializing user credentials");
    let creds = serde_json::to_string(creds)?;
    trace!("encrypting user credentials");
    Ok(key.encrypt_str_to_base64(creds))
}

// lock_playlist_synchronization

#[inline]
async fn lock_playlist_synchronization<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<Option<PlaylistSynchronization>> {
    let span = debug_span!(
        "lock_playlist_synchronization",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("locking playlist synchronization");
        let record = query_file_as!(
            SynchronizationRecord,
            "resources/main/db/pg/queries/lock-playlist-synchronization.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let sync = record.map(|record| record.into_entity()).transpose()?;
        Ok(sync)
    }
    .instrument(span)
    .await
}

// lock_source_synchronization

#[inline]
async fn lock_source_synchronization<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<Option<SourceSynchronization>> {
    let span = debug_span!(
        "lock_source_synchronization",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("locking source synchronization");
        let record = query_file_as!(
            SynchronizationRecord,
            "resources/main/db/pg/queries/lock-source-synchronization.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let sync = record.map(|record| record.into_entity()).transpose()?;
        Ok(sync)
    }
    .instrument(span)
    .await
}

// playlist_by_id

#[inline]
async fn playlist_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Playlist>> {
    let span = debug_span!(
        "playlist_by_id",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching playlist");
        let record = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/playlist-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let playlist = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(playlist)
    }
    .instrument(span)
    .await
}

// playlist_contains_track

#[inline]
async fn playlist_contains_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = debug_span!(
        "playlist_contains_track",
        playlist.id = %playlist_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if playlist contains track");
        let record = query_file!(
            "resources/main/db/pg/queries/playlist-contains-track.sql",
            playlist_id,
            track_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let contains = record.contains.unwrap_or(false);
        Ok(contains)
    }
    .instrument(span)
    .await
}

// playlist_ids_by_source

#[inline]
async fn playlist_ids_by_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Uuid>> {
    let span = debug_span!(
        "playlist_ids_by_source",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlists");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-playlists.sql",
            src_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlist IDs");
        let records = query_file!(
            "resources/main/db/pg/queries/playlist-ids-by-source.sql",
            src_id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records.into_iter().map(|record| record.id).collect(),
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// playlist_tracks

#[inline]
async fn playlist_tracks<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = debug_span!(
        "playlist_tracks",
        params.limit = req.limit,
        params.offset = req.offset,
        playlist.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlist tracks");
        let record = query_file!("resources/main/db/pg/queries/count-playlist-tracks.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlist tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/playlist-tracks.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity())
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// playlists

#[inline]
async fn playlists<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = debug_span!(
        "playlists",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlists");
        let record = query_file!("resources/main/db/pg/queries/count-playlists.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlists");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/playlists.sql",
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// source_by_id

#[inline]
async fn source_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Source>> {
    let span = debug_span!(
        "source_by_id",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/source-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let src = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(src)
    }
    .instrument(span)
    .await
}

// source_by_owner_kind

#[inline]
async fn source_by_owner_kind<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    owner_id: Uuid,
    kind: &SourceKind,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Source>> {
    let span = debug_span!(
        "source_by_owner_kind",
        src.owner.id = %owner_id,
    );
    async {
        trace!("serializing source kind");
        let kind = serde_json::to_value(kind)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/source-by-owner-kind.sql",
            owner_id,
            &kind,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let src = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(src)
    }
    .instrument(span)
    .await
}

// source_contains_track

#[inline]
async fn source_contains_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = debug_span!(
        "source_contains_track",
        src.id = %src_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if source contains track");
        let record = query_file!(
            "resources/main/db/pg/queries/source-contains-track.sql",
            src_id,
            track_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let contains = record.contains.unwrap_or(false);
        Ok(contains)
    }
    .instrument(span)
    .await
}

// source_tracks

#[inline]
async fn source_tracks<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = debug_span!(
        "source_tracks",
        params.limit = req.limit,
        params.offset = req.offset,
        src.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting source tracks");
        let record = query_file!("resources/main/db/pg/queries/count-source-tracks.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching source tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/source-tracks.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity())
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// sources

#[inline]
async fn sources<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Source>> {
    let span = debug_span!(
        "sources",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting sources");
        let record = query_file!("resources/main/db/pg/queries/count-sources.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching sources");
        let records = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/sources.sql",
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// track_by_id

#[inline]
async fn track_by_id<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    id: Uuid,
    conn: A,
) -> PostgresResult<Option<Track>> {
    let span = debug_span!(
        "track_by_id",
        track.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/track-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let track = record.map(|record| record.into_entity()).transpose()?;
        Ok(track)
    }
    .instrument(span)
    .await
}

// track_by_title_artists_album_year

#[inline]
async fn track_by_title_artists_album_year<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    title: &str,
    artists: &BTreeSet<String>,
    album: &str,
    year: i32,
    conn: A,
) -> PostgresResult<Option<Track>> {
    let album = album.to_lowercase();
    let artists = artists
        .iter()
        .map(|artist| artist.to_lowercase())
        .collect::<Vec<_>>();
    let title = title.to_lowercase();
    let span = debug_span!(
        "track_by_title_artists_album_year",
        track.album.name = album,
        track.artists = ?artists,
        track.title = title,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/track-by-title-artists-album-year.sql",
            title,
            &artists,
            album,
            year,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let track = record.map(|record| record.into_entity()).transpose()?;
        Ok(track)
    }
    .instrument(span)
    .await
}

// tracks

#[inline]
async fn tracks<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = debug_span!(
        "tracks",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting tracks");
        let record = query_file!("resources/main/db/pg/queries/count-tracks.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/tracks.sql",
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity())
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// update_playlist

#[inline]
async fn update_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist: &Playlist,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "update_playlist",
        %playlist.id,
        playlist.name,
        playlist.src.owner.email,
        %playlist.src.owner.id,
    );
    async {
        trace!("serializing playlist synchronization");
        let sync = serde_json::to_value(&playlist.sync)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating playlist");
        query_file!(
            "resources/main/db/pg/queries/update-playlist.sql",
            playlist.id,
            sync,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// update_source

#[inline]
async fn update_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src: &Source,
    conn: A,
) -> PostgresResult<()> {
    let span: tracing::Span = debug_span!(
        "update_source",
        %src.id,
    );
    async {
        trace!("serializing source synchronization");
        let sync = serde_json::to_value(&src.sync)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating playlist");
        query_file!(
            "resources/main/db/pg/queries/update-source.sql",
            src.id,
            sync,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

#[inline]
async fn update_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    track: &Track,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "update_track",
        %track.id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating track");
        query_file!(
            "resources/main/db/pg/queries/update-track.sql",
            track.id,
            track.spotify_id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

#[inline]
async fn update_user<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    usr: &User,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<()> {
    let span = debug_span!(
        "update_user",
        %usr.id,
        %usr.email,
        %usr.role,
    );
    async {
        let creds = encrypt_credentials(&usr.creds, key)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating user");
        query_file!(
            "resources/main/db/pg/queries/update-user.sql",
            usr.id,
            usr.email,
            usr.role as _,
            creds,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// user_by_email

#[inline]
async fn user_by_email<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    email: &str,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<User>> {
    let span = debug_span!("user_by_email", usr.email = email,);
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/user-by-email.sql",
            email,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let usr = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(usr)
    }
    .instrument(span)
    .await
}

// user_by_id

#[inline]
async fn user_by_id<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<User>> {
    let span = debug_span!(
        "user_by_id",
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/user-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let usr = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(usr)
    }
    .instrument(span)
    .await
}

// user_playlists

#[inline]
async fn user_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = debug_span!(
        "user_playlists",
        params.limit = req.limit,
        params.offset = req.offset,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user playlists");
        let record = query_file!("resources/main/db/pg/queries/count-user-playlists.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user playlists");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/user-playlists.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// user_sources

#[inline]
async fn user_sources<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Source>> {
    let span = debug_span!(
        "user_sources",
        params.limit = req.limit,
        params.offset = req.offset,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user playlists");
        let record = query_file!("resources/main/db/pg/queries/count-user-sources.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user sources");
        let records = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/user-sources.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// users

#[inline]
async fn users<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<User>> {
    let span = debug_span!(
        "users",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting users");
        let record = query_file!("resources/main/db/pg/queries/count-users.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching users");
        let records = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/users.sql",
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// Tests

#[cfg(test)]
mod test {
    use std::io::stderr;

    use mockable::{DefaultEnv, MockEnv};
    use mockall::predicate::eq;

    use crate::{
        model::{
            Credentials, Predicate, SourceKind, SpotifyCredentials, SpotifyResourceKind,
            SpotifyToken, Target,
        },
        test_env_var, TracingConfig,
    };

    use super::*;

    // Data

    struct Data {
        playlists: Vec<Playlist>,
        srcs: Vec<Source>,
        tracks: Vec<Track>,
        usrs: Vec<User>,
    }

    impl Data {
        fn new() -> Self {
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
                spotify_id: None,
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
                spotify_id: None,
                title: "you never can tell".into(),
                year: 1964,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the letter/neon rainbow".into(),
                },
                artists: BTreeSet::from_iter(["the box tops".into()]),
                creation: DateTime::parse_from_rfc3339("2023-01-02T00:01:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xf747ca3a0cc74d9fb38adc506f99f5df),
                spotify_id: None,
                title: "the letter".into(),
                year: 1967,
            };
            let usr_1 = User {
                creation: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                creds: Credentials {
                    spotify: Some(SpotifyCredentials {
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
                email: "user_1@test".into(),
                id: Uuid::from_u128(0xee21186a990c42e9bcd269f9090a7736),
                role: Role::Admin,
            };
            let usr_2 = User {
                creation: DateTime::parse_from_rfc3339("2023-02-01T00:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                creds: Default::default(),
                email: "user_2@test".into(),
                id: Uuid::from_u128(0xec1ca9f93c4744a295c7a13ff6de852d),
                role: Role::User,
            };
            let usr_3 = User {
                creation: DateTime::parse_from_rfc3339("2023-03-01T00:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                creds: Default::default(),
                email: "user_3@test".into(),
                id: Uuid::from_u128(0x8fc899c5f25449669b5ae8f1c4f97f7c),
                role: Role::User,
            };
            let src_1 = Source {
                creation: DateTime::parse_from_rfc3339("2023-01-05T01:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x911ca8e748744bf4b8e11ddd1b6cee41),
                kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                owner: usr_1.clone(),
                sync: Synchronization::Pending,
            };
            let src_2 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T02:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xf1c418db13c047a79ecb9aa4cf4995eb),
                kind: SourceKind::Spotify(SpotifyResourceKind::Playlist("src_2".into())),
                owner: usr_1.clone(),
                sync: Synchronization::Pending,
            };
            let src_3 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T03:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0x12d423d13bc04eefb0c66748beb7d52e),
                kind: SourceKind::Spotify(SpotifyResourceKind::Playlist("src_3".into())),
                owner: usr_1.clone(),
                sync: Synchronization::Pending,
            };
            let src_4 = Source {
                creation: DateTime::parse_from_rfc3339("2023-02-05T04:00:00Z")
                    .expect("failed to parse date")
                    .into(),
                id: Uuid::from_u128(0xa23c9cc92b7246db9a52922f1c09db01),
                kind: SourceKind::Spotify(SpotifyResourceKind::Playlist("src_4".into())),
                owner: usr_2.clone(),
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
                        predicate: Predicate::YearEquals(1993),
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
                        predicate: Predicate::YearEquals(2013),
                        src: src_1.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_2".into()),
                    },
                    Playlist {
                        creation: DateTime::parse_from_rfc3339("2023-03-05T00:00:10Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0xa80267ba89be4350ac0d8ebecb88efa0),
                        name: "playlist_3".into(),
                        predicate: Predicate::YearEquals(1961),
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
                        predicate: Predicate::YearEquals(1999),
                        src: src_4.clone(),
                        sync: Synchronization::Pending,
                        tgt: Target::Spotify("playlist_4".into()),
                    },
                ],
                srcs: vec![src_1, src_2, src_3, src_4],
                tracks: vec![track_1, track_2, track_3],
                usrs: vec![usr_1, usr_2, usr_3],
            }
        }
    }

    impl Default for Data {
        fn default() -> Self {
            Self::new()
        }
    }

    // init

    async fn init(db: PgPool) -> PostgresPool {
        TracingConfig::new("autoplaylist-common", stderr).init(&DefaultEnv);
        let secret = test_env_var(ENV_VAR_KEY_DB_SECRET, "changeit");
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

    mod client {
        use super::*;

        // Mods

        mod add_track_to_playlist {
            use super::*;

            // run

            async fn run(track_idx: usize, db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[track_idx].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.add_track_to_playlist(playlist_id, track_id)
                    .await
                    .expect("failed to add track");
                let contains = conn
                    .playlist_contains_track(playlist_id, track_id)
                    .await
                    .expect("failed to check if playlist contains track");
                assert!(contains);
            }

            // Tests

            #[sqlx::test]
            async fn unit_when_track_was_already_added(db: PgPool) {
                run(0, db).await;
            }

            #[sqlx::test]
            async fn unit_when_track_was_added(db: PgPool) {
                run(1, db).await;
            }
        }

        mod add_track_to_source {
            use super::*;

            // run

            async fn run(track_idx: usize, db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[track_idx].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.add_track_to_source(src_id, track_id)
                    .await
                    .expect("failed to add track");
                let contains = conn
                    .source_contains_track(src_id, track_id)
                    .await
                    .expect("failed to check if playlist contains track");
                assert!(contains);
            }

            // Tests

            #[sqlx::test]
            async fn unit_when_track_was_already_added(db: PgPool) {
                run(0, db).await;
            }

            #[sqlx::test]
            async fn unit_when_track_was_added(db: PgPool) {
                run(1, db).await;
            }
        }

        mod count_source_playlists {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let count = conn
                    .count_source_playlists(src_id)
                    .await
                    .expect("failed to count source playlists");
                assert_eq!(count, 3);
            }
        }

        mod create_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn playlist(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = PlaylistCreation {
                    name: "playlist_5".into(),
                    predicate: Predicate::YearEquals(2023),
                    src: data.srcs[0].clone(),
                    tgt: Target::Spotify("playlist_5".into()),
                };
                let playlist = conn
                    .create_playlist(&creation)
                    .await
                    .expect("failed to create playlist");
                assert_eq!(playlist.name, creation.name);
                assert_eq!(playlist.predicate, creation.predicate);
                assert_eq!(playlist.src, creation.src);
                assert_eq!(playlist.tgt, creation.tgt);
                let playlist_fetched = conn
                    .playlist_by_id(playlist.id)
                    .await
                    .expect("failed to fetch playlist")
                    .expect("playlist doesn't exist");
                assert_eq!(playlist, playlist_fetched);
            }
        }

        mod create_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = SourceCreation {
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: data.usrs[1].clone(),
                };
                let src = conn
                    .create_source(&creation)
                    .await
                    .expect("failed to create source");
                assert_eq!(src.kind, creation.kind);
                assert_eq!(src.owner, creation.owner);
                let src_fetched = conn
                    .source_by_id(src.id)
                    .await
                    .expect("failed to fetch source")
                    .expect("source doesn't exist");
                assert_eq!(src, src_fetched);
            }
        }

        mod create_track {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn track(db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = TrackCreation {
                    album: Album {
                        compil: false,
                        name: "The Dark Side of the Moon".into(),
                    },
                    artists: vec!["Pink Floyd".into()].into_iter().collect(),
                    spotify_id: Some("id".into()),
                    title: "Time".into(),
                    year: 1973,
                };
                let track = conn
                    .create_track(&creation)
                    .await
                    .expect("failed to create track");
                assert_eq!(track.album.name, creation.album.name.to_lowercase());
                assert_eq!(track.album.compil, creation.album.compil);
                let artists: BTreeSet<String> = creation
                    .artists
                    .into_iter()
                    .map(|artist| artist.to_lowercase())
                    .collect();
                assert_eq!(track.artists, artists);
                assert_eq!(track.spotify_id, creation.spotify_id);
                assert_eq!(track.title, creation.title.to_lowercase());
                assert_eq!(track.year, creation.year);
                let track_fetched = conn
                    .track_by_id(track.id)
                    .await
                    .expect("failed to fetch track")
                    .expect("track doesn't exist");
                assert_eq!(track, track_fetched);
            }
        }

        mod create_user {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn user(db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = UserCreation {
                    creds: Default::default(),
                    email: "user_5@test".into(),
                };
                let usr = conn
                    .create_user(&creation)
                    .await
                    .expect("failed to create user");
                assert_eq!(usr.creds, creation.creds);
                assert_eq!(usr.email, creation.email);
                let usr_fetched = conn
                    .user_by_id(usr.id)
                    .await
                    .expect("failed to fetch user")
                    .expect("user doesn't exist");
                assert_eq!(usr, usr_fetched);
            }
        }

        mod delete_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let id = data.playlists[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.delete_playlist(id)
                    .await
                    .expect("failed to delete playlist");
                let playlist = conn
                    .playlist_by_id(id)
                    .await
                    .expect("failed to fetch playlist");
                assert!(playlist.is_none());
            }
        }

        mod delete_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let id = data.srcs[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.delete_source(id)
                    .await
                    .expect("failed to delete source");
                let src = conn.source_by_id(id).await.expect("failed to fetch source");
                assert!(src.is_none());
            }
        }

        mod delete_tracks_from_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let id = data.playlists[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.delete_tracks_from_playlist(id)
                    .await
                    .expect("failed to delete tracks");
                let page = conn
                    .playlist_tracks(id, PageRequest::new(100, 0))
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page.total, 0);
            }
        }

        mod delete_tracks_from_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let id = data.srcs[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.delete_tracks_from_source(id)
                    .await
                    .expect("failed to delete tracks");
                let page = conn
                    .source_tracks(id, PageRequest::new(100, 0))
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page.total, 0);
            }
        }

        mod lock_playlist_synchronization {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<PlaylistSynchronization>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let sync = conn
                    .lock_playlist_synchronization(id)
                    .await
                    .expect("failed to fetch playlist synchronization");
                assert_eq!(sync, expected);
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn synchronization(db: PgPool) {
                let data = Data::new();
                let id = data.playlists[0].id;
                run(id, Some(Synchronization::Pending), db).await;
            }
        }

        mod lock_source_synchronization {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<SourceSynchronization>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let sync = conn
                    .lock_source_synchronization(id)
                    .await
                    .expect("failed to fetch source synchronization");
                assert_eq!(sync, expected);
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn synchronization(db: PgPool) {
                let data = Data::new();
                let id = data.srcs[0].id;
                run(id, Some(Synchronization::Pending), db).await;
            }
        }

        mod playlist_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let playlist = conn
                    .playlist_by_id(id)
                    .await
                    .expect("failed to fetch playlist");
                assert_eq!(playlist, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn playlist(db: PgPool) {
                let data = Data::new();
                let playlist = &data.playlists[0];
                run(playlist.id, Some(playlist), db).await;
            }
        }

        mod playlist_contains_track {
            use super::*;

            // run

            async fn run(playlist_id: Uuid, track_id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let contains = conn
                    .playlist_contains_track(playlist_id, track_id)
                    .await
                    .expect("failed to check if playlist contains track");
                assert_eq!(contains, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_playlist_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[1].id;
                let track_id = data.tracks[0].id;
                run(playlist_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn false_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[1].id;
                run(playlist_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn true_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[0].id;
                run(playlist_id, track_id, true, db).await;
            }
        }

        mod playlist_ids_by_source {
            use super::*;

            // run

            async fn run(src_id: Uuid, expected: Page<Uuid>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .playlist_ids_by_source(src_id, expected.req)
                    .await
                    .expect("failed to fetch playlist IDs");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.playlists[0].id,
                        data.playlists[1].id,
                        data.playlists[2].id,
                    ],
                    last: true,
                    req: PageRequest::new(3, 0),
                    total: 3,
                };
                run(data.srcs[0].id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].id],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.srcs[0].id, expected, db).await;
            }
        }

        mod playlists {
            use super::*;

            // run

            async fn run(expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .playlists(expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.playlists.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .playlists
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .playlists
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod source_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src = conn.source_by_id(id).await.expect("failed to fetch source");
                assert_eq!(src, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.id, Some(src), db).await;
            }
        }

        mod source_by_owner_kind {
            use super::*;

            // run

            async fn run(owner_id: Uuid, kind: &SourceKind, expected: Option<&Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src = conn
                    .source_by_owner_kind(owner_id, kind)
                    .await
                    .expect("failed to fetch source");
                assert_eq!(src, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none_when_owner_doesnt_match(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.srcs[0].kind, None, db).await;
            }

            #[sqlx::test]
            async fn none_when_kind_doesnt_match(db: PgPool) {
                let data = Data::new();
                run(data.srcs[0].owner.id, &data.srcs[3].kind, None, db).await;
            }

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.owner.id, &src.kind, Some(src), db).await;
            }
        }

        mod source_contains_track {
            use super::*;

            // run

            async fn run(src_id: Uuid, track_id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let contains = conn
                    .source_contains_track(src_id, track_id)
                    .await
                    .expect("failed to check if source contains track");
                assert_eq!(contains, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_source_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[1].id;
                let track_id = data.tracks[0].id;
                run(src_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn false_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[1].id;
                run(src_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn true_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[0].id;
                run(src_id, track_id, true, db).await;
            }
        }

        mod sources {
            use super::*;

            // run

            async fn run(expected: Page<Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .sources(expected.req)
                    .await
                    .expect("failed to fetch sources");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.srcs.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .srcs
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.srcs[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .srcs
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod track_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let track = conn.track_by_id(id).await.expect("failed to fetch track");
                assert_eq!(track, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn track(db: PgPool) {
                let data = Data::new();
                let track = &data.tracks[0];
                run(track.id, Some(track), db).await;
            }
        }

        mod track_by_title_artists_album_year {
            use super::*;

            // Params

            struct Params {
                album: &'static str,
                artists: &'static [&'static str],
                title: &'static str,
                year: i32,
            }

            // run

            async fn run(params: Params, expected: Option<&Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let artists: BTreeSet<String> = params
                    .artists
                    .iter()
                    .map(|artist| (*artist).into())
                    .collect();
                let track = conn
                    .track_by_title_artists_album_year(
                        params.title,
                        &artists,
                        params.album,
                        params.year,
                    )
                    .await
                    .expect("failed to fetch track");
                assert_eq!(track, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none_when_title_mismatch(db: PgPool) {
                run(
                    Params {
                        album: "Dusty In Memphis",
                        artists: &["Dusty Springfield"],
                        title: "time",
                        year: 1969,
                    },
                    None,
                    db,
                )
                .await;
            }

            #[sqlx::test]
            async fn none_when_artists_mismatch(db: PgPool) {
                run(
                    Params {
                        album: "Dusty In Memphis",
                        artists: &["Dusty Springfield", "Pink Floyd"],
                        title: "Son Of A Preacher Man",
                        year: 1969,
                    },
                    None,
                    db,
                )
                .await;
            }

            #[sqlx::test]
            async fn none_when_album_mismatch(db: PgPool) {
                run(
                    Params {
                        album: "The Dark Side Of The Moon",
                        artists: &["Dusty Springfield"],
                        title: "Son Of A Preacher Man",
                        year: 1969,
                    },
                    None,
                    db,
                )
                .await;
            }

            #[sqlx::test]
            async fn none_when_year_mismatch(db: PgPool) {
                run(
                    Params {
                        album: "Dusty In Memphis",
                        artists: &["Dusty Springfield"],
                        title: "Son Of A Preacher Man",
                        year: 1970,
                    },
                    None,
                    db,
                )
                .await;
            }

            #[sqlx::test]
            async fn track(db: PgPool) {
                let data = Data::new();
                run(
                    Params {
                        album: "Dusty In Memphis",
                        artists: &["Dusty Springfield"],
                        title: "Son Of A Preacher Man",
                        year: 1969,
                    },
                    Some(&data.tracks[0]),
                    db,
                )
                .await;
            }
        }

        mod tracks {
            use super::*;

            // run

            async fn run(expected: Page<Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .tracks(expected.req)
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.tracks.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .tracks
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.tracks[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .tracks
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod update_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let expected = Playlist {
                    sync: Synchronization::Running,
                    ..data.playlists[0].clone()
                };
                let playlist_updated = Playlist {
                    creation: Utc::now(),
                    id: expected.id,
                    name: "playlist_2".into(),
                    predicate: Predicate::YearEquals(1983),
                    src: data.srcs[1].clone(),
                    sync: expected.sync.clone(),
                    tgt: Target::Spotify("playlist_2".into()),
                };
                conn.update_playlist(&playlist_updated)
                    .await
                    .expect("failed to update playlist");
                let playlist = conn
                    .playlist_by_id(expected.id)
                    .await
                    .expect("failed to fetch source")
                    .expect("source doesn't exist");
                assert_eq!(playlist, expected);
            }
        }

        mod update_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let expected = Source {
                    sync: Synchronization::Running,
                    ..data.srcs[0].clone()
                };
                let source_updated = Source {
                    creation: Utc::now(),
                    id: expected.id,
                    kind: SourceKind::Spotify(SpotifyResourceKind::Playlist("id".into())),
                    owner: data.usrs[1].clone(),
                    sync: expected.sync.clone(),
                };
                conn.update_source(&source_updated)
                    .await
                    .expect("failed to update source");
                let src = conn
                    .source_by_id(expected.id)
                    .await
                    .expect("failed to fetch source")
                    .expect("source doesn't exist");
                assert_eq!(src, expected);
            }
        }

        mod update_track {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let expected = Track {
                    spotify_id: Some("id".into()),
                    ..data.tracks[0].clone()
                };
                let track_updated = Track {
                    album: Album {
                        compil: false,
                        name: "The Dark Side of the Moon".into(),
                    },
                    artists: BTreeSet::from_iter(["Pink Floyd".into()]),
                    creation: Utc::now(),
                    id: expected.id,
                    spotify_id: expected.spotify_id.clone(),
                    title: "Time".into(),
                    year: 1973,
                };
                conn.update_track(&track_updated)
                    .await
                    .expect("failed to update track");
                let track = conn
                    .track_by_id(expected.id)
                    .await
                    .expect("failed to fetch track")
                    .expect("track doesn't exist");
                assert_eq!(track, expected);
            }
        }

        mod update_user {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let expected = User {
                    email: "user_1_1@test".into(),
                    creds: Default::default(),
                    role: Role::User,
                    ..data.usrs[0].clone()
                };
                let usr_updated = User {
                    creation: Utc::now(),
                    id: expected.id,
                    ..expected.clone()
                };
                conn.update_user(&usr_updated)
                    .await
                    .expect("failed to update user");
                let usr = conn
                    .user_by_id(expected.id)
                    .await
                    .expect("failed to fetch user")
                    .expect("user doesn't exist");
                assert_eq!(usr, expected);
            }
        }

        mod user_by_email {
            use super::*;

            // run

            async fn run(email: &str, expected: Option<&User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let usr = conn
                    .user_by_email(email)
                    .await
                    .expect("failed to fetch user");
                assert_eq!(usr, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run("user_0@test", None, db).await;
            }

            #[sqlx::test]
            async fn user(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                run(&data.usrs[0].email, Some(usr), db).await;
            }
        }

        mod user_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let usr = conn.user_by_id(id).await.expect("failed to fetch user");
                assert_eq!(usr, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn user(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                run(usr.id, Some(usr), db).await;
            }
        }

        mod user_playlists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .user_playlists(id, expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.playlists[0].clone(),
                        data.playlists[1].clone(),
                        data.playlists[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(data.usrs[0].id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.usrs[0].id, expected, db).await;
            }
        }

        mod user_sources {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Page<Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .user_sources(id, expected.req)
                    .await
                    .expect("failed to fetch sources");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.srcs[0].clone(),
                        data.srcs[1].clone(),
                        data.srcs[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(data.usrs[0].id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.srcs[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.usrs[0].id, expected, db).await;
            }
        }

        mod users {
            use super::*;

            // run

            async fn run(expected: Page<User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .users(expected.req)
                    .await
                    .expect("failed to fetch users");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.usrs.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .tracks
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.usrs[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .tracks
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }
    }
}
