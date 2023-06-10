use std::{
    error::Error as StdError,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    num::TryFromIntError,
    ops::DerefMut,
    result::Result as StdResult,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{
    tokio_postgres::{Client as TokioPostgresClient, Error as TokioPosgresError, NoTls, Row},
    Config as DeadpoolConfig, CreatePoolError, Object, Pool as DeadpoolPool, PoolError,
    Transaction as TokioPostgresTransaction,
};
use postgres_types::{FromSql, ToSql};
use refinery::{embed_migrations, Error as RefineryError};
use serde_json::json;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::domain::{
    Artist, Base, BaseKind, Platform, Playlist, PlaylistFilter, Role, SpotifyAuth, SpotifyToken,
    Sync, SyncState, Track, User,
};

use super::{
    ArtistRepository, BaseRepository, Client, Config, Page, PlaylistRepository, Pool, Repositories,
    Result, TrackRepository, Transaction, UserRepository,
};

// Macros

macro_rules! sql {
    ($name:literal) => {
        include_str!(concat!("../../db/postgres/queries/", $name, ".sql"))
    };
}

// Error

#[derive(Debug)]
pub enum Error {
    Client(TokioPosgresError),
    IntConversion(TryFromIntError),
    MissingPlatformId,
    Pool(PoolError),
}

impl Error {
    fn client_boxed(err: TokioPosgresError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::Client(err))
    }

    fn int_conversion_boxed(err: TryFromIntError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::IntConversion(err))
    }

    fn missing_platform_id_boxed() -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::MissingPlatformId)
    }

    fn pool_boxed(err: PoolError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::Pool(err))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Client(err) => write!(f, "database client failed: {err}"),
            Self::MissingPlatformId => {
                write!(f, "incoherent data in database: missing platform ID")
            }
            Self::Pool(err) => write!(f, "getting database connection from pool failed: {err}"),
            Self::IntConversion(err) => {
                write!(f, "conversion of numeric type failed: {err}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Client(err) => Some(err),
            Self::MissingPlatformId => None,
            Self::Pool(err) => Some(err),
            Self::IntConversion(err) => Some(err),
        }
    }
}

// InitializationError

#[derive(Debug)]
pub enum InitializationError {
    Migrations(Box<RefineryError>),
    PoolCreation(CreatePoolError),
    Pool(PoolError),
}

impl Display for InitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Migrations(err) => write!(f, "database migrations failed: {err}"),
            Self::PoolCreation(err) => {
                write!(f, "database connection pool creation failed: {err}")
            }
            Self::Pool(err) => write!(f, "database connection pool failed: {err}"),
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

// Extractor

trait Extractor<T>: Send + StdSync {
    fn extract_from_row(&self, row: &Row) -> Result<T>;
}

// ArtistExtractor

struct ArtistExtractor(&'static str);

impl Default for ArtistExtractor {
    fn default() -> Self {
        Self("artist")
    }
}

impl Extractor<Artist> for ArtistExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<Artist> {
        Ok(Artist {
            id: try_get(self.0, "id", row)?,
            name: try_get(self.0, "name", row)?,
            spotify_id: try_get(self.0, "spotify_id", row)?,
        })
    }
}

// BaseExtractor

struct BaseExtractor {
    alias_prefix: &'static str,
    sync_extractor: SyncExtractor,
    user_extractor: UserExtractor,
}

impl Default for BaseExtractor {
    fn default() -> Self {
        Self {
            alias_prefix: "base",
            sync_extractor: SyncExtractor("base"),
            user_extractor: UserExtractor("base_user"),
        }
    }
}

impl Extractor<Base> for BaseExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<Base> {
        let platform: PlatformSql = try_get(self.alias_prefix, "platform", row)?;
        let platform_id: Option<String> = try_get(self.alias_prefix, "platform_id", row)?;
        let kind: BaseKindSql = try_get(self.alias_prefix, "kind", row)?;
        let kind = match kind {
            BaseKindSql::Likes => BaseKind::Likes,
            BaseKindSql::Playlist => {
                let platform_id = platform_id.ok_or_else(Error::missing_platform_id_boxed)?;
                BaseKind::Playlist(platform_id)
            }
        };
        Ok(Base {
            creation_date: try_get(self.alias_prefix, "creation_date", row)?,
            id: try_get(self.alias_prefix, "id", row)?,
            kind,
            platform: platform.into(),
            sync: self.sync_extractor.extract_from_row_opt(row)?,
            user: self.user_extractor.extract_from_row(row)?,
        })
    }
}

// PlaylistExtractor

struct PlaylistExtractor(&'static str);

impl Default for PlaylistExtractor {
    fn default() -> Self {
        Self("playlist")
    }
}

impl Extractor<Playlist> for PlaylistExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<Playlist> {
        Ok(Playlist {
            base_id: try_get(self.0, "base_id", row)?,
            creation_date: try_get(self.0, "creation_date", row)?,
            id: try_get(self.0, "id", row)?,
            name: try_get(self.0, "name", row)?,
            user_id: try_get(self.0, "user_id", row)?,
        })
    }
}

// SpotifyAuthExtractor

struct SpotifyAuthExtractor(&'static str);

impl Default for SpotifyAuthExtractor {
    fn default() -> Self {
        Self("auth")
    }
}

impl Extractor<SpotifyAuth> for SpotifyAuthExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<SpotifyAuth> {
        Ok(SpotifyAuth {
            email: try_get(self.0, "email", row)?,
            token: SpotifyToken {
                access_token: try_get(self.0, "access_token", row)?,
                expiration_date: try_get(self.0, "expiration_date", row)?,
                refresh_token: try_get(self.0, "refresh_token", row)?,
            },
            user_id: try_get(self.0, "user_id", row)?,
        })
    }
}

// SyncExtractor

struct SyncExtractor(&'static str);

impl SyncExtractor {
    #[inline]
    fn extract_from_row(&self, state: SyncStateSql, row: &Row) -> Result<Sync> {
        Ok(Sync {
            last_err_msg: try_get(self.0, "last_sync_err_msg", row)?,
            last_id: try_get(self.0, "last_sync_id", row)?,
            last_offset: try_get_int::<i64, u32>(self.0, "last_sync_offset", row)?,
            last_start_date: try_get(self.0, "last_sync_start_date", row)?,
            last_success_date: try_get(self.0, "last_sync_success_date", row)?,
            last_total: try_get_int::<i64, u32>(self.0, "last_sync_total", row)?,
            state: state.into(),
        })
    }

    fn extract_from_row_opt(&self, row: &Row) -> Result<Option<Sync>> {
        let state: Option<SyncStateSql> = try_get(self.0, "sync_state", row)?;
        match state {
            Some(state) => Ok(Some(self.extract_from_row(state, row)?)),
            None => Ok(None),
        }
    }
}

impl Extractor<Sync> for SyncExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<Sync> {
        let state: SyncStateSql = try_get(self.0, "sync_state", row)?;
        self.extract_from_row(state, row)
    }
}

// TrackExtractor

struct TrackExtractor(&'static str);

impl Default for TrackExtractor {
    fn default() -> Self {
        Self("track")
    }
}

impl Extractor<Track> for TrackExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<Track> {
        Ok(Track {
            from_compilation: try_get(self.0, "from_compilation", row)?,
            id: try_get(self.0, "id", row)?,
            name: try_get(self.0, "name", row)?,
            release_year: try_get_int::<i32, u16>(self.0, "release_year", row)?,
            spotify_id: try_get(self.0, "spotify_id", row)?,
        })
    }
}

// UserExtractor

struct UserExtractor(&'static str);

impl Default for UserExtractor {
    fn default() -> Self {
        Self("user")
    }
}

impl Extractor<User> for UserExtractor {
    fn extract_from_row(&self, row: &Row) -> Result<User> {
        let role: RoleSql = try_get(self.0, "role", row)?;
        Ok(User {
            creation_date: try_get(self.0, "creation_date", row)?,
            id: try_get(self.0, "id", row)?,
            role: role.into(),
        })
    }
}

// BaseKindSql

#[derive(Clone, Debug, FromSql, ToSql)]
#[postgres(name = "base_kind")]
enum BaseKindSql {
    #[postgres(name = "likes")]
    Likes,
    #[postgres(name = "playlist")]
    Playlist,
}

impl BaseKindSql {
    fn from_base_kind(kind: &BaseKind) -> (Self, Option<&String>) {
        match kind {
            BaseKind::Likes => (Self::Likes, None),
            BaseKind::Playlist(platform_id) => (Self::Playlist, Some(platform_id)),
        }
    }
}

// Platform

impl From<PlatformSql> for Platform {
    fn from(platform: PlatformSql) -> Self {
        match platform {
            PlatformSql::Spotify => Platform::Spotify,
        }
    }
}

// PlatformSql

#[derive(Clone, Debug, FromSql, ToSql)]
#[postgres(name = "platform")]
enum PlatformSql {
    #[postgres(name = "spotify")]
    Spotify,
}

impl From<Platform> for PlatformSql {
    fn from(platform: Platform) -> Self {
        match platform {
            Platform::Spotify => PlatformSql::Spotify,
        }
    }
}

// Role

impl From<RoleSql> for Role {
    fn from(role: RoleSql) -> Self {
        match role {
            RoleSql::Admin => Self::Admin,
            RoleSql::User => Self::User,
        }
    }
}

// RoleSql

#[derive(Clone, Debug, FromSql, ToSql)]
#[postgres(name = "role")]
pub enum RoleSql {
    #[postgres(name = "admin")]
    Admin,
    #[postgres(name = "user")]
    User,
}

impl From<Role> for RoleSql {
    fn from(role: Role) -> Self {
        match role {
            Role::Admin => Self::Admin,
            Role::User => Self::User,
        }
    }
}

// SyncState

impl From<SyncStateSql> for SyncState {
    fn from(state: SyncStateSql) -> Self {
        match state {
            SyncStateSql::Aborted => Self::Aborted,
            SyncStateSql::Failed => Self::Failed,
            SyncStateSql::Running => Self::Running,
            SyncStateSql::Succeeded => Self::Succeeded,
        }
    }
}

// SyncStateSql

#[derive(Clone, Debug, FromSql, ToSql)]
#[postgres(name = "sync_state")]
enum SyncStateSql {
    #[postgres(name = "aborted")]
    Aborted,
    #[postgres(name = "failed")]
    Failed,
    #[postgres(name = "running")]
    Running,
    #[postgres(name = "succeeded")]
    Succeeded,
}

impl From<SyncState> for SyncStateSql {
    fn from(state: SyncState) -> Self {
        match state {
            SyncState::Aborted => Self::Aborted,
            SyncState::Failed => Self::Failed,
            SyncState::Running => Self::Running,
            SyncState::Succeeded => Self::Succeeded,
        }
    }
}

// PostgresClient

pub struct PostgresClient(Object);

impl PostgresClient {
    fn new_boxed(client: Object) -> Box<dyn Client> {
        Box::new(Self(client))
    }
}

#[async_trait]
impl Client for PostgresClient {
    fn repositories(&self) -> Box<dyn Repositories + '_> {
        PostgresRepositories::new_boxed(&self.0)
    }

    async fn transaction(&mut self) -> Result<Box<dyn Transaction + '_>> {
        debug!("opening database transaction");
        self.0
            .transaction()
            .await
            .map(PostgresTransaction::new_boxed)
            .map_err(Error::client_boxed)
    }
}

// PostgresRepositories

pub struct PostgresRepositories<'a>(&'a TokioPostgresClient);

impl<'a> PostgresRepositories<'a> {
    fn new_boxed(client: &'a TokioPostgresClient) -> Box<dyn Repositories + '_> {
        Box::new(Self(client))
    }
}

impl Repositories for PostgresRepositories<'_> {
    fn artist(&self) -> Box<dyn ArtistRepository + '_> {
        Box::new(PostgresArtistRepository(self.0))
    }

    fn base(&self) -> Box<dyn BaseRepository + '_> {
        Box::new(PostgresBaseRepository(self.0))
    }

    fn playlist(&self) -> Box<dyn PlaylistRepository + '_> {
        Box::new(PostgresPlaylistRepository(self.0))
    }

    fn track(&self) -> Box<dyn TrackRepository + '_> {
        Box::new(PostgresTrackRepository(self.0))
    }

    fn user(&self) -> Box<dyn UserRepository + '_> {
        Box::new(PostgresUserRepository(self.0))
    }
}

// PostgresTransaction

pub struct PostgresTransaction<'a>(TokioPostgresTransaction<'a>);

impl<'a> PostgresTransaction<'a> {
    fn new_boxed(tx: TokioPostgresTransaction<'a>) -> Box<dyn Transaction + '_> {
        Box::new(Self(tx))
    }
}

#[async_trait]
impl Transaction for PostgresTransaction<'_> {
    async fn commit(self: Box<Self>) -> Result<()>
    where
        Self: Sized,
    {
        debug!("committing database transaction");
        self.0
            .commit()
            .await
            .map_err(|err| Box::new(err) as Box<dyn StdError + Send + StdSync>)
    }

    fn repositories(&self) -> Box<dyn Repositories + '_> {
        Box::new(PostgresRepositories(self.0.client()))
    }

    async fn rollback(self: Box<Self>) -> Result<()>
    where
        Self: Sized,
    {
        debug!("rollbacking database transaction");
        self.0
            .rollback()
            .await
            .map_err(|err| Box::new(err) as Box<dyn StdError + Send + StdSync>)
    }
}

// PostgresBaseRepository

pub struct PostgresBaseRepository<'a>(&'a TokioPostgresClient);

#[async_trait]
impl BaseRepository for PostgresBaseRepository<'_> {
    async fn delete_track_by_id_sync_not(&self, id: &Uuid, sync_id: &Uuid) -> Result<()> {
        debug!("deleting tracks from base that their sync ID is not {sync_id}");
        self.0
            .execute(sql!("base/delete-tracks-by-id-sync-id-not"), &[id, sync_id])
            .await
            .map_err(Box::new)?;
        Ok(())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Base>> {
        debug!("fetching base {id} from database");
        let extractor = BaseExtractor::default();
        let base = query_opt(sql!("base/get-by-id"), &[id], &extractor, self.0).await?;
        debug!("base fetched: {base:?}");
        Ok(base)
    }

    async fn get_by_user_kind_platform(
        &self,
        user_id: &Uuid,
        kind: &BaseKind,
        platform: Platform,
    ) -> Result<Option<Base>> {
        debug!("fetching base from database owned by user {user_id} with {kind:?} on {platform}");
        let extractor = BaseExtractor::default();
        let (kind, platform_id) = BaseKindSql::from_base_kind(kind);
        let platform: PlatformSql = platform.into();
        let base = query_opt(
            sql!("base/get-by-user-kind-platform"),
            &[user_id, &platform, &kind, &platform_id],
            &extractor,
            self.0,
        )
        .await?;
        debug!("base fetched: {base:?}");
        Ok(base)
    }

    async fn insert(&self, base: &Base) -> Result<()> {
        debug!("inserting {base:?} into database");
        let platform: PlatformSql = base.platform.into();
        let (kind, platform_id) = BaseKindSql::from_base_kind(&base.kind);
        self.0
            .execute(
                sql!("base/insert"),
                &[
                    &base.id,
                    &base.creation_date,
                    &base.user.id,
                    &platform,
                    &kind,
                    &platform_id,
                ],
            )
            .await
            .map_err(Box::new)?;
        Ok(())
    }

    async fn list(&self, limit: u32, offset: u32) -> Result<Page<Base>> {
        debug!("counting total of bases");
        let total = count(sql!("base/count"), &[], self.0).await?;
        debug!("listing bases from offset {offset} limiting to {limit} results");
        let limit_i64: i64 = limit.into();
        let offset_i64: i64 = offset.into();
        let extractor = BaseExtractor::default();
        let items = query(
            sql!("base/list"),
            &[&limit_i64, &offset_i64],
            &extractor,
            self.0,
        )
        .await?;
        let page = Page {
            is_last: offset + limit >= total,
            items,
            total,
        };
        debug!("page fetched: {page:?}");
        Ok(page)
    }

    async fn lock_sync(
        &self,
        id: &Uuid,
        sync_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<Sync>> {
        debug!("locking sync of base {id}");
        let extractor = SyncExtractor("base");
        let sync = query_opt(
            sql!("base/lock-sync"),
            &[id, &sync_id, &now],
            &extractor,
            self.0,
        )
        .await?;
        debug!("base sync fetched: {sync:?}");
        Ok(sync)
    }

    async fn update_sync(&self, id: &Uuid, sync: &Sync) -> Result<()> {
        debug!("updating sync of base {id} with {sync:?}");
        let state: SyncStateSql = sync.state.into();
        let last_offset: i64 = sync.last_offset.into();
        let last_total: i64 = sync.last_total.into();
        self.0
            .execute(
                sql!("base/update-sync"),
                &[
                    &id,
                    &state,
                    &sync.last_id,
                    &sync.last_start_date,
                    &sync.last_success_date,
                    &sync.last_err_msg,
                    &last_offset,
                    &last_total,
                ],
            )
            .await
            .map_err(Error::client_boxed)?;
        Ok(())
    }

    async fn upsert_track(&self, id: &Uuid, track_id: &Uuid, sync_id: &Uuid) -> Result<()> {
        debug!("upserting tack {track_id} into base {id}");
        self.0
            .execute(sql!("base/upsert-track"), &[id, track_id, sync_id])
            .await
            .map_err(Error::client_boxed)?;
        Ok(())
    }
}

// PostgresPlaylistRepository

pub struct PostgresPlaylistRepository<'a>(&'a TokioPostgresClient);

#[async_trait]
impl PlaylistRepository for PostgresPlaylistRepository<'_> {
    async fn delete(&self, id: &Uuid) -> Result<()> {
        debug!("deleting playlist {id} from database");
        self.0
            .execute(sql!("playlist/delete"), &[id])
            .await
            .map_err(Error::client_boxed)?;
        Ok(())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Playlist>> {
        debug!("fetching playlist {id} from database");
        let extractor = PlaylistExtractor::default();
        let playlist = query_opt(sql!("playlist/get-by-id"), &[id], &extractor, self.0).await?;
        debug!("playlist fetched: {playlist:?}");
        Ok(playlist)
    }

    async fn get_by_user_name(&self, user_id: &Uuid, name: &str) -> Result<Option<Playlist>> {
        debug!("fetching playlist from database owned by user {user_id} named `{name}`");
        let extractor = PlaylistExtractor::default();
        let playlist = query_opt(
            sql!("playlist/get-by-user-name"),
            &[user_id, &name],
            &extractor,
            self.0,
        )
        .await?;
        debug!("playlist fetched: {playlist:?}");
        Ok(playlist)
    }

    async fn insert(&self, playlist: &Playlist, filters: &[PlaylistFilter]) -> Result<()> {
        debug!("inserting {playlist:?} with {filters:?} into database");
        self.0
            .execute(
                sql!("playlist/insert"),
                &[
                    &playlist.id,
                    &playlist.creation_date,
                    &playlist.user_id,
                    &playlist.base_id,
                    &playlist.name,
                ],
            )
            .await
            .map_err(Box::new)?;
        let st = self
            .0
            .prepare(sql!("playlist/insert-filter"))
            .await
            .map_err(Box::new)?;
        for filter in filters {
            trace!("inserting {filter:?} into database");
            self.0
                .execute(&st, &[&playlist.id, &json!(filter)])
                .await
                .map_err(Box::new)?;
        }
        Ok(())
    }

    async fn list_by_user(
        &self,
        user_id: &Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Page<Playlist>> {
        debug!("counting total of playlists owned by user {user_id}");
        let total = count(sql!("playlist/count-by-user"), &[user_id], self.0).await?;
        debug!("listing playlists owned by user {user_id} from offset {offset} limiting to {limit} results");
        let limit_i64: i64 = limit.into();
        let offset_i64: i64 = offset.into();
        let extractor = PlaylistExtractor::default();
        let items = query(
            sql!("playlist/list-by-user"),
            &[user_id, &limit_i64, &offset_i64],
            &extractor,
            self.0,
        )
        .await?;
        let page = Page {
            is_last: offset + limit >= total,
            items,
            total,
        };
        debug!("page fetched: {page:?}");
        Ok(page)
    }
}

// PostgresUserRepository

pub struct PostgresUserRepository<'a>(&'a TokioPostgresClient);

#[async_trait]
impl UserRepository for PostgresUserRepository<'_> {
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<User>> {
        debug!("fetching user {id} from database");
        let extractor = UserExtractor::default();
        let user = query_opt(sql!("user/get-by-id"), &[id], &extractor, self.0).await?;
        debug!("user fetched: {user:?}");
        Ok(user)
    }

    async fn get_by_spotify_email(&self, email: &str) -> Result<Option<User>> {
        debug!("fetching user from database with Spotify email `{email}`");
        let extractor = UserExtractor::default();
        let user = query_opt(
            sql!("user/get-by-spotify-email"),
            &[&email],
            &extractor,
            self.0,
        )
        .await?;
        debug!("user fetched: {user:?}");
        Ok(user)
    }

    async fn get_spotify_auth_by_id(&self, id: &Uuid) -> Result<Option<SpotifyAuth>> {
        debug!("fetching Spotify auth of user {id} from database");
        let extractor = SpotifyAuthExtractor::default();
        let auth = query_opt(
            sql!("user/get-spotify-auth-by-id"),
            &[id],
            &extractor,
            self.0,
        )
        .await?;
        debug!("Spotify auth fetched: {auth:?}");
        Ok(auth)
    }

    async fn insert(&self, user: &User) -> Result<()> {
        debug!("inserting {user:?} into database");
        let role: RoleSql = user.role.into();
        self.0
            .execute(sql!("user/insert"), &[&user.id, &user.creation_date, &role])
            .await
            .map_err(Box::new)?;
        Ok(())
    }

    async fn upsert_spotify_auth(&self, auth: &SpotifyAuth) -> Result<()> {
        debug!("upserting {auth:?} into database");
        self.0
            .query(
                sql!("user/upsert-spotify-auth"),
                &[
                    &auth.user_id,
                    &auth.email,
                    &auth.token.access_token,
                    &auth.token.expiration_date,
                    &auth.token.refresh_token,
                ],
            )
            .await
            .map_err(Box::new)?;
        Ok(())
    }
}

// PostgresArtistRepository

pub struct PostgresArtistRepository<'a>(&'a TokioPostgresClient);

#[async_trait]
impl ArtistRepository for PostgresArtistRepository<'_> {
    async fn get_by_spotify_id(&self, id: &str) -> Result<Option<Artist>> {
        debug!("fetching artyist from database with Spotify ID {id}");
        let extractor = ArtistExtractor::default();
        let track = query_opt(sql!("artist/get-by-spotify-id"), &[&id], &extractor, self.0).await?;
        debug!("artist fetched: {track:?}");
        Ok(track)
    }

    async fn insert(&self, artist: &Artist) -> Result<()> {
        debug!("inserting {artist:?} into database");
        self.0
            .execute(
                sql!("artist/insert"),
                &[&artist.id, &artist.name, &artist.spotify_id],
            )
            .await
            .map_err(Box::new)?;
        Ok(())
    }
}

// PostgresTrackRepository

pub struct PostgresTrackRepository<'a>(&'a TokioPostgresClient);

#[async_trait]
impl TrackRepository for PostgresTrackRepository<'_> {
    async fn get_by_spotify_id(&self, id: &str) -> Result<Option<Track>> {
        debug!("fetching track from database with Spotify ID {id}");
        let extractor = TrackExtractor::default();
        let track = query_opt(sql!("track/get-by-spotify-id"), &[&id], &extractor, self.0).await?;
        debug!("track fetched: {track:?}");
        Ok(track)
    }

    async fn insert(&self, track: &Track, artist_ids: &[Uuid]) -> Result<()> {
        debug!("inserting {track:?} with artists {artist_ids:?} into database");
        let release_year: i32 = track.release_year.into();
        self.0
            .execute(
                sql!("track/insert"),
                &[
                    &track.id,
                    &track.name,
                    &release_year,
                    &track.from_compilation,
                    &track.spotify_id,
                ],
            )
            .await
            .map_err(Box::new)?;
        let st = self
            .0
            .prepare(sql!("track/insert-artist"))
            .await
            .map_err(Box::new)?;
        for id in artist_ids {
            trace!("linking artist {id:?} to track {} into database", track.id);
            self.0
                .execute(&st, &[&track.id, id])
                .await
                .map_err(Box::new)?;
        }
        Ok(())
    }
}

// PostgresPool

pub struct PostgresPool(DeadpoolPool);

impl PostgresPool {
    pub async fn init(cfg: Config) -> StdResult<Self, InitializationError> {
        let cfg: DeadpoolConfig = cfg.into();
        trace!("creating database connection pool");
        let pool = cfg
            .create_pool(None, NoTls)
            .map_err(InitializationError::PoolCreation)?;
        let mut client = Self::client(&pool)
            .await
            .map_err(InitializationError::Pool)?;
        info!("running database migrations");
        migrations::runner()
            .run_async(client.deref_mut().deref_mut())
            .await
            .map_err(|err| InitializationError::Migrations(Box::new(err)))?;
        Ok(PostgresPool(pool))
    }

    #[inline]
    async fn client(pool: &DeadpoolPool) -> StdResult<Object, PoolError> {
        trace!("getting database connection from pool");
        pool.get().await
    }
}

#[async_trait]
impl Pool for PostgresPool {
    async fn client(&self) -> Result<Box<dyn Client>> {
        Self::client(&self.0)
            .await
            .map(PostgresClient::new_boxed)
            .map_err(Error::pool_boxed)
    }
}

// DeadpoolConfig

impl From<Config> for DeadpoolConfig {
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

// count

#[inline]
async fn count(
    sql: &str,
    params: &[&(dyn ToSql + StdSync)],
    client: &TokioPostgresClient,
) -> Result<u32> {
    trace!("executing `{sql}`");
    let row = client
        .query_one(sql, params)
        .await
        .map_err(Error::client_boxed)?;
    trace!("row fetched: {row:?}");
    let total: i64 = row.try_get(0).map_err(Error::client_boxed)?;
    total.try_into().map_err(Error::int_conversion_boxed)
}

// query

#[inline]
async fn query<T>(
    sql: &str,
    params: &[&(dyn ToSql + StdSync)],
    extractor: &dyn Extractor<T>,
    client: &TokioPostgresClient,
) -> Result<Vec<T>> {
    trace!("executing `{sql}`");
    let rows = client
        .query(sql, params)
        .await
        .map_err(Error::client_boxed)?;
    trace!("rows fetched: {rows:?}");
    rows.iter()
        .map(|row| extractor.extract_from_row(row))
        .collect()
}

// query_opt

#[inline]
async fn query_opt<T>(
    sql: &str,
    params: &[&(dyn ToSql + StdSync)],
    extractor: &dyn Extractor<T>,
    client: &TokioPostgresClient,
) -> Result<Option<T>> {
    trace!("executing `{sql}`");
    let row = client
        .query_opt(sql, params)
        .await
        .map_err(Error::client_boxed)?;
    trace!("row fetched: {row:?}");
    row.map(|row| extractor.extract_from_row(&row)).transpose()
}

// try_get

#[inline]
fn try_get<'a, T: FromSql<'a>>(alias_prefix: &str, key: &str, row: &'a Row) -> Result<T> {
    row.try_get(format!("{alias_prefix}_{key}").as_str())
        .map_err(Error::client_boxed)
}

// try_get_int

#[inline]
fn try_get_int<'a, S: FromSql<'a>, T: TryFrom<S, Error = TryFromIntError>>(
    alias_prefix: &str,
    key: &str,
    row: &'a Row,
) -> Result<T> {
    try_get::<S>(alias_prefix, key, row)
        .and_then(|val| val.try_into().map_err(Error::int_conversion_boxed))
}

// Mods

embed_migrations!("db/postgres/migrations");
