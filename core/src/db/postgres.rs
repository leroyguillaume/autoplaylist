use std::{
    borrow::Cow,
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
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::domain::{
    Base, BaseKind, Platform, Playlist, PlaylistFilter, PlaylistFilterOperator, Role, SpotifyAuth,
    Sync, SyncState, User,
};

use super::{
    BaseRepository, Client, Config, Page, PlaylistRepository, Pool, Repositories, Result,
    Transaction, UserRepository,
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
    MissingPlatformId,
    Pool(PoolError),
    TotalConversion(TryFromIntError),
}

impl Error {
    fn client_boxed(err: TokioPosgresError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::Client(err))
    }

    fn missing_platform_id_boxed() -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::MissingPlatformId)
    }

    fn pool_boxed(err: PoolError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::Pool(err))
    }

    fn total_conversion_boxed(err: TryFromIntError) -> Box<dyn StdError + Send + StdSync> {
        Box::new(Error::TotalConversion(err))
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
            Self::TotalConversion(err) => {
                write!(f, "conversion of total into unsigned number failed: {err}")
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
            Self::TotalConversion(err) => Some(err),
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

// Base

impl TryFrom<BaseSql<'_>> for Base {
    type Error = Box<dyn StdError + Send + StdSync>;

    fn try_from(base: BaseSql<'_>) -> Result<Self> {
        trace!("converting {base:?} into base");
        let kind = match base.kind {
            BaseKindSql::Likes => BaseKind::Likes,
            BaseKindSql::Playlist => {
                let platform_id = base
                    .platform_id
                    .ok_or_else(Error::missing_platform_id_boxed)?;
                BaseKind::Playlist(platform_id.into_owned())
            }
        };
        Ok(Self {
            creation_date: base.creation_date.into_owned(),
            id: base.id.into_owned(),
            kind,
            platform: base.platform.into(),
            sync: base.sync.map(Sync::try_from).transpose()?,
            user_id: base.user_id.into_owned(),
        })
    }
}

// BaseSql

#[derive(Clone, Debug)]
struct BaseSql<'a> {
    creation_date: Cow<'a, DateTime<Utc>>,
    id: Cow<'a, Uuid>,
    kind: BaseKindSql,
    platform: PlatformSql,
    platform_id: Option<Cow<'a, String>>,
    sync: Option<SyncSql<'a>>,
    user_id: Cow<'a, Uuid>,
}

impl<'a> BaseSql<'a> {
    fn from_base(base: &'a Base) -> Self {
        let (kind, platform_id) = BaseKindSql::from_base_kind(&base.kind);
        Self {
            creation_date: Cow::Borrowed(&base.creation_date),
            id: Cow::Borrowed(&base.id),
            kind,
            platform: base.platform.into(),
            platform_id: platform_id.map(Cow::Borrowed),
            sync: base.sync.as_ref().map(SyncSql::from_sync),
            user_id: Cow::Borrowed(&base.user_id),
        }
    }

    fn try_from_row(alias: &str, row: &'a Row) -> Result<Self> {
        trace!("extracting base from {row:?}");
        Ok(Self {
            creation_date: try_get_cowed(alias, "creation_date", row)?,
            id: try_get_cowed(alias, "id", row)?,
            kind: try_get(alias, "kind", row)?,
            platform: try_get(alias, "platform", row)?,
            platform_id: try_get_opt_cowed(alias, "platform_id", row)?,
            sync: SyncSql::try_from_row(alias, row)?,
            user_id: try_get_cowed(alias, "user_id", row)?,
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

// Playlist

impl TryFrom<PlaylistSql<'_>> for Playlist {
    type Error = Box<dyn StdError + Send + StdSync>;

    fn try_from(playlist: PlaylistSql) -> Result<Self> {
        trace!("converting {playlist:?} into playlist");
        Ok(Self {
            base_id: playlist.base_id.into_owned(),
            creation_date: playlist.creation_date.into_owned(),
            id: playlist.id.into_owned(),
            name: playlist.name.into_owned(),
            user_id: playlist.user_id.into_owned(),
        })
    }
}

// PlaylistSql

#[derive(Clone, Debug)]
struct PlaylistSql<'a> {
    base_id: Cow<'a, Uuid>,
    creation_date: Cow<'a, DateTime<Utc>>,
    id: Cow<'a, Uuid>,
    name: Cow<'a, String>,
    user_id: Cow<'a, Uuid>,
}

impl<'a> PlaylistSql<'a> {
    fn from_playlist(playlist: &'a Playlist) -> Self {
        Self {
            base_id: Cow::Borrowed(&playlist.base_id),
            creation_date: Cow::Borrowed(&playlist.creation_date),
            id: Cow::Borrowed(&playlist.id),
            name: Cow::Borrowed(&playlist.name),
            user_id: Cow::Borrowed(&playlist.user_id),
        }
    }

    fn try_from_row(alias: &str, row: &'a Row) -> Result<Self> {
        trace!("extracting playlist from {row:?}");
        Ok(Self {
            base_id: try_get_cowed(alias, "base_id", row)?,
            creation_date: try_get_cowed(alias, "creation_date", row)?,
            id: try_get_cowed(alias, "id", row)?,
            name: try_get_cowed(alias, "name", row)?,
            user_id: try_get_cowed(alias, "user_id", row)?,
        })
    }
}

// PlaylistFilterSql

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilterSql<'a> {
    Artist(PlaylistFilterOperatorSql<'a>),
}

impl<'a> PlaylistFilterSql<'a> {
    fn from_filter(filter: &'a PlaylistFilter) -> Self {
        match filter {
            PlaylistFilter::Artist(op) => {
                Self::Artist(PlaylistFilterOperatorSql::from_operator(op))
            }
        }
    }
}

// PlaylsitFilterOperatorSql

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilterOperatorSql<'a> {
    Is(Cow<'a, String>),
}

impl<'a> PlaylistFilterOperatorSql<'a> {
    fn from_operator(op: &'a PlaylistFilterOperator) -> Self {
        match op {
            PlaylistFilterOperator::Is(val) => Self::Is(Cow::Borrowed(val)),
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

// SpotifyAuthSql

#[derive(Clone)]
pub struct SpotifyAuthSql<'a> {
    pub email: Cow<'a, String>,
    pub access_token: Cow<'a, String>,
    pub refresh_token: Option<Cow<'a, String>>,
    pub user_id: Cow<'a, Uuid>,
}

impl Debug for SpotifyAuthSql<'_> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("SpotifyAuthSql")
            .field("email", &self.email)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("user_id", &"<redacted>")
            .finish()
    }
}

impl<'a> SpotifyAuthSql<'a> {
    fn from_spotify_auth(auth: &'a SpotifyAuth) -> Self {
        Self {
            email: Cow::Borrowed(&auth.email),
            access_token: Cow::Borrowed(&auth.access_token),
            refresh_token: auth.refresh_token.as_ref().map(Cow::Borrowed),
            user_id: Cow::Borrowed(&auth.user_id),
        }
    }
}

// Sync

impl From<SyncSql<'_>> for Sync {
    fn from(sync: SyncSql) -> Self {
        trace!("converting {sync:?} into sync");
        Self {
            last_err_msg: sync.last_err_msg.map(|msg| msg.into_owned()),
            last_start_date: sync.last_start_date.into_owned(),
            last_success_date: sync.last_success_date.map(|date| date.into_owned()),
            state: sync.state.into(),
        }
    }
}

// SyncSql

#[derive(Clone, Debug)]
struct SyncSql<'a> {
    last_err_msg: Option<Cow<'a, String>>,
    last_start_date: Cow<'a, DateTime<Utc>>,
    last_success_date: Option<Cow<'a, DateTime<Utc>>>,
    state: SyncStateSql,
}

impl<'a> SyncSql<'a> {
    fn try_from_row(alias: &str, row: &'a Row) -> Result<Option<Self>> {
        trace!("extracting playlist from {row:?}");
        try_get::<Option<SyncStateSql>>(alias, "sync_state", row)?
            .map(|state| {
                Ok(Self {
                    last_err_msg: try_get_opt_cowed(alias, "last_sync_err_msg", row)?,
                    last_start_date: try_get_cowed(alias, "last_sync_start_date", row)?,
                    last_success_date: try_get_opt_cowed(alias, "last_sync_success_date", row)?,
                    state,
                })
            })
            .transpose()
    }

    fn from_sync(sync: &'a Sync) -> Self {
        Self {
            last_err_msg: sync.last_err_msg.as_ref().map(Cow::Borrowed),
            last_start_date: Cow::Borrowed(&sync.last_start_date),
            last_success_date: sync.last_success_date.as_ref().map(Cow::Borrowed),
            state: sync.state.into(),
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

// User

impl From<UserSql<'_>> for User {
    fn from(user: UserSql) -> Self {
        trace!("converting {user:?} into user");
        Self {
            creation_date: user.creation_date.into_owned(),
            id: user.id.into_owned(),
            role: user.role.into(),
        }
    }
}

// UserSql

#[derive(Clone, Debug)]
struct UserSql<'a> {
    creation_date: Cow<'a, DateTime<Utc>>,
    id: Cow<'a, Uuid>,
    role: RoleSql,
}

impl<'a> UserSql<'a> {
    fn from_user(user: &'a User) -> Self {
        Self {
            creation_date: Cow::Borrowed(&user.creation_date),
            id: Cow::Borrowed(&user.id),
            role: user.role.into(),
        }
    }

    fn try_from_row(alias: &str, row: &'a Row) -> Result<Self> {
        trace!("extracting user from {row:?}");
        Ok(Self {
            creation_date: try_get_cowed(alias, "creation_date", row)?,
            id: try_get_cowed(alias, "id", row)?,
            role: try_get(alias, "role", row)?,
        })
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
    fn base(&self) -> Box<dyn BaseRepository + '_> {
        Box::new(PostgresBaseRepository(self.0))
    }

    fn playlist(&self) -> Box<dyn PlaylistRepository + '_> {
        Box::new(PostgresPlaylistRepository(self.0))
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
    async fn get_by_user_kind_platform(
        &self,
        user_id: &Uuid,
        kind: &BaseKind,
        platform: Platform,
    ) -> Result<Option<Base>> {
        debug!("fetching base from database owned by user {user_id} with {kind:?} on {platform}");
        let (kind, platform_id) = BaseKindSql::from_base_kind(kind);
        let platform: PlatformSql = platform.into();
        let base = self
            .0
            .query_opt(
                sql!("base/get-by-user-kind-platform"),
                &[user_id, &platform, &kind, &platform_id],
            )
            .await
            .map_err(Error::client_boxed)?
            .map(|row| BaseSql::try_from_row("base", &row).and_then(Base::try_from))
            .transpose()?;
        debug!("base fetched: {base:?}");
        Ok(base)
    }

    async fn insert(&self, base: &Base) -> Result<()> {
        debug!("inserting {base:?} into database");
        let base = BaseSql::from_base(base);
        trace!("inserting {base:?} into database");
        self.0
            .query(
                sql!("base/insert"),
                &[
                    base.id.as_ref(),
                    base.creation_date.as_ref(),
                    base.user_id.as_ref(),
                    &base.platform,
                    &base.kind,
                    &base.platform_id.as_ref().map(|id| id.as_ref()),
                ],
            )
            .await
            .map_err(Box::new)?;
        Ok(())
    }

    async fn list_by_user(&self, user_id: &Uuid, limit: u32, offset: u32) -> Result<Page<Base>> {
        debug!("counting total of bases owned by user {user_id}");
        let total: i64 = self
            .0
            .query_one(sql!("base/count-by-user"), &[user_id])
            .await
            .map_err(Error::client_boxed)?
            .get(0);
        debug!("listing bases owned by user {user_id} from offset {offset} limiting to {limit} results");
        let limit: i64 = limit.into();
        let offset: i64 = offset.into();
        let content = self
            .0
            .query(sql!("base/list-by-user"), &[user_id, &limit, &offset])
            .await
            .map_err(Error::client_boxed)?
            .into_iter()
            .map(|row| BaseSql::try_from_row("base", &row).and_then(Base::try_from))
            .collect::<Result<Vec<Base>>>()?;
        let page = Page {
            content,
            total: total.try_into().map_err(Error::total_conversion_boxed)?,
        };
        debug!("page fetched: {page:?}");
        Ok(page)
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
        debug!("fetching playlist from database with id {id}");
        let playlist = self
            .0
            .query_opt(sql!("playlist/get-by-id"), &[id])
            .await
            .map_err(Error::client_boxed)
            .map(|row| {
                row.map(|row| {
                    PlaylistSql::try_from_row("playlist", &row).and_then(Playlist::try_from)
                })
            })?
            .transpose()?;
        debug!("playlist fetched: {playlist:?}");
        Ok(playlist)
    }

    async fn get_by_user_name(&self, user_id: &Uuid, name: &str) -> Result<Option<Playlist>> {
        debug!("fetching playlist from database owned by user {user_id} named `{name}`");
        let playlist = self
            .0
            .query_opt(sql!("playlist/get-by-user-name"), &[user_id, &name])
            .await
            .map_err(Error::client_boxed)
            .map(|row| {
                row.map(|row| {
                    PlaylistSql::try_from_row("playlist", &row).and_then(Playlist::try_from)
                })
            })?
            .transpose()?;
        debug!("playlist fetched: {playlist:?}");
        Ok(playlist)
    }

    async fn insert(&self, playlist: &Playlist, filters: &[PlaylistFilter]) -> Result<()> {
        debug!("inserting {playlist:?} with {filters:?} into database");
        let playlist = PlaylistSql::from_playlist(playlist);
        trace!("inserting {playlist:?} into database");
        self.0
            .query(
                sql!("playlist/insert"),
                &[
                    playlist.id.as_ref(),
                    playlist.creation_date.as_ref(),
                    playlist.user_id.as_ref(),
                    playlist.base_id.as_ref(),
                    playlist.name.as_ref(),
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
            let filter = PlaylistFilterSql::from_filter(filter);
            trace!("inserting {filter:?} into database");
            self.0
                .query(&st, &[playlist.id.as_ref(), &json!(filter)])
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
        let total: i64 = self
            .0
            .query_one(sql!("playlist/count-by-user"), &[user_id])
            .await
            .map_err(Error::client_boxed)?
            .get(0);
        debug!("listing playlists owned by user {user_id} from offset {offset} limiting to {limit} results");
        let limit: i64 = limit.into();
        let offset: i64 = offset.into();
        let content = self
            .0
            .query(sql!("playlist/list-by-user"), &[user_id, &limit, &offset])
            .await
            .map_err(Error::client_boxed)?
            .into_iter()
            .map(|row| PlaylistSql::try_from_row("playlist", &row).and_then(Playlist::try_from))
            .collect::<Result<Vec<Playlist>>>()?;
        let page = Page {
            content,
            total: total.try_into().map_err(Error::total_conversion_boxed)?,
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
        debug!("fetching user from database with id {id}");
        let user = self
            .0
            .query_opt(sql!("user/get-by-id"), &[id])
            .await
            .map_err(Error::client_boxed)
            .map(|row| row.map(|row| UserSql::try_from_row("user", &row).map(User::from)))?
            .transpose()?;
        debug!("user fetched: {user:?}");
        Ok(user)
    }

    async fn get_by_spotify_email(&self, email: &str) -> Result<Option<User>> {
        debug!("fetching user from database with Spotify email `{email}`");
        let user = self
            .0
            .query_opt(sql!("user/get-by-spotify-email"), &[&email])
            .await
            .map_err(Error::client_boxed)
            .map(|row| row.map(|row| UserSql::try_from_row("user", &row).map(User::from)))?
            .transpose()?;
        debug!("user fetched: {user:?}");
        Ok(user)
    }

    async fn insert(&self, user: &User) -> Result<()> {
        debug!("inserting {user:?} into database");
        let user = UserSql::from_user(user);
        trace!("inserting {user:?} into database");
        self.0
            .query(
                sql!("user/insert"),
                &[user.id.as_ref(), user.creation_date.as_ref(), &user.role],
            )
            .await
            .map_err(Box::new)?;
        Ok(())
    }

    async fn upsert_spotify_auth(&self, auth: &SpotifyAuth) -> Result<()> {
        debug!("upserting {auth:?} into database");
        let auth = SpotifyAuthSql::from_spotify_auth(auth);
        trace!("upserting {auth:?} into database");
        self.0
            .query(
                sql!("user/upsert-spotify-auth"),
                &[
                    auth.user_id.as_ref(),
                    auth.email.as_ref(),
                    auth.access_token.as_ref(),
                    &auth.refresh_token.as_ref().map(|token| token.as_ref()),
                ],
            )
            .await
            .map_err(Box::new)?;
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

// Impl - Config

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

// try_get

#[inline]
fn try_get<'a, T: FromSql<'a>>(alias: &str, key: &str, row: &'a Row) -> Result<T> {
    row.try_get(format!("{alias}_{key}").as_str())
        .map_err(Error::client_boxed)
}

// try_get_cowed

#[inline]
fn try_get_cowed<'a, T: Clone + FromSql<'a>>(
    alias: &str,
    key: &str,
    row: &'a Row,
) -> Result<Cow<'a, T>> {
    try_get::<T>(alias, key, row).map(Cow::Owned)
}

// try_get_opt_cowed

#[inline]
fn try_get_opt_cowed<'a, T: Clone + FromSql<'a>>(
    alias: &str,
    key: &str,
    row: &'a Row,
) -> Result<Option<Cow<'a, T>>> {
    try_get::<Option<T>>(alias, key, row).map(|val| val.map(Cow::Owned))
}

// Mods

embed_migrations!("db/postgres/migrations");
