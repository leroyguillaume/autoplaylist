use std::collections::BTreeSet;

use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

use crate::model::{
    Album, Credentials, Page, PageRequest, Platform, Playlist, PlaylistSynchronization, Predicate,
    Source, SourceKind, SourceSynchronization, Target, Track, User,
};

// Macros

#[macro_export]
macro_rules! transactional {
    ($tx:expr, $f:expr) => {{
        match $f.await {
            Ok(val) => {
                $tx.commit().await?;
                Ok(val)
            }
            Err(err) => {
                $tx.rollback().await?;
                Err(err)
            }
        }
    }};
}

macro_rules! mock_client_impl {
    ($type:ty, $attr:tt) => {
        #[cfg(any(test, feature = "test"))]
        #[async_trait]
        impl DatabaseClient for $type {
            async fn add_track_to_playlist(
                &mut self,
                playlist_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<()> {
                self.$attr
                    .add_track_to_playlist(playlist_id, track_id)
                    .await
            }

            async fn add_track_to_source(
                &mut self,
                src_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<()> {
                self.$attr.add_track_to_source(src_id, track_id).await
            }

            fn as_client_mut(&mut self) -> &mut dyn DatabaseClient {
                self
            }

            async fn count_source_playlists(&mut self, id: Uuid) -> DatabaseResult<u32> {
                self.$attr.count_source_playlists(id).await
            }

            async fn create_playlist(
                &mut self,
                creation: &PlaylistCreation,
            ) -> DatabaseResult<Playlist> {
                self.$attr.create_playlist(creation).await
            }

            async fn create_source(&mut self, creation: &SourceCreation) -> DatabaseResult<Source> {
                self.$attr.create_source(creation).await
            }

            async fn create_track(&mut self, creation: &TrackCreation) -> DatabaseResult<Track> {
                self.$attr.create_track(creation).await
            }

            async fn create_user(&mut self, creation: &UserCreation) -> DatabaseResult<User> {
                self.$attr.create_user(creation).await
            }

            async fn delete_playlist(&mut self, id: Uuid) -> DatabaseResult<bool> {
                self.$attr.delete_playlist(id).await
            }

            async fn delete_source(&mut self, id: Uuid) -> DatabaseResult<bool> {
                self.$attr.delete_source(id).await
            }

            async fn delete_tracks_from_playlist(&mut self, id: Uuid) -> DatabaseResult<u64> {
                self.$attr.delete_tracks_from_playlist(id).await
            }

            async fn delete_tracks_from_source(&mut self, id: Uuid) -> DatabaseResult<u64> {
                self.$attr.delete_tracks_from_source(id).await
            }

            async fn delete_user(&mut self, id: Uuid) -> DatabaseResult<bool> {
                self.$attr.delete_user(id).await
            }

            async fn lock_playlist_synchronization(
                &mut self,
                id: Uuid,
            ) -> DatabaseResult<Option<PlaylistSynchronization>> {
                self.$attr.lock_playlist_synchronization(id).await
            }

            async fn lock_source_synchronization(
                &mut self,
                id: Uuid,
            ) -> DatabaseResult<Option<SourceSynchronization>> {
                self.$attr.lock_source_synchronization(id).await
            }

            async fn playlist_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Playlist>> {
                self.$attr.playlist_by_id(id).await
            }

            async fn playlist_contains_track(
                &mut self,
                playlist_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<bool> {
                self.$attr
                    .playlist_contains_track(playlist_id, track_id)
                    .await
            }

            async fn playlist_ids_by_source(
                &mut self,
                src_id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Uuid>> {
                self.$attr.playlist_ids_by_source(src_id, req).await
            }

            async fn playlist_tracks(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                self.$attr.playlist_tracks(id, req).await
            }

            async fn playlists(&mut self, req: PageRequest) -> DatabaseResult<Page<Playlist>> {
                self.$attr.playlists(req).await
            }

            async fn search_playlists_by_name(
                &mut self,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                self.$attr.search_playlists_by_name(q, req).await
            }

            async fn search_user_playlists_by_name(
                &mut self,
                id: Uuid,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                self.$attr.search_user_playlists_by_name(id, q, req).await
            }

            async fn search_users_by_email(
                &mut self,
                q: &str,
                req: PageRequest,
            ) -> DatabaseResult<Page<User>> {
                self.$attr.search_users_by_email(q, req).await
            }

            async fn source_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Source>> {
                self.$attr.source_by_id(id).await
            }

            async fn source_by_owner_kind(
                &mut self,
                owner_id: Uuid,
                kind: &SourceKind,
            ) -> DatabaseResult<Option<Source>> {
                self.$attr.source_by_owner_kind(owner_id, kind).await
            }

            async fn source_contains_track(
                &mut self,
                src_id: Uuid,
                track_id: Uuid,
            ) -> DatabaseResult<bool> {
                self.$attr.source_contains_track(src_id, track_id).await
            }

            async fn source_tracks(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Track>> {
                self.$attr.source_tracks(id, req).await
            }

            async fn sources(&mut self, req: PageRequest) -> DatabaseResult<Page<Source>> {
                self.$attr.sources(req).await
            }

            async fn track_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Track>> {
                self.$attr.track_by_id(id).await
            }

            async fn track_by_platform_id(
                &mut self,
                platform: Platform,
                id: &str,
            ) -> DatabaseResult<Option<Track>> {
                self.$attr.track_by_platform_id(platform, id).await
            }

            async fn tracks(&mut self, req: PageRequest) -> DatabaseResult<Page<Track>> {
                self.$attr.tracks(req).await
            }

            async fn update_playlist(&mut self, playlist: &Playlist) -> DatabaseResult<()> {
                self.$attr.update_playlist(playlist).await
            }

            async fn update_source(&mut self, src: &Source) -> DatabaseResult<()> {
                self.$attr.update_source(src).await
            }

            async fn update_user(&mut self, user: &User) -> DatabaseResult<()> {
                self.$attr.update_user(user).await
            }

            async fn user_by_email(&mut self, email: &str) -> DatabaseResult<Option<User>> {
                self.$attr.user_by_email(email).await
            }

            async fn user_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<User>> {
                self.$attr.user_by_id(id).await
            }

            async fn user_playlists(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Playlist>> {
                self.$attr.user_playlists(id, req).await
            }

            async fn user_sources(
                &mut self,
                id: Uuid,
                req: PageRequest,
            ) -> DatabaseResult<Page<Source>> {
                self.$attr.user_sources(id, req).await
            }

            async fn users(&mut self, req: PageRequest) -> DatabaseResult<Page<User>> {
                self.$attr.users(req).await
            }
        }
    };
}

// Types

pub type DatabaseResult<T> = Result<T, DatabaseError>;

// DatabaseError

#[derive(Debug, Error)]
#[error("{0}")]
pub struct DatabaseError(
    #[from]
    #[source]
    Box<dyn std::error::Error + Send + Sync>,
);

impl From<&str> for DatabaseError {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

// PlaylistCreation

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaylistCreation {
    pub name: String,
    pub predicate: Predicate,
    pub src: Source,
    pub tgt: Target,
}

impl From<Playlist> for PlaylistCreation {
    fn from(playlist: Playlist) -> Self {
        Self {
            name: playlist.name,
            predicate: playlist.predicate,
            src: playlist.src,
            tgt: playlist.tgt,
        }
    }
}

// SourceCreation

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCreation {
    pub kind: SourceKind,
    pub owner: User,
}

impl From<Source> for SourceCreation {
    fn from(src: Source) -> Self {
        Self {
            kind: src.kind,
            owner: src.owner,
        }
    }
}

// TrackCreation

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackCreation {
    pub album: Album,
    pub artists: BTreeSet<String>,
    pub platform: Platform,
    pub platform_id: String,
    pub title: String,
    pub year: i32,
}

impl From<Track> for TrackCreation {
    fn from(track: Track) -> Self {
        Self {
            album: track.album,
            artists: track.artists,
            platform: track.platform,
            platform_id: track.platform_id,
            title: track.title,
            year: track.year,
        }
    }
}

// UserCreation

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserCreation {
    pub creds: Credentials,
    pub email: String,
}

impl From<User> for UserCreation {
    fn from(user: User) -> Self {
        Self {
            creds: user.creds,
            email: user.email,
        }
    }
}

// DatabaseClient

#[cfg_attr(any(test, feature = "test"), mockall::automock)]
#[async_trait]
pub trait DatabaseClient: Send + Sync {
    async fn add_track_to_playlist(
        &mut self,
        playlist_id: Uuid,
        track_id: Uuid,
    ) -> DatabaseResult<()>;

    async fn add_track_to_source(&mut self, src_id: Uuid, track_id: Uuid) -> DatabaseResult<()>;

    fn as_client_mut(&mut self) -> &mut dyn DatabaseClient;

    async fn count_source_playlists(&mut self, id: Uuid) -> DatabaseResult<u32>;

    async fn create_playlist(&mut self, creation: &PlaylistCreation) -> DatabaseResult<Playlist>;

    async fn create_source(&mut self, creation: &SourceCreation) -> DatabaseResult<Source>;

    async fn create_track(&mut self, creation: &TrackCreation) -> DatabaseResult<Track>;

    async fn create_user(&mut self, creation: &UserCreation) -> DatabaseResult<User>;

    async fn delete_playlist(&mut self, id: Uuid) -> DatabaseResult<bool>;

    async fn delete_source(&mut self, id: Uuid) -> DatabaseResult<bool>;

    async fn delete_tracks_from_playlist(&mut self, id: Uuid) -> DatabaseResult<u64>;

    async fn delete_tracks_from_source(&mut self, id: Uuid) -> DatabaseResult<u64>;

    async fn delete_user(&mut self, id: Uuid) -> DatabaseResult<bool>;

    async fn lock_playlist_synchronization(
        &mut self,
        id: Uuid,
    ) -> DatabaseResult<Option<PlaylistSynchronization>>;

    async fn lock_source_synchronization(
        &mut self,
        id: Uuid,
    ) -> DatabaseResult<Option<SourceSynchronization>>;

    async fn playlist_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Playlist>>;

    async fn playlist_contains_track(
        &mut self,
        playlist_id: Uuid,
        track_id: Uuid,
    ) -> DatabaseResult<bool>;

    async fn playlist_ids_by_source(
        &mut self,
        src_id: Uuid,
        req: PageRequest,
    ) -> DatabaseResult<Page<Uuid>>;

    async fn playlist_tracks(&mut self, id: Uuid, req: PageRequest) -> DatabaseResult<Page<Track>>;

    async fn playlists(&mut self, req: PageRequest) -> DatabaseResult<Page<Playlist>>;

    async fn search_playlists_by_name(
        &mut self,
        q: &str,
        req: PageRequest,
    ) -> DatabaseResult<Page<Playlist>>;

    async fn search_user_playlists_by_name(
        &mut self,
        id: Uuid,
        q: &str,
        req: PageRequest,
    ) -> DatabaseResult<Page<Playlist>>;

    async fn search_users_by_email(
        &mut self,
        q: &str,
        req: PageRequest,
    ) -> DatabaseResult<Page<User>>;

    async fn source_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Source>>;

    async fn source_by_owner_kind(
        &mut self,
        owner_id: Uuid,
        kind: &SourceKind,
    ) -> DatabaseResult<Option<Source>>;

    async fn source_contains_track(&mut self, src_id: Uuid, track_id: Uuid)
        -> DatabaseResult<bool>;

    async fn source_tracks(&mut self, id: Uuid, req: PageRequest) -> DatabaseResult<Page<Track>>;

    async fn sources(&mut self, req: PageRequest) -> DatabaseResult<Page<Source>>;

    async fn track_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<Track>>;

    async fn track_by_platform_id(
        &mut self,
        platform: Platform,
        id: &str,
    ) -> DatabaseResult<Option<Track>>;

    async fn tracks(&mut self, req: PageRequest) -> DatabaseResult<Page<Track>>;

    async fn update_playlist(&mut self, playlist: &Playlist) -> DatabaseResult<()>;

    async fn update_source(&mut self, src: &Source) -> DatabaseResult<()>;

    async fn update_user(&mut self, user: &User) -> DatabaseResult<()>;

    async fn user_by_email(&mut self, email: &str) -> DatabaseResult<Option<User>>;

    async fn user_by_id(&mut self, id: Uuid) -> DatabaseResult<Option<User>>;

    async fn user_playlists(
        &mut self,
        id: Uuid,
        req: PageRequest,
    ) -> DatabaseResult<Page<Playlist>>;

    async fn user_sources(&mut self, id: Uuid, req: PageRequest) -> DatabaseResult<Page<Source>>;

    async fn users(&mut self, req: PageRequest) -> DatabaseResult<Page<User>>;
}

// DatabaseConnection

pub trait DatabaseConnection: DatabaseClient {}

// DatabasePool

#[async_trait]
pub trait DatabasePool<CONN: DatabaseConnection, TX: DatabaseTransaction>: Send + Sync {
    async fn acquire(&self) -> DatabaseResult<CONN>;

    async fn begin(&self) -> DatabaseResult<TX>;
}

// DatabaseTransaction

#[async_trait]
pub trait DatabaseTransaction: DatabaseClient {
    async fn commit(self) -> DatabaseResult<()>;

    async fn rollback(self) -> DatabaseResult<()>;
}

// MockDatabaseConnection

#[cfg(any(test, feature = "test"))]
#[derive(Default)]
pub struct MockDatabaseConnection(pub MockDatabaseClient);

#[cfg(any(test, feature = "test"))]
impl MockDatabaseConnection {
    pub fn new() -> Self {
        Self::default()
    }
}

mock_client_impl!(MockDatabaseConnection, 0);

#[cfg(any(test, feature = "test"))]
impl DatabaseConnection for MockDatabaseConnection {}

// MockDatabasePool

#[cfg(any(test, feature = "test"))]
#[derive(Default)]
pub struct MockDatabasePool {
    pub acquire: mockable::Mock<MockDatabaseConnection>,
    pub begin: mockable::Mock<MockDatabaseTransaction>,
}

#[cfg(any(test, feature = "test"))]
#[async_trait]
impl DatabasePool<MockDatabaseConnection, MockDatabaseTransaction> for MockDatabasePool {
    async fn acquire(&self) -> DatabaseResult<MockDatabaseConnection> {
        Ok(self.acquire.call())
    }

    async fn begin(&self) -> DatabaseResult<MockDatabaseTransaction> {
        Ok(self.begin.call())
    }
}

// MockDatabaseTransaction

#[cfg(any(test, feature = "test"))]
pub struct MockDatabaseTransaction {
    pub client: MockDatabaseClient,
    pub commit: mockable::Mock<()>,
    pub rollback: mockable::Mock<()>,
}

#[cfg(any(test, feature = "test"))]
impl MockDatabaseTransaction {
    pub fn new() -> Self {
        Self {
            client: MockDatabaseClient::new(),
            commit: mockable::Mock::once(|| ()),
            rollback: mockable::Mock::never(),
        }
    }
}

#[cfg(any(test, feature = "test"))]
impl Default for MockDatabaseTransaction {
    fn default() -> Self {
        Self::new()
    }
}

mock_client_impl!(MockDatabaseTransaction, client);

#[cfg(any(test, feature = "test"))]
#[async_trait]
impl DatabaseTransaction for MockDatabaseTransaction {
    async fn commit(self) -> DatabaseResult<()> {
        self.commit.call();
        Ok(())
    }

    async fn rollback(self) -> DatabaseResult<()> {
        self.rollback.call();
        Ok(())
    }
}

// Mods

pub mod pg;

// Tests

#[cfg(test)]
mod test {
    use chrono::Utc;
    use mockable::Mock;

    use crate::model::{Role, SpotifySourceKind, Synchronization};

    use super::*;

    mod playlist_creation {
        use super::*;

        mod from_playlist {
            use super::*;

            #[test]
            fn creation() {
                let playlist = Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let expected = PlaylistCreation {
                    name: playlist.name.clone(),
                    predicate: playlist.predicate.clone(),
                    src: playlist.src.clone(),
                    tgt: playlist.tgt.clone(),
                };
                let creation = PlaylistCreation::from(playlist);
                assert_eq!(creation, expected);
            }
        }
    }

    mod source_creation {
        use super::*;

        mod from_source {
            use super::*;

            #[test]
            fn creation() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                };
                let expected = SourceCreation {
                    kind: src.kind.clone(),
                    owner: src.owner.clone(),
                };
                let creation = SourceCreation::from(src);
                assert_eq!(creation, expected);
            }
        }
    }

    mod track_creation {
        use super::*;

        mod from_track {
            use super::*;

            #[test]
            fn creation() {
                let track = Track {
                    album: Album {
                        compil: false,
                        name: "The Dark Side of the Moon".into(),
                    },
                    artists: BTreeSet::from_iter(["Pink Floyd".into()]),
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    platform: Platform::Spotify,
                    platform_id: "id".into(),
                    title: "Time".into(),
                    year: 1973,
                };
                let expected = TrackCreation {
                    album: track.album.clone(),
                    artists: track.artists.clone(),
                    platform: track.platform,
                    platform_id: track.platform_id.clone(),
                    title: track.title.clone(),
                    year: track.year,
                };
                let creation = TrackCreation::from(track);
                assert_eq!(creation, expected);
            }
        }
    }

    mod transactional {
        use super::*;

        // MockError

        struct MockError;

        impl From<DatabaseError> for MockError {
            fn from(_: DatabaseError) -> Self {
                Self
            }
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            commit: Mock<()>,
            f: Mock<Result<(), MockError>>,
            rollback: Mock<()>,
        }

        // run

        async fn run(mocks: Mocks) -> Result<(), MockError> {
            let mut client = MockDatabaseClient::new();
            client
                .expect_user_by_email()
                .times(1)
                .returning(|_| Ok(None));
            let mut tx = MockDatabaseTransaction {
                client,
                commit: mocks.commit.clone(),
                rollback: mocks.rollback.clone(),
            };
            transactional!(tx, async {
                tx.user_by_email("user@test").await?;
                mocks.f.call()?;
                Ok::<(), MockError>(())
            })
        }

        // Tests

        #[tokio::test]
        async fn commit() {
            let mocks = Mocks {
                commit: Mock::once(|| ()),
                f: Mock::once(|| Ok(())),
                ..Default::default()
            };
            let res = run(mocks).await;
            assert!(res.is_ok());
        }

        #[tokio::test]
        async fn rollback() {
            let mocks = Mocks {
                f: Mock::once(|| Err(MockError)),
                rollback: Mock::once(|| ()),
                ..Default::default()
            };
            let res = run(mocks).await;
            assert!(res.is_err());
        }
    }

    mod user_creation {
        use super::*;

        mod from_user {
            use super::*;

            #[test]
            fn creation() {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    email: "user@test".into(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let expected = UserCreation {
                    creds: usr.creds.clone(),
                    email: usr.email.clone(),
                };
                let creation = UserCreation::from(usr);
                assert_eq!(creation, expected);
            }
        }
    }
}
