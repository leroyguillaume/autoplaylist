use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::{
    api::{CreatePlaylistRequest, PageRequestQueryParams, Platform, QQueryParam},
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConsumer},
        BrokerClient, Consumer, PlaylistMessage, PlaylistMessageKind, SourceMessage,
        SourceMessageKind,
    },
    db::{
        pg::{PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseConnection, DatabasePool, DatabaseTransaction, PlaylistCreation, SourceCreation,
    },
    model::{Page, Playlist, Target, User},
    spotify::{rspotify::RSpotifyClient, SpotifyClient},
    transactional,
};
use tracing::info;
use uuid::Uuid;

use crate::{ServiceError, ServiceResult};

// PlaylistService

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PlaylistService: Send + Sync {
    async fn authenticated_user_playlists(
        &self,
        usr_id: Uuid,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>>;

    async fn create(&self, req: CreatePlaylistRequest, owner: User) -> ServiceResult<Playlist>;

    async fn delete(&self, playlist: &Playlist) -> ServiceResult<()>;

    async fn playlist_by_id(&self, id: Uuid) -> ServiceResult<Option<Playlist>>;

    async fn playlists(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<Playlist>>;

    async fn search_authenticated_user_playlists_by_name(
        &self,
        usr_id: Uuid,
        params: &QQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>>;

    async fn search_playlists_by_name(
        &self,
        params: &QQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>>;

    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()>;
}

// DefaultPlaylistService

pub struct DefaultPlaylistService<
    CSM: Consumer,
    BROKER: BrokerClient<CSM>,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    SPOTIFY: SpotifyClient,
> {
    broker: Arc<BROKER>,
    db: Arc<DB>,
    spotify: Arc<SPOTIFY>,
    _csm: PhantomData<CSM>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
}

impl
    DefaultPlaylistService<
        RabbitMqConsumer,
        RabbitMqClient,
        PostgresConnection,
        PostgresTransaction<'_>,
        PostgresPool,
        RSpotifyClient,
    >
{
    pub fn new(
        broker: Arc<RabbitMqClient>,
        db: Arc<PostgresPool>,
        spotify: Arc<RSpotifyClient>,
    ) -> Self {
        Self {
            broker,
            db,
            spotify,
            _csm: PhantomData,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
        }
    }
}

#[async_trait]
impl<
        CSM: Consumer,
        BROKER: BrokerClient<CSM>,
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SPOTIFY: SpotifyClient,
    > PlaylistService for DefaultPlaylistService<CSM, BROKER, DBCONN, DBTX, DB, SPOTIFY>
{
    async fn authenticated_user_playlists(
        &self,
        usr_id: Uuid,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.user_playlists(usr_id, req.into()).await?;
        Ok(page)
    }

    async fn create(&self, req: CreatePlaylistRequest, mut owner: User) -> ServiceResult<Playlist> {
        let tgt = match req.platform {
            Platform::Spotify => {
                let creds = owner
                    .creds
                    .spotify
                    .as_mut()
                    .ok_or(ServiceError::NoSpotifyCredentials(owner.id))?;
                let id = self.spotify.create_playlist(&req.name, creds).await?;
                Target::Spotify(id)
            }
        };
        let mut db_tx = self.db.begin().await?;
        let (playlist, new_src) = transactional!(db_tx, async {
            let src = db_tx.source_by_owner_kind(owner.id, &req.src).await?;
            let (src, new_src) = match src {
                Some(src) => (src, false),
                None => {
                    let creation = SourceCreation {
                        kind: req.src,
                        owner,
                    };
                    let src = db_tx.create_source(&creation).await?;
                    info!(src.owner.email, %src.owner.id, "source created");
                    (src, true)
                }
            };
            let creation = PlaylistCreation {
                name: req.name,
                predicate: req.predicate,
                src,
                tgt,
            };
            let playlist = db_tx.create_playlist(&creation).await?;
            info!(%playlist.id, playlist.src.owner.email, %playlist.src.owner.id, "playlist created");
            Ok::<(Playlist, bool), ServiceError>((playlist, new_src))
        })?;
        let publisher = self.broker.publisher();
        if new_src {
            let msg = SourceMessage {
                id: playlist.src.id,
                kind: SourceMessageKind::Created,
            };
            publisher.publish_source_message(&msg).await?;
        }
        let msg = PlaylistMessage {
            id: playlist.src.id,
            kind: PlaylistMessageKind::Created,
        };
        publisher.publish_playlist_message(&msg).await?;
        Ok(playlist)
    }

    async fn delete(&self, playlist: &Playlist) -> ServiceResult<()> {
        let mut db_tx = self.db.begin().await?;
        transactional!(db_tx, async {
            db_tx.delete_playlist(playlist.id).await?;
            info!(%playlist.id, "playlist deleted");
            if db_tx.count_source_playlists(playlist.src.id).await? == 0 {
                db_tx.delete_source(playlist.src.id).await?;
                info!(src.id = %playlist.src.id, "source deleted");
            }
            Ok::<(), ServiceError>(())
        })?;
        Ok(())
    }

    async fn playlist_by_id(&self, id: Uuid) -> ServiceResult<Option<Playlist>> {
        let mut db_conn = self.db.acquire().await?;
        let playlist = db_conn.playlist_by_id(id).await?;
        Ok(playlist)
    }

    async fn playlists(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<Playlist>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.playlists(req.into()).await?;
        Ok(page)
    }

    async fn search_authenticated_user_playlists_by_name(
        &self,
        usr_id: Uuid,
        params: &QQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn
            .search_user_playlists_by_name(usr_id, &params.q, req.into())
            .await?;
        Ok(page)
    }

    async fn search_playlists_by_name(
        &self,
        params: &QQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Playlist>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn
            .search_playlists_by_name(&params.q, req.into())
            .await?;
        Ok(page)
    }

    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()> {
        let msg = PlaylistMessage {
            id,
            kind: PlaylistMessageKind::Sync,
        };
        self.broker
            .publisher()
            .publish_playlist_message(&msg)
            .await?;
        Ok(())
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::{
        broker::{MockBrokerClient, MockPublisher},
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Credentials, Playlist, Predicate, Role, Source, SourceKind, SpotifyCredentials,
            SpotifyResourceKind, SpotifyToken, Synchronization,
        },
        spotify::MockSpotifyClient,
    };
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use super::*;

    // Mods

    mod default_playlist_message {
        use super::*;

        // Mods

        mod authenticated_user_playlists {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let id = Uuid::new_v4();
                let req = PageRequestQueryParams::<25>::default();
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_user_playlists()
                                .with(eq(id), eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_, _| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = playlist_svc
                    .authenticated_user_playlists(id, req)
                    .await
                    .expect("failed to get playlists");
                assert_eq!(page, expected);
            }
        }

        mod create {
            use super::*;

            // Data

            struct Data {
                owner: User,
                req: CreatePlaylistRequest,
                spotify_creds: SpotifyCredentials,
            }

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                create_spotify_playlist: Mock<()>,
                create_src: Mock<()>,
                publish_playlist_msg: Mock<()>,
                publish_src_msg: Mock<()>,
                src_by_owner_kind: Mock<Option<Source>, Source>,
            }

            // run

            async fn run(data: Data, mocks: Mocks) -> ServiceResult<(Playlist, Playlist)> {
                let spotify_id = "id";
                let expected = Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: data.req.name.clone(),
                    predicate: data.req.predicate.clone(),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: data.req.src.clone(),
                        owner: data.owner.clone(),
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                };
                let src_msg = SourceMessage {
                    id: expected.src.id,
                    kind: SourceMessageKind::Created,
                };
                let playlist_msg = PlaylistMessage {
                    id: expected.src.id,
                    kind: PlaylistMessageKind::Created,
                };
                let mut spotify = MockSpotifyClient::new();
                spotify
                    .expect_create_playlist()
                    .with(eq(expected.name.clone()), eq(data.spotify_creds.clone()))
                    .times(mocks.create_spotify_playlist.times())
                    .returning(|_, _| Ok(spotify_id.into()));
                let db = MockDatabasePool {
                    begin: Mock::once({
                        let playlist = expected.clone();
                        let mocks = mocks.clone();
                        move || {
                            let mut tx = MockDatabaseTransaction::new();
                            tx.client
                                .expect_source_by_owner_kind()
                                .with(eq(playlist.src.owner.id), eq(playlist.src.kind.clone()))
                                .times(mocks.src_by_owner_kind.times())
                                .returning({
                                    let src = playlist.src.clone();
                                    let mock = mocks.src_by_owner_kind.clone();
                                    move |_, _| Ok(mock.call_with_args(src.clone()))
                                });
                            let creation: SourceCreation = playlist.src.clone().into();
                            tx.client
                                .expect_create_source()
                                .with(eq(creation))
                                .times(mocks.create_src.times())
                                .returning({
                                    let src = playlist.src.clone();
                                    move |_| Ok(src.clone())
                                });
                            let creation: PlaylistCreation = playlist.clone().into();
                            tx.client
                                .expect_create_playlist()
                                .with(eq(creation))
                                .returning({
                                    let playlist = playlist.clone();
                                    move |_| Ok(playlist.clone())
                                });
                            tx
                        }
                    }),
                    ..Default::default()
                };
                let mut publisher = MockPublisher::new();
                publisher
                    .expect_publish_source_message()
                    .with(eq(src_msg))
                    .times(mocks.publish_src_msg.times())
                    .returning(|_| Ok(()));
                publisher
                    .expect_publish_playlist_message()
                    .with(eq(playlist_msg))
                    .times(mocks.publish_playlist_msg.times())
                    .returning(|_| Ok(()));
                let broker = MockBrokerClient {
                    publisher,
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(broker),
                    db: Arc::new(db),
                    spotify: Arc::new(spotify),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                playlist_svc
                    .create(data.req, data.owner)
                    .await
                    .map(|playlist| (playlist, expected))
            }

            // Tests

            #[tokio::test]
            async fn no_spotify_credentials() {
                let owner_id = Uuid::new_v4();
                let spotify_creds = SpotifyCredentials {
                    id: "id".into(),
                    token: SpotifyToken {
                        access: "access".into(),
                        expiration: Utc::now(),
                        refresh: "refresh".into(),
                    },
                };
                let data = Data {
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: owner_id,
                        role: Role::User,
                    },
                    req: CreatePlaylistRequest {
                        name: "name".into(),
                        platform: Platform::Spotify,
                        predicate: Predicate::YearEquals(1993),
                        src: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    },
                    spotify_creds,
                };
                let mocks = Mocks::default();
                let err = run(data, mocks)
                    .await
                    .expect_err("creating playlist should fail");
                match err {
                    ServiceError::NoSpotifyCredentials(id) => {
                        assert_eq!(id, owner_id);
                    }
                    _ => panic!("unexpected error: {err}"),
                }
            }

            #[tokio::test]
            async fn spotify_playlist_when_source_didnt_exist() {
                let owner_id = Uuid::new_v4();
                let spotify_creds = SpotifyCredentials {
                    id: "id".into(),
                    token: SpotifyToken {
                        access: "access".into(),
                        expiration: Utc::now(),
                        refresh: "refresh".into(),
                    },
                };
                let data = Data {
                    owner: User {
                        creation: Utc::now(),
                        creds: Credentials {
                            spotify: Some(spotify_creds.clone()),
                        },
                        email: "user@test".into(),
                        id: owner_id,
                        role: Role::User,
                    },
                    req: CreatePlaylistRequest {
                        name: "name".into(),
                        platform: Platform::Spotify,
                        predicate: Predicate::YearEquals(1993),
                        src: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    },
                    spotify_creds,
                };
                let mocks = Mocks {
                    create_spotify_playlist: Mock::once(|| ()),
                    create_src: Mock::once(|| ()),
                    publish_playlist_msg: Mock::once(|| ()),
                    publish_src_msg: Mock::once(|| ()),
                    src_by_owner_kind: Mock::once_with_args(|_| None),
                };
                let (playlist, expected) =
                    run(data, mocks).await.expect("failed to create playlist");
                assert_eq!(playlist, expected);
            }

            #[tokio::test]
            async fn spotify_playlist_when_source_already_existed() {
                let owner_id = Uuid::new_v4();
                let spotify_creds = SpotifyCredentials {
                    id: "id".into(),
                    token: SpotifyToken {
                        access: "access".into(),
                        expiration: Utc::now(),
                        refresh: "refresh".into(),
                    },
                };
                let data = Data {
                    owner: User {
                        creation: Utc::now(),
                        creds: Credentials {
                            spotify: Some(spotify_creds.clone()),
                        },
                        email: "user@test".into(),
                        id: owner_id,
                        role: Role::User,
                    },
                    req: CreatePlaylistRequest {
                        name: "name".into(),
                        platform: Platform::Spotify,
                        predicate: Predicate::YearEquals(1993),
                        src: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    },
                    spotify_creds,
                };
                let mocks = Mocks {
                    create_spotify_playlist: Mock::once(|| ()),
                    publish_playlist_msg: Mock::once(|| ()),
                    src_by_owner_kind: Mock::once_with_args(|src: Source| Some(src.clone())),
                    ..Default::default()
                };
                let (playlist, expected) =
                    run(data, mocks).await.expect("failed to create playlist");
                assert_eq!(playlist, expected);
            }
        }

        mod delete {
            use super::*;

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                commit: Mock<()>,
                count_src_playlists: Mock<u32>,
                delete_playlist: Mock<()>,
                delete_src: Mock<()>,
                rollback: Mock<()>,
            }

            // run

            async fn run(mocks: Mocks) -> ServiceResult<()> {
                let playlist = Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".into(),
                    predicate: Predicate::YearEquals(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
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
                let db = MockDatabasePool {
                    begin: Mock::once({
                        let mocks = mocks.clone();
                        let playlist = playlist.clone();
                        move || {
                            let mut db_tx = MockDatabaseTransaction {
                                commit: mocks.commit.clone(),
                                rollback: mocks.rollback.clone(),
                                ..Default::default()
                            };
                            db_tx
                                .client
                                .expect_count_source_playlists()
                                .with(eq(playlist.src.id))
                                .times(mocks.count_src_playlists.times())
                                .returning({
                                    let mock = mocks.count_src_playlists.clone();
                                    move |_| Ok(mock.call())
                                });
                            db_tx
                                .client
                                .expect_delete_playlist()
                                .with(eq(playlist.id))
                                .times(mocks.delete_playlist.times())
                                .returning(move |_| Ok(()));
                            db_tx
                                .client
                                .expect_delete_source()
                                .with(eq(playlist.src.id))
                                .times(mocks.delete_src.times())
                                .returning(move |_| Ok(()));
                            db_tx
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                playlist_svc.delete(&playlist).await
            }

            // Tests

            #[tokio::test]
            async fn unit_when_still_playlists_based_on_source() {
                let mocks = Mocks {
                    commit: Mock::once(|| ()),
                    count_src_playlists: Mock::once(|| 1),
                    delete_playlist: Mock::once(|| ()),
                    ..Default::default()
                };
                run(mocks).await.expect("failed to delete playlist");
            }

            #[tokio::test]
            async fn unit_when_no_more_playlist_based_on_source() {
                let mocks = Mocks {
                    commit: Mock::once(|| ()),
                    count_src_playlists: Mock::once(|| 0),
                    delete_playlist: Mock::once(|| ()),
                    delete_src: Mock::once(|| ()),
                    ..Default::default()
                };
                run(mocks).await.expect("failed to delete playlist");
            }
        }

        mod playlist_by_id {
            use super::*;

            // Tests

            #[tokio::test]
            async fn playlist() {
                let id = Uuid::new_v4();
                let expected = Playlist {
                    creation: Utc::now(),
                    id,
                    name: "name".into(),
                    predicate: Predicate::YearEquals(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
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
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_playlist_by_id()
                                .with(eq(id))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_| Ok(Some(expected.clone()))
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let playlist = playlist_svc
                    .playlist_by_id(id)
                    .await
                    .expect("failed to get playlist")
                    .expect("playlist doesn't exist");
                assert_eq!(playlist, expected);
            }
        }

        mod playlists {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let req = PageRequestQueryParams::<25>::default();
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_playlists()
                                .with(eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = playlist_svc
                    .playlists(req)
                    .await
                    .expect("failed to get playlists");
                assert_eq!(page, expected);
            }
        }

        mod search_authenticated_user_playlists_by_name {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let id = Uuid::new_v4();
                let params = QQueryParam { q: "query".into() };
                let req = PageRequestQueryParams::<25>::default();
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        let params = params.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_search_user_playlists_by_name()
                                .with(eq(id), eq(params.q.clone()), eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_, _, _| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = playlist_svc
                    .search_authenticated_user_playlists_by_name(id, &params, req)
                    .await
                    .expect("failed to get playlists");
                assert_eq!(page, expected);
            }
        }

        mod search_playlists {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let req = PageRequestQueryParams::<25>::default();
                let params = QQueryParam { q: "query".into() };
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        let params = params.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_search_playlists_by_name()
                                .with(eq(params.q.clone()), eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_, _| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = playlist_svc
                    .search_playlists_by_name(&params, req)
                    .await
                    .expect("failed to get playlists");
                assert_eq!(page, expected);
            }
        }

        mod start_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let msg = PlaylistMessage {
                    id: Uuid::new_v4(),
                    kind: PlaylistMessageKind::Sync,
                };
                let mut publisher = MockPublisher::new();
                publisher
                    .expect_publish_playlist_message()
                    .with(eq(msg.clone()))
                    .times(1)
                    .returning(|_| Ok(()));
                let broker = MockBrokerClient {
                    publisher,
                    ..Default::default()
                };
                let playlist_svc = DefaultPlaylistService {
                    broker: Arc::new(broker),
                    db: Arc::new(MockDatabasePool::default()),
                    spotify: Arc::new(MockSpotifyClient::default()),
                    _csm: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                playlist_svc
                    .start_synchronization(msg.id)
                    .await
                    .expect("failed to start synchronization");
            }
        }
    }
}
