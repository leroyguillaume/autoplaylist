use std::{
    io::stdout,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::TryFromIntError,
    sync::Arc,
};

use autoplaylist_common::{
    api::{
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, JwtResponse,
        PageRequestQueryParams, PlaylistResponse, RedirectUriQueryParam, PATH_ADMIN,
        PATH_AUTH_SPOTIFY, PATH_AUTH_SPOTIFY_TOKEN, PATH_HEALTH, PATH_PLAYLIST, PATH_SRC,
        PATH_SYNC,
    },
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConfig, RabbitMqConsumer},
        BrokerError,
    },
    db::{
        pg::{PostgresConfig, PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseError,
    },
    model::Role,
    sigs::TerminationSignalListener,
    spotify::{
        rspotify::{RSpotifyClient, RSpotifyConfig},
        SpotifyError,
    },
    TracingConfig,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing, Json, Router, Server,
};
use mockable::{DefaultClock, DefaultEnv, Env};
use thiserror::Error;
use tower_http::{
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{debug, error, info, info_span, Instrument, Level};
use uuid::Uuid;

use crate::{
    auth::{AuthService, DefaultAuthService, DefaultJwtProvider, JwtConfig},
    playlist::{DefaultPlaylistService, PlaylistService},
    src::{DefaultSourceService, SourceService},
};

// main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = DefaultEnv;
    TracingConfig::new("autoplaylist-api", stdout).init(&env);
    let term = TerminationSignalListener::init()?;
    let db_cfg = PostgresConfig::from_env(&env)?;
    let db = Arc::new(PostgresPool::init(db_cfg).await?);
    let broker_cfg = RabbitMqConfig::from_env(&env);
    let broker = Arc::new(RabbitMqClient::init(broker_cfg).await?);
    let spotify_cfg = RSpotifyConfig::from_env(&env)?;
    let spotify = Arc::new(RSpotifyClient::new(spotify_cfg));
    let jwt_cfg = JwtConfig::from_env(&env)?;
    let auth_svc = DefaultAuthService::init(jwt_cfg, db.clone(), spotify.clone())?;
    let playlist_svc = DefaultPlaylistService::new(broker.clone(), db, spotify);
    let src_svc = DefaultSourceService::new(broker);
    let svc = Arc::new(DefaultServices {
        auth: auth_svc,
        playlist: playlist_svc,
        src: src_svc,
    });
    let app = create_app(svc);
    let addr = env
        .socket_addr("SERVER_ADDR")
        .unwrap_or(Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            8000,
        ))))?;
    info!(server.addr = %addr, "server started");
    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(term)
        .await?;
    info!("server stopped");
    Ok(())
}

// Macros

macro_rules! authenticated_admin {
    ($auth:expr, $headers:expr) => {{
        let usr = authenticated_user!($auth, $headers);
        if usr.role != Role::Admin {
            return handle_error(ServiceError::Forbidden);
        }
        usr
    }};
}

macro_rules! authenticated_user {
    ($auth:expr, $headers:expr) => {
        match $auth.authenticated_user($headers).await {
            Ok(usr) => usr,
            Err(err) => return handle_error(err),
        }
    };
}

// Types

type ServiceResult<T> = Result<T, ServiceError>;

// ServiceError

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("broker error: {0}")]
    Broker(
        #[from]
        #[source]
        BrokerError,
    ),
    #[error("failed to cast integer: {0}")]
    Cast(
        #[from]
        #[source]
        TryFromIntError,
    ),
    #[error("database error: {0}")]
    Database(
        #[from]
        #[source]
        DatabaseError,
    ),
    #[error("user doesn't habe enough permissions")]
    Forbidden,
    #[error("failed to generate JWT: {0}")]
    JwtGeneration(
        #[from]
        #[source]
        jwt::Error,
    ),
    #[error("user {0} doesn't have Sotify credentials")]
    NoSpotifyCredentials(Uuid),
    #[error("regex compilation error: {0}")]
    RegexCompilation(
        #[from]
        #[source]
        regex::Error,
    ),
    #[error("Spotify error: {0}")]
    Spotify(
        #[from]
        #[source]
        SpotifyError,
    ),
    #[error("user is not authenticated")]
    Unauthorized,
}

// Services

trait Services: Send + Sync {
    fn auth(&self) -> &dyn AuthService;

    fn playlist(&self) -> &dyn PlaylistService;

    fn source(&self) -> &dyn SourceService;
}

// DefaultServices

struct DefaultServices<'a> {
    auth: DefaultAuthService<
        PostgresConnection,
        PostgresTransaction<'a>,
        PostgresPool,
        DefaultJwtProvider<DefaultClock>,
        RSpotifyClient,
    >,
    playlist: DefaultPlaylistService<
        RabbitMqConsumer,
        RabbitMqClient,
        PostgresConnection,
        PostgresTransaction<'a>,
        PostgresPool,
        RSpotifyClient,
    >,
    src: DefaultSourceService<RabbitMqConsumer, RabbitMqClient>,
}

impl Services for DefaultServices<'_> {
    fn auth(&self) -> &dyn AuthService {
        &self.auth
    }

    fn playlist(&self) -> &dyn PlaylistService {
        &self.playlist
    }

    fn source(&self) -> &dyn SourceService {
        &self.src
    }
}

// create_app

#[inline]
fn create_app<SVC: Services + 'static>(svc: Arc<SVC>) -> Router {
    let trace_lvl = Level::INFO;
    let lat_unit = LatencyUnit::Millis;
    let mk_span = DefaultMakeSpan::new().level(trace_lvl);
    let on_resp = DefaultOnResponse::new()
        .latency_unit(lat_unit)
        .level(trace_lvl);
    let on_fail = DefaultOnFailure::new()
        .latency_unit(lat_unit)
        .level(trace_lvl);
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(mk_span)
        .on_response(on_resp)
        .on_failure(on_fail);
    Router::new()
    .route(&format!("{PATH_ADMIN}{PATH_PLAYLIST}"), routing::get(|headers: HeaderMap, State(svc): State<Arc<SVC>>, Query(params): Query<PageRequestQueryParams<25>>| async move {
        let usr = authenticated_admin!(svc.auth(), &headers);
        let span = info_span!("playlists", params.limit, params.offset, usr.email, %usr.id);
        async {
            match svc.playlist().playlists(params.into()).await {
                Ok(page) => {
                    let resp = page.map(PlaylistResponse::from);
                    (StatusCode::OK, Json(resp)).into_response()
                },
                Err(err) => handle_error(err),
            }
        }
        .instrument(span)
        .await
    }))
        .route(
            PATH_AUTH_SPOTIFY,
            routing::get(
                |Query(params): Query<RedirectUriQueryParam>,
                State(svc): State<Arc<SVC>>| async move {
                    let span =
                        info_span!("spotify_authorize_url", params.redirect_uri);
                    async {
                        let res = svc
                            .auth()
                            .spotify_authorize_url(&params);
                        match res {
                            Ok(url) => {
                                ([(header::LOCATION, url)], StatusCode::MOVED_PERMANENTLY).into_response()
                            }
                            Err(err) => handle_error(err),
                        }
                    }
                    .instrument(span)
                    .await
                },
            ),
        )
        .route(
            PATH_AUTH_SPOTIFY_TOKEN,
            routing::get(
                |Query(params): Query<AuthenticateViaSpotifyQueryParams>,
                 State(svc): State<Arc<SVC>>| async move {
                    let span =
                        info_span!("authenticate_via_spotify", params.code, params.redirect_uri);
                    async {
                        let res = svc
                            .auth()
                            .authenticate_via_spotify(&params)
                            .await;
                        match res {
                            Ok(jwt) => {
                                (StatusCode::OK, Json(JwtResponse::from(jwt))).into_response()
                            }
                            Err(err) => handle_error(err),
                        }
                    }
                    .instrument(span)
                    .await
                },
            ),
        )
        .route(
            PATH_HEALTH,
            routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        .route(PATH_PLAYLIST, routing::get(|headers: HeaderMap, State(svc): State<Arc<SVC>>, Query(params): Query<PageRequestQueryParams<25>>| async move {
            let usr = authenticated_user!(svc.auth(), &headers);
            let span = info_span!("authenticated_user_playlists", params.limit, params.offset, usr.email, %usr.id);
            async {
                match svc.playlist().authenticated_user_playlists(usr.id, params.into()).await {
                    Ok(page) => {
                        let resp = page.map(PlaylistResponse::from);
                        (StatusCode::OK, Json(resp)).into_response()
                    },
                    Err(err) => handle_error(err),
                }
            }
            .instrument(span)
            .await
        }))
        .route(PATH_PLAYLIST, routing::post(|headers: HeaderMap, State(svc): State<Arc<SVC>>, Json(req): Json<CreatePlaylistRequest>| async move {
            let usr = authenticated_user!(svc.auth(), &headers);
            let span = info_span!(
                "create_playlist",
                playlist.name = req.name,
                playlist.platform = %req.platform,
                usr.email,
                %usr.id
            );
            async {
                match svc.playlist().create(req, usr).await {
                    Ok(playlist) => {
                        let resp = PlaylistResponse::from(playlist);
                        (StatusCode::CREATED, Json(resp)).into_response()
                    },
                    Err(err) => handle_error(err),
                }
            }
            .instrument(span)
            .await
        }))
        .route(&format!("{PATH_PLAYLIST}/:id{PATH_SYNC}"), routing::put(|Path(id): Path<Uuid>, headers: HeaderMap, State(svc): State<Arc<SVC>>,| async move {
            let usr = authenticated_admin!(svc.auth(), &headers);
            let span = info_span!("start_playlist_synchronization", playlist.id = %id, usr.email, %usr.id);
            async {
                match svc.playlist().start_synchronization(id).await {
                    Ok(_) => StatusCode::NO_CONTENT.into_response(),
                    Err(err) => handle_error(err),
                }
            }
            .instrument(span)
            .await
        }))
        .route(&format!("{PATH_SRC}/:id{PATH_SYNC}"), routing::put(|Path(id): Path<Uuid>, headers: HeaderMap, State(svc): State<Arc<SVC>>,| async move {
            let usr = authenticated_admin!(svc.auth(), &headers);
            let span = info_span!("start_source_synchronization", src.id = %id, usr.email, %usr.id);
            async {
                match svc.source().start_synchronization(id).await {
                    Ok(_) => StatusCode::NO_CONTENT.into_response(),
                    Err(err) => handle_error(err),
                }
            }
            .instrument(span)
            .await
        }))
        .layer(trace_layer)
        .with_state(svc)
}

// handle_error

#[inline]
fn handle_error(err: ServiceError) -> Response {
    match err {
        ServiceError::Forbidden => {
            debug!(details = %err, "user doesn't have enough permissions");
            StatusCode::FORBIDDEN.into_response()
        }
        ServiceError::NoSpotifyCredentials(_) => {
            debug!(details = %err, "user doesn't have Spotify credentials");
            StatusCode::PRECONDITION_FAILED.into_response()
        }
        ServiceError::Unauthorized => {
            debug!(details = %err, "user is not authenticated");
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => {
            error!(details = %err, "unexpected error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// Mods

mod auth;
mod playlist;
mod src;

// Tests

#[cfg(test)]
mod test {
    use std::io::stderr;

    use autoplaylist_common::{
        api::Platform,
        model::{
            Page, PageRequest, Playlist, Predicate, Role, Source, SourceKind, SpotifyResourceKind,
            Synchronization, Target, User,
        },
    };
    use axum_test::{TestResponse, TestServer};
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;

    use crate::{auth::MockAuthService, playlist::MockPlaylistService, src::MockSourceService};

    use super::*;

    // MockServices

    #[derive(Default)]
    struct MockServices {
        auth: MockAuthService,
        playlist: MockPlaylistService,
        src: MockSourceService,
    }

    impl Services for MockServices {
        fn auth(&self) -> &dyn AuthService {
            &self.auth
        }

        fn playlist(&self) -> &dyn PlaylistService {
            &self.playlist
        }

        fn source(&self) -> &dyn SourceService {
            &self.src
        }
    }

    // init

    fn init(svc: MockServices) -> TestServer {
        TracingConfig::new("autoplaylist-api", stderr).init(&DefaultEnv);
        let app = create_app(Arc::new(svc));
        TestServer::new(app.into_make_service()).expect("failed to initialize server")
    }

    // Mods

    mod authenticate_via_spotify {
        use super::*;

        // Tests

        #[tokio::test]
        async fn ok() {
            let params = AuthenticateViaSpotifyQueryParams {
                code: "code".into(),
                redirect_uri: "redirect_uri".into(),
            };
            let expected = JwtResponse { jwt: "jwt".into() };
            let mut auth = MockAuthService::new();
            auth.expect_authenticate_via_spotify()
                .with(eq(params.clone()))
                .returning({
                    let jwt = expected.jwt.clone();
                    move |_| Ok(jwt.clone())
                });
            let svc = MockServices {
                auth,
                ..Default::default()
            };
            let server = init(svc);
            let resp = server
                .get(PATH_AUTH_SPOTIFY_TOKEN)
                .add_query_params(&params)
                .await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod authenticated_user_playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            authenticated_usr: Mock<ServiceResult<User>, User>,
            authenticated_usr_playlists: Mock<Page<Playlist>, Page<Playlist>>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthService::new();
            auth.expect_authenticated_user()
                .times(mocks.authenticated_usr.times())
                .returning({
                    let mock = mocks.authenticated_usr.clone();
                    let usr = usr.clone();
                    move |_| mock.call_with_args(usr.clone())
                });
            let mut playlist = MockPlaylistService::new();
            playlist
                .expect_authenticated_user_playlists()
                .with(eq(usr.id), eq(page.req))
                .times(mocks.authenticated_usr_playlists.times())
                .returning({
                    let mock = mocks.authenticated_usr_playlists.clone();
                    let page = page.clone();
                    move |_, _| Ok(mock.call_with_args(page.clone()))
                });
            let svc = MockServices {
                auth,
                playlist,
                ..Default::default()
            };
            let server = init(svc);
            let req = PageRequestQueryParams::<25>::from(page.req);
            let resp = server.get(PATH_PLAYLIST).add_query_params(req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(|_| Err(ServiceError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(Ok),
                authenticated_usr_playlists: Mock::once_with_args(|page| page),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod create_playlist {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            authenticated_usr: Mock<ServiceResult<User>, User>,
            create_playlist: Mock<ServiceResult<Playlist>, Playlist>,
        }

        // run

        async fn run(mocks: Mocks) -> (TestResponse, PlaylistResponse) {
            let req = CreatePlaylistRequest {
                name: "name".into(),
                platform: Platform::Spotify,
                predicate: Predicate::YearEquals(1993),
                src: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: req.name.clone(),
                predicate: req.predicate.clone(),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: req.src.clone(),
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
            let expected = PlaylistResponse::from(playlist.clone());
            let mut auth_svc = MockAuthService::new();
            auth_svc.expect_authenticated_user().times(1).returning({
                let usr = playlist.src.owner.clone();
                let mock = mocks.authenticated_usr.clone();
                move |_| mock.call_with_args(usr.clone())
            });
            let mut playlist_svc = MockPlaylistService::new();
            playlist_svc
                .expect_create()
                .with(eq(req.clone()), eq(playlist.src.owner.clone()))
                .times(mocks.create_playlist.times())
                .returning({
                    let playlist = playlist.clone();
                    let mock = mocks.create_playlist.clone();
                    move |_, _| mock.call_with_args(playlist.clone())
                });
            let svc = MockServices {
                auth: auth_svc,
                playlist: playlist_svc,
                ..Default::default()
            };
            let server = init(svc);
            let resp = server.post(PATH_PLAYLIST).json(&req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(|_| Err(ServiceError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn precondition_failed() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(Ok),
                create_playlist: Mock::once_with_args(|playlist: Playlist| {
                    Err(ServiceError::NoSpotifyCredentials(playlist.src.owner.id))
                }),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::PRECONDITION_FAILED);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn playlist() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(Ok),
                create_playlist: Mock::once_with_args(Ok),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::CREATED);
            resp.assert_json(&expected);
        }
    }

    mod health {
        use super::*;

        // Tests

        #[tokio::test]
        async fn no_content() {
            let server = init(Default::default());
            let resp = server.get(PATH_HEALTH).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            authenticated_usr: Mock<ServiceResult<User>>,
            playlists: Mock<Page<Playlist>, Page<Playlist>>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthService::new();
            auth.expect_authenticated_user()
                .times(mocks.authenticated_usr.times())
                .returning({
                    let mock = mocks.authenticated_usr.clone();
                    move |_| mock.call()
                });
            let mut playlist = MockPlaylistService::new();
            playlist
                .expect_playlists()
                .with(eq(page.req))
                .times(mocks.playlists.times())
                .returning({
                    let mock = mocks.playlists.clone();
                    let page = page.clone();
                    move |_| Ok(mock.call_with_args(page.clone()))
                });
            let svc = MockServices {
                auth,
                playlist,
                ..Default::default()
            };
            let server = init(svc);
            let req = PageRequestQueryParams::<25>::from(page.req);
            let resp = server
                .get(&format!("{PATH_ADMIN}{PATH_PLAYLIST}"))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                authenticated_usr: Mock::once_with_args(|_| Err(ServiceError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    })
                }),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                    })
                }),
                playlists: Mock::once_with_args(|page| page),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod spotify_authorize_url {
        use super::*;

        // Tests

        #[tokio::test]
        async fn moved_permanently() {
            let expected = "url";
            let param = RedirectUriQueryParam {
                redirect_uri: "redirect_uri".into(),
            };
            let mut auth = MockAuthService::new();
            auth.expect_spotify_authorize_url()
                .with(eq(param.clone()))
                .times(1)
                .returning(|_| Ok(expected.into()));
            let svc = MockServices {
                auth,
                ..Default::default()
            };
            let server = init(svc);
            let resp = server.get(PATH_AUTH_SPOTIFY).add_query_params(&param).await;
            resp.assert_status(StatusCode::MOVED_PERMANENTLY);
            let loc = resp.header(header::LOCATION);
            let url = loc.to_str().expect("failed to decode header");
            assert_eq!(url, expected);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod start_playlist_synchronization {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            authenticated_usr: Mock<ServiceResult<User>>,
            start_sync: Mock<()>,
        }

        // run

        async fn run(mocks: Mocks) -> TestResponse {
            let id = Uuid::new_v4();
            let mut auth_svc = MockAuthService::new();
            auth_svc.expect_authenticated_user().times(1).returning({
                let mock = mocks.authenticated_usr.clone();
                move |_| mock.call()
            });
            let mut playlist_svc = MockPlaylistService::new();
            playlist_svc
                .expect_start_synchronization()
                .with(eq(id))
                .times(mocks.start_sync.times())
                .returning(|_| Ok(()));
            let svc = MockServices {
                auth: auth_svc,
                playlist: playlist_svc,
                ..Default::default()
            };
            let server = init(svc);
            server
                .put(&format!("{PATH_PLAYLIST}/{id}{PATH_SYNC}"))
                .await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| Err(ServiceError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    })
                }),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                    })
                }),
                start_sync: Mock::once(|| ()),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod start_source_synchronization {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            authenticated_usr: Mock<ServiceResult<User>>,
            start_sync: Mock<()>,
        }

        // run

        async fn run(mocks: Mocks) -> TestResponse {
            let id = Uuid::new_v4();
            let mut auth_svc = MockAuthService::new();
            auth_svc.expect_authenticated_user().times(1).returning({
                let mock = mocks.authenticated_usr.clone();
                move |_| mock.call()
            });
            let mut src_svc = MockSourceService::new();
            src_svc
                .expect_start_synchronization()
                .with(eq(id))
                .times(mocks.start_sync.times())
                .returning(|_| Ok(()));
            let svc = MockServices {
                auth: auth_svc,
                src: src_svc,
                ..Default::default()
            };
            let server = init(svc);
            server.put(&format!("{PATH_SRC}/{id}{PATH_SYNC}")).await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| Err(ServiceError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    })
                }),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content() {
            let mocks = Mocks {
                authenticated_usr: Mock::once(|| {
                    Ok(User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                    })
                }),
                start_sync: Mock::once(|| ()),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }
}
