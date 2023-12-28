use std::{
    future::Future,
    io::stdout,
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::TryFromIntError,
    sync::Arc,
};

use autoplaylist_common::{
    api::{
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, PageRequestQueryParams,
        PreconditionFailedResponse, RedirectUriQueryParam, SearchQueryParam, UpdatePlaylistRequest,
        UpdateTrackRequest, UpdateUserRequest, ValidationErrorResponse, PATH_AUTH, PATH_HEALTH,
        PATH_PLAYLIST, PATH_REFRESH, PATH_SPOTIFY, PATH_SRC, PATH_SYNC, PATH_TOKEN, PATH_TRACK,
        PATH_USR,
    },
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConfig},
        BrokerClient, BrokerError,
    },
    db::{
        pg::{PostgresConfig, PostgresPool},
        DatabaseConnection, DatabaseError, DatabasePool, DatabaseTransaction,
    },
    sigs::TerminationSignalListener,
    spotify::{
        rspotify::{RSpotifyClient, RSpotifyConfig},
        SpotifyClient, SpotifyError,
    },
    TracingConfig,
};
use axum::{
    extract::{Path, Query, State},
    http::{header::InvalidHeaderValue, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing, Json, Router, Server,
};
use mockable::{DefaultClock, DefaultEnv, Env};
use thiserror::Error;
use tower_http::{
    cors::{self, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{debug, error, info, Level};
use uuid::Uuid;

use crate::{
    auth::{Authenticator, DefaultAuthenticator},
    conv::{Converter, DefaultConverter},
    handler::*,
    jwt::{DefaultJwtProvider, JwtConfig, JwtProvider},
    pull::{DefaultPlaylistsPuller, PlaylistsPuller},
};

// main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = DefaultEnv;
    TracingConfig::new("autoplaylist-api", stdout).init(&env);
    let term = TerminationSignalListener::init()?;
    let db_cfg = PostgresConfig::from_env(&env)?;
    let broker_cfg = RabbitMqConfig::from_env(&env);
    let spotify_cfg = RSpotifyConfig::from_env(&env)?;
    let jwt_cfg = JwtConfig::from_env(&env)?;
    let jwt_prov = DefaultJwtProvider::new(jwt_cfg);
    let svc = DefaultServices {
        auth: DefaultAuthenticator::new(jwt_prov),
        broker: RabbitMqClient::init(broker_cfg).await?,
        conv: DefaultConverter,
        spotify: RSpotifyClient::new(spotify_cfg),
        playlists_puller: DefaultPlaylistsPuller,
    };
    let state = Arc::new(AppState {
        db: PostgresPool::init(db_cfg).await?,
        svc,
        _dbconn: PhantomData,
        _dbtx: PhantomData,
    });
    let origins = env
        .strings(ENV_VAR_KEY_ALLOWED_ORIGINS, ",")
        .unwrap_or_default()
        .into_iter()
        .map(|origin| origin.parse())
        .collect::<Result<Vec<HeaderValue>, InvalidHeaderValue>>()?;
    let app = create_app(state, origins);
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

macro_rules! ensure_user_is_admin {
    ($usr:expr) => {
        if $usr.role != autoplaylist_common::model::Role::Admin {
            return Err(crate::ApiError::Forbidden);
        }
    };
}

macro_rules! ensure_user_is_admin_or_itself {
    ($usr:expr, $id:expr) => {
        if $usr.role != autoplaylist_common::model::Role::Admin && $usr.id != $id {
            return Err(crate::ApiError::Forbidden);
        }
    };
}

macro_rules! ensure_user_is_admin_or_owner {
    ($usr:expr, $owner:expr) => {
        if $usr.role != autoplaylist_common::model::Role::Admin && $usr.id != $owner.id {
            return Err(crate::ApiError::Forbidden);
        }
    };
}

// Consts - Env var keys

const ENV_VAR_KEY_ALLOWED_ORIGINS: &str = "CORS_ALLOWED_ORIGINS";

// Types

type ApiResult<T> = Result<T, ApiError>;

// ApiError

#[derive(Debug, Error)]
pub enum ApiError {
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
    #[error("failed to encode JWT: {0}")]
    JwtEncoding(
        #[from]
        #[source]
        jsonwebtoken::errors::Error,
    ),
    #[error("user doesn't have Sotify credentials")]
    NoSpotifyCredentials,
    #[error("resource doesn't exist")]
    NotFound,
    #[error("regex compilation error: {0}")]
    RegexCompilation(
        #[from]
        #[source]
        regex::Error,
    ),
    #[error("failed to serialize JSON: {0}")]
    Serialization(
        #[from]
        #[source]
        serde_json::Error,
    ),
    #[error("synchronization is running")]
    SynchronizationIsRunning,
    #[error("Spotify error: {0}")]
    Spotify(
        #[from]
        #[source]
        SpotifyError,
    ),
    #[error("user is not authenticated")]
    Unauthorized,
    #[error("invalid request")]
    Validation(ValidationErrorResponse),
}

impl From<ValidationErrorResponse> for ApiError {
    fn from(resp: ValidationErrorResponse) -> Self {
        Self::Validation(resp)
    }
}

// AppState

pub struct AppState<
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    SVC: Services,
> {
    db: DB,
    svc: SVC,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
}

// Services

pub trait Services: Send + Sync {
    fn auth(&self) -> &dyn Authenticator;

    fn broker(&self) -> &dyn BrokerClient;

    fn converter(&self) -> &dyn Converter;

    fn jwt(&self) -> &dyn JwtProvider;

    fn playlists_puller(&self) -> &dyn PlaylistsPuller;

    fn spotify(&self) -> &dyn SpotifyClient;
}

// DefaultServices

pub struct DefaultServices {
    auth: DefaultAuthenticator<DefaultJwtProvider<DefaultClock>>,
    broker: RabbitMqClient,
    conv: DefaultConverter,
    playlists_puller: DefaultPlaylistsPuller,
    spotify: RSpotifyClient,
}

impl Services for DefaultServices {
    fn auth(&self) -> &dyn Authenticator {
        &self.auth
    }

    fn broker(&self) -> &dyn BrokerClient {
        &self.broker
    }

    fn converter(&self) -> &dyn Converter {
        &self.conv
    }

    fn jwt(&self) -> &dyn JwtProvider {
        &self.auth.0
    }

    fn playlists_puller(&self) -> &dyn PlaylistsPuller {
        &self.playlists_puller
    }

    fn spotify(&self) -> &dyn SpotifyClient {
        &self.spotify
    }
}

// create_app

#[inline]
fn create_app<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    state: Arc<AppState<DBCONN, DBTX, DB, SVC>>,
    origins: Vec<HeaderValue>,
) -> Router {
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
    let cors_layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_origin(origins)
        .allow_headers(cors::Any);
    Router::new()
        // spotify_authorize_url
        .route(
            &format!("{PATH_AUTH}{PATH_SPOTIFY}"),
            routing::get(
                |Query(params): Query<RedirectUriQueryParam>,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    spotify_authorize_url(params, state.as_ref()).await
                },
            ),
        )
        // authenticate_via_spotify
        .route(
            &format!("{PATH_AUTH}{PATH_SPOTIFY}{PATH_TOKEN}"),
            routing::get(
                |Query(params): Query<AuthenticateViaSpotifyQueryParams>,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    authenticate_via_spotify(params, state.as_ref()).await
                },
            ),
        )
        // health
        .route(
            PATH_HEALTH,
            routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        // playlists
        .route(
            PATH_PLAYLIST,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    playlists(
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // create_playlist
        .route(
            PATH_PLAYLIST,
            routing::post(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Json(req): Json<CreatePlaylistRequest>| async move {
                    create_playlist(&headers, req, state.as_ref()).await
                },
            ),
        )
        // delete_playlist
        .route(
            &format!("{PATH_PLAYLIST}/:id"),
            routing::delete(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    delete_playlist(id, &headers, state.as_ref()).await
                },
            ),
        )
        // playlist_by_id
        .route(
            &format!("{PATH_PLAYLIST}/:id"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    playlist_by_id(id, &headers, state.as_ref()).await
                },
            ),
        )
        // update_playlist
        .route(
            &format!("{PATH_PLAYLIST}/:id"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Json(req): Json<UpdatePlaylistRequest>| async move {
                    update_playlist(id, &headers, req, state.as_ref()).await
                },
            ),
        )
        // start_playlist_synchronization
        .route(
            &format!("{PATH_PLAYLIST}/:id{PATH_SYNC}"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    start_playlist_synchronization(id, &headers, state.as_ref()).await
                },
            ),
        )
        // playlist_tracks
        .route(
            &format!("{PATH_PLAYLIST}/:id{PATH_TRACK}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    playlist_tracks(
                        id,
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // sources
        .route(
            PATH_SRC,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                    sources(&headers, req, state.as_ref()).await
                },
            ),
        )
        // source_by_id
        .route(
            &format!("{PATH_SRC}/:id"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    source_by_id(id, &headers, state.as_ref()).await
                },
            ),
        )
        // source_tracks
        .route(
            &format!("{PATH_SRC}/:id{PATH_TRACK}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    source_tracks(
                        id,
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // start_source_synchronization
        .route(
            &format!("{PATH_SRC}/:id{PATH_SYNC}"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    start_source_synchronization(id, &headers, state.as_ref()).await
                },
            ),
        )
        // tracks
        .route(
            PATH_TRACK,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    tracks(
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // track_by_id
        .route(
            &format!("{PATH_TRACK}/:id"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    track_by_id(id, &headers, state.as_ref()).await
                },
            ),
        )
        // update_track
        .route(
            &format!("{PATH_TRACK}/:id"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Json(req): Json<UpdateTrackRequest>| async move {
                    update_track(id, &headers, req, state.as_ref()).await
                },
            ),
        )
        // delete_track
        .route(
            &format!("{PATH_TRACK}/:id"),
            routing::delete(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    delete_track(id, &headers, state.as_ref()).await
                },
            ),
        )
        // users
        .route(
            PATH_USR,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    users(
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // user_by_id
        .route(
            &format!("{PATH_USR}/:id"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    user_by_id(id, &headers, state.as_ref()).await
                },
            ),
        )
        // update_user
        .route(
            &format!("{PATH_USR}/:id"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Json(req): Json<UpdateUserRequest>| async move {
                    update_user(id, &headers, req, state.as_ref()).await
                },
            ),
        )
        // delete_user
        .route(
            &format!("{PATH_USR}/:id"),
            routing::delete(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    delete_user(id, &headers, state.as_ref()).await
                },
            ),
        )
        // user_playlists
        .route(
            &format!("{PATH_USR}/:id{PATH_PLAYLIST}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    user_playlists(
                        id,
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // user_spotify_playlists
        .route(
            &format!("{PATH_USR}/:id{PATH_PLAYLIST}{PATH_SPOTIFY}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>,
                 params: Option<Query<SearchQueryParam>>| async move {
                    user_spotify_playlists(
                        id,
                        &headers,
                        req,
                        params.map(|Query(params)| params),
                        state.as_ref(),
                    )
                    .await
                },
            ),
        )
        // refresh_user_spotify_playlists
        .route(
            &format!("{PATH_USR}/:id{PATH_PLAYLIST}{PATH_SPOTIFY}{PATH_REFRESH}"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    refresh_user_spotify_playlists(id, &headers, state.as_ref()).await
                },
            ),
        )
        // user_sources
        .route(
            &format!("{PATH_USR}/:id{PATH_SRC}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                    user_sources(id, &headers, req, state.as_ref()).await
                },
            ),
        )
        .layer(trace_layer)
        .layer(cors_layer)
        .with_state(state)
}

// handle_error

#[inline]
async fn handling_error<RESP: IntoResponse, FUT: Future<Output = ApiResult<RESP>>>(
    f: FUT,
) -> Response {
    match f.await {
        Ok(resp) => resp.into_response(),
        Err(err) => match err {
            ApiError::Forbidden => {
                debug!(details = %err, "user doesn't have enough permissions");
                StatusCode::FORBIDDEN.into_response()
            }
            ApiError::NoSpotifyCredentials => {
                debug!(details = %err, "user doesn't have Spotify credentials");
                let resp = PreconditionFailedResponse {
                    details: err.to_string(),
                };
                (StatusCode::PRECONDITION_FAILED, Json(resp)).into_response()
            }
            ApiError::NotFound => {
                debug!(details = %err, "resource doesn't exist");
                StatusCode::NOT_FOUND.into_response()
            }
            ApiError::SynchronizationIsRunning => {
                debug!(details = %err, "synchronization is running");
                let resp = PreconditionFailedResponse {
                    details: err.to_string(),
                };
                (StatusCode::PRECONDITION_FAILED, Json(resp)).into_response()
            }
            ApiError::Unauthorized => {
                debug!(details = %err, "user is not authenticated");
                StatusCode::UNAUTHORIZED.into_response()
            }
            ApiError::Validation(resp) => {
                debug!("request is invalid");
                (StatusCode::BAD_REQUEST, Json(resp)).into_response()
            }
            _ => {
                error!(details = %err, "unexpected error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

// MockServices

#[cfg(test)]
#[derive(Default)]
pub struct MockServices {
    pub auth: auth::MockAuthenticator,
    pub broker: autoplaylist_common::broker::MockBrokerClient,
    pub conv: conv::MockConverter,
    pub playlists_puller: pull::MockPlaylistsPuller,
    pub jwt: jwt::MockJwtProvider,
    pub spotify: autoplaylist_common::spotify::MockSpotifyClient,
}

#[cfg(test)]
impl Services for MockServices {
    fn auth(&self) -> &dyn Authenticator {
        &self.auth
    }

    fn broker(&self) -> &dyn BrokerClient {
        &self.broker
    }

    fn converter(&self) -> &dyn Converter {
        &self.conv
    }

    fn playlists_puller(&self) -> &dyn PlaylistsPuller {
        &self.playlists_puller
    }

    fn jwt(&self) -> &dyn JwtProvider {
        &self.jwt
    }

    fn spotify(&self) -> &dyn SpotifyClient {
        &self.spotify
    }
}

// Mods

mod auth;
mod conv;
mod handler;
mod jwt;
mod pull;

// Tests

#[cfg(test)]
mod test {
    use std::io::stderr;

    use autoplaylist_common::db::{
        MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction,
    };
    use axum_test::TestServer;

    use super::*;

    // init

    pub fn init(
        state: AppState<
            MockDatabaseConnection,
            MockDatabaseTransaction,
            MockDatabasePool,
            MockServices,
        >,
    ) -> TestServer {
        TracingConfig::new("autoplaylist-api", stderr).init(&DefaultEnv);
        let app = create_app(Arc::new(state), vec![]);
        TestServer::new(app.into_make_service()).expect("failed to initialize server")
    }

    // AppState

    impl Default
        for AppState<
            MockDatabaseConnection,
            MockDatabaseTransaction,
            MockDatabasePool,
            MockServices,
        >
    {
        fn default() -> Self {
            Self {
                db: Default::default(),
                svc: Default::default(),
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            }
        }
    }

    // Mods

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
}
