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
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, JwtResponse,
        PageRequestQueryParams, PlaylistResponse, RedirectUriQueryParam, SearchQueryParam,
        SourceResponse, UserResponse, Validate, ValidationErrorResponse, PATH_AUTH, PATH_HEALTH,
        PATH_ME, PATH_PLAYLIST, PATH_SEARCH, PATH_SPOTIFY, PATH_SRC, PATH_SYNC, PATH_TOKEN,
        PATH_TRACK, PATH_USR,
    },
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConfig},
        BrokerClient, BrokerError, PlaylistMessage, PlaylistMessageKind, SourceMessage,
        SourceMessageKind,
    },
    db::{
        pg::{PostgresConfig, PostgresPool},
        DatabaseConnection, DatabaseError, DatabasePool, DatabaseTransaction, PlaylistCreation,
        SourceCreation, UserCreation,
    },
    model::{Credentials, Platform, Playlist, Role, SpotifyCredentials, Target},
    sigs::TerminationSignalListener,
    spotify::{
        rspotify::{RSpotifyClient, RSpotifyConfig},
        SpotifyClient, SpotifyError,
    },
    transactional, TracingConfig,
};
use axum::{
    extract::{Path, Query, State},
    http::{
        header::{self, InvalidHeaderValue},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
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
use tracing::{debug, error, info, info_span, Instrument, Level};
use uuid::Uuid;

use crate::{
    auth::{Authenticator, DefaultAuthenticator},
    jwt::{DefaultJwtProvider, JwtConfig, JwtProvider},
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
    let jwt_prov = DefaultJwtProvider::init(jwt_cfg)?;
    let svc = DefaultServices {
        auth: DefaultAuthenticator::new(jwt_prov),
        broker: RabbitMqClient::init(broker_cfg).await?,
        spotify: RSpotifyClient::new(spotify_cfg),
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
        if $usr.role != Role::Admin {
            return Err(ApiError::Forbidden);
        }
    };
}

macro_rules! ensure_user_is_admin_or_itself {
    ($usr:expr, $id:expr) => {
        if $usr.role != Role::Admin && $usr.id != $id {
            return Err(ApiError::Forbidden);
        }
    };
}

macro_rules! ensure_user_is_admin_or_owner {
    ($usr:expr, $owner:expr) => {
        if $usr.role != Role::Admin && $usr.id != $owner.id {
            return Err(ApiError::Forbidden);
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
    #[error("failed to generate JWT: {0}")]
    JwtGeneration(
        #[from]
        #[source]
        ::jwt::Error,
    ),
    #[error("user {0} doesn't have Sotify credentials")]
    NoSpotifyCredentials(Uuid),
    #[error("resource {0} doesn't exist")]
    NotFound(Uuid),
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
    #[error("invalid request")]
    Validation(ValidationErrorResponse),
}

impl From<ValidationErrorResponse> for ApiError {
    fn from(resp: ValidationErrorResponse) -> Self {
        Self::Validation(resp)
    }
}

// AppState

struct AppState<
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

trait Services: Send + Sync {
    fn auth(&self) -> &dyn Authenticator;

    fn broker(&self) -> &dyn BrokerClient;

    fn jwt(&self) -> &dyn JwtProvider;

    fn spotify(&self) -> &dyn SpotifyClient;
}

// DefaultServices

pub struct DefaultServices {
    auth: DefaultAuthenticator<DefaultJwtProvider<DefaultClock>>,
    broker: RabbitMqClient,
    spotify: RSpotifyClient,
}

impl Services for DefaultServices {
    fn auth(&self) -> &dyn Authenticator {
        &self.auth
    }

    fn broker(&self) -> &dyn BrokerClient {
        &self.broker
    }

    fn jwt(&self) -> &dyn JwtProvider {
        &self.auth.0
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
                    let span = info_span!("spotify_authorize_url", params.redirect_uri);
                    handling_error(async {
                        let url = state.svc.spotify().authorize_url(&params.redirect_uri)?;
                        Ok(([(header::LOCATION, url)], StatusCode::MOVED_PERMANENTLY))
                    })
                    .instrument(span)
                    .await
                },
            ),
        )
        // authenticate_via_spotify
        .route(
            &format!("{PATH_AUTH}{PATH_SPOTIFY}{PATH_TOKEN}"),
            routing::get(
                |Query(params): Query<AuthenticateViaSpotifyQueryParams>,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                    let span =
                        info_span!("authenticate_via_spotify", params.code, params.redirect_uri);
                    handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let spotify = state.svc.spotify();
                        let mut token = spotify
                            .authenticate(&params.code, &params.redirect_uri)
                            .await?;
                        let spotify_usr = spotify.authenticated_user(&mut token).await?;
                        let creds = SpotifyCredentials {
                            id: spotify_usr.id,
                            token,
                        };
                        let usr = db_conn.user_by_email(&spotify_usr.email).await?;
                        let (usr, created) = match usr {
                            Some(mut usr) => {
                                usr.creds.spotify = Some(creds);
                                db_conn.update_user(&usr).await?;
                                (usr, false)
                            }
                            None => {
                                let creation = UserCreation {
                                    creds: Credentials {
                                        spotify: Some(creds),
                                    },
                                    email: spotify_usr.email,
                                };
                                let usr = db_conn.create_user(&creation).await?;
                                info!(usr.email, %usr.id, "user created");
                                (usr, true)
                            }
                        };
                        let jwt = state.svc.jwt().generate(usr.id)?;
                        let resp = JwtResponse { jwt };
                        let status = if created {
                            StatusCode::CREATED
                        } else {
                            StatusCode::OK
                        };
                        Ok((status, Json(resp)))
                    })
                    .instrument(span)
                    .await
                },
            ),
        )
        // health
        .route(
            PATH_HEALTH,
            routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        // auth_user
        .route(
            PATH_ME,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                        );
                        async {
                            let resp = UserResponse::from(usr);
                            Ok((StatusCode::OK, Json(resp)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // delete_auth_user
        .route(
            PATH_ME,
            routing::delete(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "delete_auth_user",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                        );
                        async {
                            if db_conn.delete_user(usr.id).await? {
                                info!(usr.email, %usr.id, "user deleted");
                                Ok(StatusCode::NO_CONTENT)
                            } else {
                                Ok(StatusCode::UNAUTHORIZED)
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // auth_user_playlists
        .route(
            &format!("{PATH_ME}{PATH_PLAYLIST}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user_playlists",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            let page = db_conn
                                .user_playlists(usr.id, req.into())
                                .await?
                                .map(PlaylistResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // search_auth_user_playlists_by_name
        .route(
            &format!("{PATH_ME}{PATH_PLAYLIST}{PATH_SEARCH}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_auth_user_playlists_by_name",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            let page = db_conn
                                .search_user_playlists_by_name(usr.id, &params.q, req.into())
                                .await?
                                .map(PlaylistResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }.instrument(span).await
                    })
                    .await
                },
            ),
        )
        // auth_user_sources
        .route(
            &format!("{PATH_ME}{PATH_SRC}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user_sources",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            let page = db_conn
                                .user_sources(usr.id, req.into())
                                .await?
                                .map(SourceResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // playlists
        .route(
            PATH_PLAYLIST,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                    handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlists",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            let page = db_conn
                                .playlists(req.into())
                                .await?
                                .map(PlaylistResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
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
                     handling_error(async {
                        req.validate()?;
                        let mut db_tx = state.db.begin().await?;
                        let mut usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_tx.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "create_playlist",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            playlist.name = req.name,
                            playlist.platform = %req.platform,
                        );
                        async {
                            let tgt = match req.platform {
                                Platform::Spotify => {
                                    let creds = usr
                                        .creds
                                        .spotify
                                        .as_mut()
                                        .ok_or(ApiError::NoSpotifyCredentials(usr.id))?;
                                    let id = state.svc.spotify().create_playlist(&req.name, creds).await?;
                                    Target::Spotify(id)
                                }
                            };
                            let (playlist, new_src) = transactional!(db_tx, async {
                                let src = db_tx.source_by_owner_kind(usr.id, &req.src).await?;
                                let (src, new_src) = match src {
                                    Some(src) => (src, false),
                                    None => {
                                        let creation = SourceCreation {
                                            kind: req.src,
                                            owner: usr,
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
                                Ok::<(Playlist, bool), ApiError>((playlist, new_src))
                            })?;
                            let broker = state.svc.broker();
                            if new_src {
                                let msg = SourceMessage {
                                    id: playlist.src.id,
                                    kind: SourceMessageKind::Created,
                                };
                                broker.publish_source_message(&msg).await?;
                            }
                            let msg = PlaylistMessage {
                                id: playlist.id,
                                kind: PlaylistMessageKind::Created,
                            };
                            broker.publish_playlist_message(&msg).await?;
                            Ok((StatusCode::CREATED, Json(PlaylistResponse::from(playlist))))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_tx = state.db.begin().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_tx.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "delete_playlist",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_tx.playlist_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            ensure_user_is_admin_or_owner!(usr, playlist.src.owner);
                            transactional!(db_tx, async {
                                let deleted = db_tx.delete_playlist(id).await?;
                                let src_count = db_tx.count_source_playlists(id).await?;
                                if src_count == 0 {
                                    db_tx.delete_source(playlist.src.id).await?;
                                    info!(%playlist.src.id, "source deleted");
                                }
                                if deleted {
                                    info!(%id, "playlist deleted");
                                    Ok(StatusCode::NO_CONTENT)
                                } else {
                                    Ok(StatusCode::NOT_FOUND)
                                }
                            })
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlist_by_id",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_conn.playlist_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            ensure_user_is_admin_or_owner!(usr, playlist.src.owner);
                            Ok((StatusCode::OK, Json(PlaylistResponse::from(playlist))))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // search_playlists_by_name
        .route(
            &format!("{PATH_PLAYLIST}{PATH_SEARCH}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_playlists_by_name",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            let page = db_conn
                                .search_playlists_by_name(&params.q, req.into())
                                .await?
                                .map(PlaylistResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "start_playlist_synchronization",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            playlist.id = %id,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            if db_conn.playlist_exists(id).await? {
                                let msg = PlaylistMessage {
                                    id,
                                    kind: PlaylistMessageKind::Sync,
                                };
                                state.svc.broker().publish_playlist_message(&msg).await?;
                                Ok(StatusCode::NO_CONTENT)
                            } else {
                                Ok(StatusCode::NOT_FOUND)
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlist_tracks",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_conn.playlist_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            ensure_user_is_admin_or_owner!(usr, playlist.src.owner);
                            let page = db_conn.playlist_tracks(id, req.into()).await?;
                            Ok((StatusCode::OK, Json(page)).into_response())
                        }
                        .instrument(span)
                        .await
                    })
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "sources",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            let page = db_conn.sources(req.into()).await?.map(SourceResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "source_tracks",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            src.id = %id,
                        );
                        async {
                            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            ensure_user_is_admin_or_owner!(usr, src.owner);
                            let page = db_conn.source_tracks(id, req.into()).await?;
                            Ok((StatusCode::OK, Json(page)).into_response())
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "source_by_id",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            src.id = %id,
                        );
                        async {
                            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            ensure_user_is_admin_or_owner!(usr, src.owner);
                            Ok((StatusCode::OK, Json(SourceResponse::from(src))))
                        }
                        .instrument(span)
                        .await
                    })
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "start_source_synchronization",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            src.id = %id,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            if db_conn.source_exists(id).await? {
                                let msg = SourceMessage {
                                    id,
                                    kind: SourceMessageKind::Sync,
                                };
                                state.svc.broker().publish_source_message(&msg).await?;
                                Ok(StatusCode::NO_CONTENT)
                            } else {
                                Ok(StatusCode::NOT_FOUND)
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // tracks
        .route(
            PATH_TRACK,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "tracks",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            let page = db_conn.tracks(req.into()).await?;
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "track_by_id",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            track.id = %id,
                        );
                        async {
                            let track = db_conn.track_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            Ok((StatusCode::OK, Json(track)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // users
        .route(
            PATH_USR,
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "users",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            let page = db_conn.users(req.into()).await?.map(UserResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "user_by_id",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(usr, id);
                            let usr = db_conn.user_by_id(id).await?.ok_or(ApiError::NotFound(id))?;
                            Ok((StatusCode::OK, Json(UserResponse::from(usr))))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "delete_user",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(usr, id);
                            let deleted = db_conn.delete_user(id).await?;
                            if deleted {
                                Ok(StatusCode::NO_CONTENT)
                            } else {
                                Ok(StatusCode::NOT_FOUND)
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "user_playlists",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(usr, id);
                            if db_conn.user_exists(id).await? {
                                let page = db_conn.user_playlists(id, req.into()).await?.map(PlaylistResponse::from);
                                Ok((StatusCode::OK, Json(page)).into_response())
                            } else {
                                Ok(StatusCode::NOT_FOUND.into_response())
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
                },
            ),
        )
        // search_users_by_email
        .route(
            &format!("{PATH_USR}{PATH_SEARCH}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_users_by_email",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            ensure_user_is_admin!(usr);
                            let page = db_conn
                                .search_users_by_email(&params.q, req.into())
                                .await?
                                .map(UserResponse::from);
                            Ok((StatusCode::OK, Json(page)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "user_sources",
                            auth.usr.email = %usr.email,
                            auth.usr.id = %usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(usr, id);
                            if db_conn.user_exists(id).await? {
                                let page = db_conn.user_sources(id, req.into()).await?.map(SourceResponse::from);
                                Ok((StatusCode::OK, Json(page)).into_response())
                            } else {
                                Ok(StatusCode::NOT_FOUND.into_response())
                            }
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
            ApiError::NoSpotifyCredentials(_) => {
                debug!(details = %err, "user doesn't have Spotify credentials");
                StatusCode::PRECONDITION_FAILED.into_response()
            }
            ApiError::NotFound(_) => {
                debug!(details = %err, "resource doesn't exist");
                StatusCode::NOT_FOUND.into_response()
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

// Mods

mod auth;
mod jwt;

// Tests

#[cfg(test)]
mod test {
    use std::{collections::HashMap, io::stderr};

    use autoplaylist_common::{
        api::ValidationErrorKind,
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Album, Page, PageRequest, Playlist, Predicate, Role, Source, SourceKind,
            SpotifySourceKind, SpotifyToken, Synchronization, Target, Track, User,
        },
        spotify::{MockSpotifyClient, SpotifyUser},
    };
    use axum_test::{TestResponse, TestServer};
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;

    use crate::{auth::MockAuthenticator, jwt::MockJwtProvider};

    use super::*;

    // MockServices

    #[derive(Default)]
    struct MockServices {
        auth: MockAuthenticator,
        broker: MockBrokerClient,
        jwt: MockJwtProvider,
        spotify: MockSpotifyClient,
    }

    impl Services for MockServices {
        fn auth(&self) -> &dyn Authenticator {
            &self.auth
        }

        fn broker(&self) -> &dyn BrokerClient {
            &self.broker
        }

        fn jwt(&self) -> &dyn JwtProvider {
            &self.jwt
        }

        fn spotify(&self) -> &dyn SpotifyClient {
            &self.spotify
        }
    }

    // init

    fn init(
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

    mod authenticate_via_spotify {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            create_usr: Mock<()>,
            update_usr: Mock<()>,
            usr_by_email: Mock<Option<User>, User>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, JwtResponse) {
            let params = AuthenticateViaSpotifyQueryParams {
                code: "code".into(),
                redirect_uri: "redirect_uri".into(),
            };
            let token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_usr = SpotifyUser {
                id: "id".into(),
                email: "user@test".into(),
            };
            let usr = User {
                creation: Utc::now(),
                creds: Credentials {
                    spotify: Some(SpotifyCredentials {
                        id: spotify_usr.id.clone(),
                        token: token.clone(),
                    }),
                },
                email: spotify_usr.email.clone(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = "jwt";
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_by_email()
                            .with(eq(usr.email.clone()))
                            .times(mocks.usr_by_email.times())
                            .returning({
                                let usr = usr.clone();
                                let mock = mocks.usr_by_email.clone();
                                move |_| Ok(mock.call_with_args(usr.clone()))
                            });
                        conn.0
                            .expect_update_user()
                            .with(eq(usr.clone()))
                            .times(mocks.update_usr.times())
                            .returning({
                                let mock = mocks.update_usr.clone();
                                move |_| {
                                    mock.call();
                                    Ok(())
                                }
                            });
                        let creation: UserCreation = usr.clone().into();
                        conn.0
                            .expect_create_user()
                            .with(eq(creation))
                            .times(mocks.create_usr.times())
                            .returning({
                                let usr = usr.clone();
                                move |_| Ok(usr.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_authenticate()
                .with(eq(params.code.clone()), eq(params.redirect_uri.clone()))
                .times(1)
                .returning({
                    let token = token.clone();
                    move |_, _| Ok(token.clone())
                });

            spotify
                .expect_authenticated_user()
                .with(eq(token.clone()))
                .times(1)
                .returning({
                    let usr = spotify_usr.clone();
                    move |_| Ok(usr.clone())
                });
            let mut jwt_prov = MockJwtProvider::new();
            jwt_prov
                .expect_generate()
                .with(eq(usr.id))
                .times(1)
                .returning(|_| Ok(expected.into()));
            let state = AppState {
                db,
                svc: MockServices {
                    jwt: jwt_prov,
                    spotify,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let expected = JwtResponse {
                jwt: expected.into(),
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_AUTH}{PATH_SPOTIFY}{PATH_TOKEN}"))
                .add_query_params(params)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn ok_when_user_was_created() {
            let mocks = Mocks {
                create_usr: Mock::once(|| ()),
                usr_by_email: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::CREATED);
            let resp = resp.json();
            assert_eq!(expected, resp);
        }

        #[tokio::test]
        async fn ok_when_user_didnt_exist() {
            let mocks = Mocks {
                update_usr: Mock::once(|| ()),
                usr_by_email: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp = resp.json();
            assert_eq!(expected, resp);
        }
    }

    mod authenticated_user {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, UserResponse) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = UserResponse::from(usr.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once(MockDatabaseConnection::new),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(PATH_ME).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod authenticated_user_playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            playlists: Mock<()>,
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
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_playlists()
                            .with(eq(usr.id), eq(page.req))
                            .times(mocks.playlists.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_ME}{PATH_PLAYLIST}"))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                playlists: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod authenticated_user_sources {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<SourceResponse>) {
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
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(SourceResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_sources()
                            .with(eq(usr.id), eq(page.req))
                            .times(mocks.srcs.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_ME}{PATH_SRC}"))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                srcs: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod create_playlist {
        use super::*;

        // Data

        struct Data {
            creds: SpotifyCredentials,
            req: CreatePlaylistRequest,
            usr_creds: Option<SpotifyCredentials>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            create_playlist: Mock<()>,
            create_spotify_playlist: Mock<()>,
            create_src: Mock<()>,
            publish_playlist_msg: Mock<()>,
            publish_src_msg: Mock<()>,
            src_by_owner_kind: Mock<Option<Source>, Source>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, PlaylistResponse) {
            let usr = User {
                creation: Utc::now(),
                creds: Credentials {
                    spotify: data.usr_creds,
                },
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
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
                    owner: usr.clone(),
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
                id: expected.id,
                kind: PlaylistMessageKind::Created,
            };
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_create_playlist()
                .with(eq(expected.name.clone()), eq(data.creds.clone()))
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
                            .times(mocks.create_playlist.times())
                            .returning({
                                let playlist = playlist.clone();
                                move |_| Ok(playlist.clone())
                            });
                        tx
                    }
                }),
                ..Default::default()
            };
            let mut broker = MockBrokerClient::new();
            broker
                .expect_publish_source_message()
                .with(eq(src_msg))
                .times(mocks.publish_src_msg.times())
                .returning(|_| Ok(()));
            broker
                .expect_publish_playlist_message()
                .with(eq(playlist_msg))
                .times(mocks.publish_playlist_msg.times())
                .returning(|_| Ok(()));
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    broker,
                    spotify,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let expected = PlaylistResponse::from(expected);
            let server = init(state);
            let resp = server.post(PATH_PLAYLIST).json(&data.req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn bad_request() {
            let creds = SpotifyCredentials {
                id: "id".into(),
                token: SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                },
            };
            let data = Data {
                creds: creds.clone(),
                req: CreatePlaylistRequest {
                    name: "".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks::default();
            let (resp, _) = run(data, mocks).await;
            resp.assert_status_bad_request();
            let expected = ValidationErrorResponse {
                errs: HashMap::from_iter(vec![(
                    "name".into(),
                    vec![ValidationErrorKind::Length(1, 100)],
                )]),
            };
            let resp: ValidationErrorResponse = resp.json();
            assert_eq!(resp, expected);
        }

        #[tokio::test]
        async fn unauthorized() {
            let creds = SpotifyCredentials {
                id: "id".into(),
                token: SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                },
            };
            let data = Data {
                creds: creds.clone(),
                req: CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_spotify_credentials() {
            let creds = SpotifyCredentials {
                id: "id".into(),
                token: SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                },
            };
            let data = Data {
                creds,
                req: CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::PRECONDITION_FAILED);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn created_when_source_didnt_exist() {
            let creds = SpotifyCredentials {
                id: "id".into(),
                token: SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                },
            };
            let data = Data {
                creds: creds.clone(),
                req: CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                create_playlist: Mock::once(|| ()),
                create_spotify_playlist: Mock::once(|| ()),
                create_src: Mock::once(|| ()),
                publish_playlist_msg: Mock::once(|| ()),
                publish_src_msg: Mock::once(|| ()),
                src_by_owner_kind: Mock::once_with_args(|_| None),
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status(StatusCode::CREATED);
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn created_when_source_was_created() {
            let creds = SpotifyCredentials {
                id: "id".into(),
                token: SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                },
            };
            let data = Data {
                creds: creds.clone(),
                req: CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                create_playlist: Mock::once(|| ()),
                create_spotify_playlist: Mock::once(|| ()),
                publish_playlist_msg: Mock::once(|| ()),
                src_by_owner_kind: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status(StatusCode::CREATED);
            resp.assert_json(&expected);
        }
    }

    mod delete_authenticated_user {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            del: Mock<bool>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_delete_user()
                            .with(eq(usr.id))
                            .times(mocks.del.times())
                            .returning({
                                let mock = mocks.del.clone();
                                move |_| Ok(mock.call())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server.delete(PATH_ME).await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized_when_auth_failed() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn unauthorized_when_user_was_already_deleted() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                del: Mock::once(|| false),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::UNAUTHORIZED);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                del: Mock::once(|| true),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod delete_playlist {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            count_srcs: Mock<u32>,
            del: Mock<bool>,
            del_src: Mock<()>,
            playlist_by_id: Mock<Option<Playlist>, Playlist>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
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
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = playlist.src.owner.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                begin: Mock::once({
                    let playlist = playlist.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut tx = MockDatabaseTransaction::new();
                        tx.client
                            .expect_playlist_by_id()
                            .with(eq(playlist.id))
                            .times(mocks.playlist_by_id.times())
                            .returning({
                                let playlist = playlist.clone();
                                let mock = mocks.playlist_by_id.clone();
                                move |_| Ok(mock.call_with_args(playlist.clone()))
                            });
                        tx.client
                            .expect_delete_playlist()
                            .with(eq(playlist.id))
                            .times(mocks.del.times())
                            .returning({
                                let mock = mocks.del.clone();
                                move |_| Ok(mock.call())
                            });
                        tx.client
                            .expect_count_source_playlists()
                            .with(eq(playlist.id))
                            .times(mocks.count_srcs.times())
                            .returning({
                                let mock = mocks.count_srcs.clone();
                                move |_| Ok(mock.call())
                            });
                        tx.client
                            .expect_delete_source()
                            .with(eq(playlist.src.id))
                            .times(mocks.del_src.times())
                            .returning(|_| Ok(true));
                        tx
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server
                .delete(&format!("{PATH_PLAYLIST}/{}", playlist.id))
                .await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found_when_playlist_doesnt_exist() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                playlist_by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                playlist_by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found_when_playlist_is_not_deleted() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                count_srcs: Mock::once(|| 1),
                del: Mock::once(|| false),
                playlist_by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content_when_auth_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                count_srcs: Mock::once(|| 1),
                del: Mock::once(|| true),
                playlist_by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content_when_auth_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                        ..usr
                    })
                }),
                count_srcs: Mock::once(|| 0),
                del: Mock::once(|| true),
                del_src: Mock::once(|| ()),
                playlist_by_id: Mock::once_with_args(Some),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod delete_user {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            del: Mock<bool>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_delete_user()
                            .with(eq(usr.id))
                            .times(mocks.del.times())
                            .returning({
                                let mock = mocks.del.clone();
                                move |_| Ok(mock.call())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server.delete(&format!("{PATH_USR}/{}", usr.id)).await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                del: Mock::once(|| false),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content_when_user_is_itself() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                del: Mock::once(|| true),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                del: Mock::once(|| true),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
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

    mod playlist_by_id {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Playlist>, Playlist>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, PlaylistResponse) {
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
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
            let expected = PlaylistResponse::from(playlist.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = playlist.src.owner.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let playlist = playlist.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_playlist_by_id()
                            .with(eq(playlist.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let playlist = playlist.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(playlist.clone()))
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_PLAYLIST}/{}", playlist.id))
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: PlaylistResponse = resp.json();
            assert_eq!(resp, expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: PlaylistResponse = resp.json();
            assert_eq!(resp, expected);
        }
    }

    mod playlist_tracks {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Playlist>, Playlist>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
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
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = playlist.src.owner.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let playlist = playlist.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_playlist_by_id()
                            .with(eq(playlist.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let playlist = playlist.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(playlist.clone()))
                            });
                        conn.0
                            .expect_playlist_tracks()
                            .with(eq(playlist.id), eq(page.req))
                            .times(mocks.tracks.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_PLAYLIST}/{}{PATH_TRACK}", playlist.id))
                .add_query_params(req)
                .await;
            (resp, page)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        role: Role::User,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                tracks: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
                tracks: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            playlists: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_playlists()
                            .with(eq(page.req))
                            .times(mocks.playlists.times())
                            .returning({
                                let page = page.clone();
                                move |_| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(PATH_PLAYLIST).add_query_params(req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
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
                auth: Mock::once_with_args(Ok),
                playlists: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_authenticated_user_playlists_by_name {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            search: Mock<()>,
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
            let params = SearchQueryParam { q: "name".into() };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let params = params.clone();
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_search_user_playlists_by_name()
                            .with(eq(usr.id), eq(params.q.clone()), eq(page.req))
                            .times(mocks.search.times())
                            .returning({
                                let page = page.clone();
                                move |_, _, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_ME}{PATH_PLAYLIST}{PATH_SEARCH}"))
                .add_query_params(&params)
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_playlists_by_name {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let params = SearchQueryParam { q: "name".into() };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            Box::pin(async move { mock.call_with_args(usr.clone()) })
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let params = params.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_search_playlists_by_name()
                            .with(eq(params.q.clone()), eq(page.req))
                            .times(mocks.search.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_PLAYLIST}{PATH_SEARCH}"))
                .add_query_params(params)
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
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
                auth: Mock::once_with_args(Ok),
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_users_by_email {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<UserResponse>) {
            let params = SearchQueryParam { q: "name".into() };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(UserResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            Box::pin(async move { mock.call_with_args(usr.clone()) })
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let params = params.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_search_users_by_email()
                            .with(eq(params.q.clone()), eq(page.req))
                            .times(mocks.search.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_USR}{PATH_SEARCH}"))
                .add_query_params(params)
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
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
                auth: Mock::once_with_args(Ok),
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod source_by_id {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Source>, Source>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, SourceResponse) {
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
            let expected = SourceResponse::from(src.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = src.owner.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let src = src.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_source_by_id()
                            .with(eq(src.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let src = src.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(src.clone()))
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(&format!("{PATH_SRC}/{}", src.id)).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: SourceResponse = resp.json();
            assert_eq!(resp, expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        role: Role::Admin,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: SourceResponse = resp.json();
            assert_eq!(resp, expected);
        }
    }

    mod source_tracks {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Source>, Source>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
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
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = src.owner.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let src = src.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_source_by_id()
                            .with(eq(src.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let src = src.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(src.clone()))
                            });
                        conn.0
                            .expect_source_tracks()
                            .with(eq(src.id), eq(page.req))
                            .times(mocks.tracks.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_SRC}/{}{PATH_TRACK}", src.id))
                .add_query_params(req)
                .await;
            (resp, page)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        role: Role::User,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                tracks: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
                tracks: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod sources {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<SourceResponse>) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(SourceResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_sources()
                            .with(eq(page.req))
                            .times(mocks.srcs.times())
                            .returning({
                                let page = page.clone();
                                move |_| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(PATH_SRC).add_query_params(req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
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
                auth: Mock::once_with_args(Ok),
                srcs: Mock::once(|| ()),
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
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_authorize_url()
                .with(eq(param.redirect_uri.clone()))
                .returning(move |_| Ok(expected.into()));
            let state = AppState {
                db: Default::default(),
                svc: MockServices {
                    spotify,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_AUTH}{PATH_SPOTIFY}"))
                .add_query_params(&param)
                .await;
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
            auth: Mock<ApiResult<User>, User>,
            exists: Mock<bool>,
            publish: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let msg = PlaylistMessage {
                id: Uuid::new_v4(),
                kind: PlaylistMessageKind::Sync,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let msg = msg.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_playlist_exists()
                            .with(eq(msg.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let mut broker = MockBrokerClient::new();
            broker
                .expect_publish_playlist_message()
                .with(eq(msg.clone()))
                .times(mocks.publish.times())
                .returning(|_| Ok(()));
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    broker,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server
                .put(&format!("{PATH_PLAYLIST}/{}{PATH_SYNC}", msg.id))
                .await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                publish: Mock::once(|| ()),
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
            auth: Mock<ApiResult<User>, User>,
            exists: Mock<bool>,
            publish: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let msg = SourceMessage {
                id: Uuid::new_v4(),
                kind: SourceMessageKind::Sync,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let msg = msg.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_source_exists()
                            .with(eq(msg.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let mut broker = MockBrokerClient::new();
            broker
                .expect_publish_source_message()
                .with(eq(msg.clone()))
                .times(mocks.publish.times())
                .returning(|_| Ok(()));
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    broker,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server
                .put(&format!("{PATH_SRC}/{}{PATH_SYNC}", msg.id))
                .await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn no_content() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                publish: Mock::once(|| ()),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod track_by_id {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Track>, Track>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Track) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let track = Track {
                album: Album {
                    compil: false,
                    name: "album".into(),
                },
                artists: Default::default(),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                platform: Platform::Spotify,
                platform_id: "id".into(),
                title: "title".into(),
                year: 2020,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let track = track.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_track_by_id()
                            .with(eq(track.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let track = track.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(track.clone()))
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(&format!("{PATH_TRACK}/{}", track.id)).await;
            (resp, track)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: Track = resp.json();
            assert_eq!(resp, expected);
        }
    }

    mod tracks {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_tracks()
                            .with(eq(page.req))
                            .times(mocks.tracks.times())
                            .returning({
                                let page = page.clone();
                                move |_| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(PATH_TRACK).add_query_params(req).await;
            (resp, page)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                tracks: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod user_by_id {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<User>, User>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, UserResponse) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = UserResponse::from(usr.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_by_id()
                            .with(eq(usr.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let usr = usr.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(usr.clone()))
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(&format!("{PATH_USR}/{}", usr.id)).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: UserResponse = resp.json();
            assert_eq!(resp, expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            let resp: UserResponse = resp.json();
            assert_eq!(resp, expected);
        }
    }

    mod user_playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            exists: Mock<bool>,
            playlists: Mock<()>,
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
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(PlaylistResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let usr = usr.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_exists()
                            .with(eq(usr.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn.0
                            .expect_user_playlists()
                            .with(eq(usr.id), eq(page.req))
                            .times(mocks.playlists.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_USR}/{}{PATH_PLAYLIST}", usr.id))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                playlists: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                exists: Mock::once(|| true),
                playlists: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod user_sources {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            exists: Mock<bool>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<SourceResponse>) {
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
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(SourceResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let usr = usr.clone();
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_user_exists()
                            .with(eq(usr.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn.0
                            .expect_user_sources()
                            .with(eq(usr.id), eq(page.req))
                            .times(mocks.srcs.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_USR}/{}{PATH_SRC}", usr.id))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        id: Uuid::new_v4(),
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                srcs: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                exists: Mock::once(|| true),
                srcs: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod users {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            usrs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<UserResponse>) {
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(UserResponse::from);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let db = MockDatabasePool {
                acquire: Mock::once({
                    let page = page.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut conn = MockDatabaseConnection::new();
                        conn.0
                            .expect_users()
                            .with(eq(page.req))
                            .times(mocks.usrs.times())
                            .returning({
                                let page = page.clone();
                                move |_| Ok(page.clone())
                            });
                        conn
                    }
                }),
                ..Default::default()
            };
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(PATH_USR).add_query_params(req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
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
                auth: Mock::once_with_args(Ok),
                usrs: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }
}
