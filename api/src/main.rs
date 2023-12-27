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
        PageRequestQueryParams, PreconditionFailedResponse, RedirectUriQueryParam,
        SearchQueryParam, UpdatePlaylistRequest, UpdateTrackRequest, UpdateUserRequest, Validate,
        ValidationErrorResponse, PATH_AUTH, PATH_HEALTH, PATH_ME, PATH_PLAYLIST, PATH_REFRESH,
        PATH_SEARCH, PATH_SPOTIFY, PATH_SRC, PATH_SYNC, PATH_TOKEN, PATH_TRACK, PATH_USR,
    },
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConfig},
        BrokerClient, BrokerError, PlaylistMessage, PlaylistMessageKind, SourceMessage,
        SourceMessageKind,
    },
    db::{
        pg::{PostgresConfig, PostgresPool},
        DatabaseConnection, DatabaseError, DatabasePool, DatabaseTransaction, PlaylistCreation,
        SourceCreation,
    },
    model::{Credentials, Platform, Playlist, Role, SourceKind, SpotifyCredentials, Target},
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
    conv::{Converter, DefaultConverter},
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
                        let mut db_tx = state.db.begin().await?;
                        let spotify = state.svc.spotify();
                        let mut token = spotify
                            .authenticate(&params.code, &params.redirect_uri)
                            .await?;
                        let spotify_usr = spotify.authenticated_user(&mut token).await?;
                        let creds = SpotifyCredentials {
                            email: spotify_usr.email,
                            id: spotify_usr.id,
                            token,
                        };
                        let usr = db_tx.user_by_spotify_id(&creds.id).await?;
                        transactional!(db_tx, async {
                            let (usr, created) = match usr {
                                Some(mut usr) => {
                                    usr.creds.spotify = Some(creds);
                                    db_tx.update_user(&usr).await?;
                                    (usr, false)
                                }
                                None => {
                                    let creds = Credentials {
                                        spotify: Some(creds),
                                    };
                                    let mut usr = db_tx.create_user(&creds).await?;
                                    info!(%usr.id, "user created");
                                    state.svc
                                        .playlists_puller()
                                        .pull_spotify(&mut usr, spotify, db_tx.as_client_mut()).await?;
                                    (usr, true)
                                }
                            };
                            let jwt = state.svc.jwt().generate(&usr)?;
                            let resp = JwtResponse { jwt };
                            let status = if created {
                                StatusCode::CREATED
                            } else {
                                StatusCode::OK
                            };
                            Ok((status, Json(resp)))
                        })
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user",
                            auth.usr.id = %auth_usr.id,
                        );
                        async {
                            let resp = state.svc.converter().convert_user(auth_usr);
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "delete_auth_user",
                            auth.usr.id = %auth_usr.id,
                        );
                        async {
                            if db_conn.delete_user(auth_usr.id).await? {
                                info!(%auth_usr.id, "user deleted");
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user_playlists",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            let page = db_conn
                                .user_playlists(auth_usr.id, req.into())
                                .await?
                                .map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_auth_user_playlists_by_name",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            let page = db_conn
                                .search_user_playlists_by_name(auth_usr.id, &params.q, req.into())
                                .await?
                                .map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "auth_user_sources",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            let page = db_conn
                                .user_sources(auth_usr.id, req.into())
                                .await?
                                .map(|src| state.svc.converter().convert_source(src, &auth_usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlists",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let page = db_conn
                                .playlists(req.into())
                                .await?
                                .map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
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
                        let mut auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_tx.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "create_playlist",
                            auth.usr.id = %auth_usr.id,
                            playlist.name = req.name,
                            playlist.src.kind = %req.src,
                        );
                        async {
                            let tgt = match req.src {
                                SourceKind::Spotify(_) => {
                                    let creds = auth_usr
                                        .creds
                                        .spotify
                                        .as_mut()
                                        .ok_or(ApiError::NoSpotifyCredentials)?;
                                    let id = state.svc.spotify().create_playlist(&req.name, creds).await?;
                                    Target::Spotify(id)
                                }
                            };
                            let (playlist, new_src) = transactional!(db_tx, async {
                                let src = db_tx.source_by_owner_kind(auth_usr.id, &req.src).await?;
                                let (src, new_src) = match src {
                                    Some(src) => (src, false),
                                    None => {
                                        let creation = SourceCreation {
                                            kind: req.src,
                                            owner: auth_usr.clone(),
                                        };
                                        let src = db_tx.create_source(&creation).await?;
                                        info!(%src.kind, %src.owner.id, "source created");
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
                                info!(
                                    %playlist.id,
                                    %playlist.src.owner.id,
                                    %playlist.src.sync,
                                    %playlist.sync,
                                    "playlist created"
                                );
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
                            let resp = state.svc.converter().convert_playlist(playlist, &auth_usr);
                            Ok((StatusCode::CREATED, Json(resp)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_tx.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "delete_playlist",
                            auth.usr.id = %auth_usr.id,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_tx.playlist_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
                            transactional!(db_tx, async {
                                let deleted = db_tx.delete_playlist(id).await?;
                                let src_count = db_tx.count_source_playlists(playlist.src.id).await?;
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlist_by_id",
                            auth.usr.id = %auth_usr.id,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_conn.playlist_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
                            let resp = state.svc.converter().convert_playlist(playlist, &auth_usr);
                            Ok((StatusCode::OK, Json(resp)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        req.validate()?;
                        let mut db_tx = state.db.begin().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_tx.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "update_playlist",
                            auth.usr.id = %auth_usr.id,
                            playlist.id = %id,
                            playlist.name = req.name,
                        );
                        async {
                            let playlist = transactional!(db_tx, async {
                                let mut playlist = db_tx.playlist_by_id(id).await?.ok_or(ApiError::NotFound)?;
                                ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
                                playlist.name = req.name;
                                playlist.predicate = req.predicate;
                                if !db_tx.update_playlist_safely(&playlist).await? {
                                    return Err(ApiError::SynchronizationIsRunning);
                                }
                                match &playlist.tgt {
                                    Target::Spotify(id) => {
                                        let creds = playlist.src.owner.creds.spotify.as_mut().ok_or(ApiError::NoSpotifyCredentials)?;
                                        state.svc.spotify().update_playlist_name(id, &playlist.name, &mut creds.token).await?;
                                    }
                                }
                                db_tx.update_user(&playlist.src.owner).await?;
                                Ok(playlist)
                            })?;
                            info!(
                                %playlist.id,
                                %playlist.src.owner.id,
                                %playlist.src.sync,
                                %playlist.sync,
                                "playlist updated"
                            );
                            let resp = state.svc.converter().convert_playlist(playlist, &auth_usr);
                            Ok((StatusCode::OK, Json(resp)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_playlists_by_name",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let page = db_conn
                                .search_playlists_by_name(&params.q, req.into())
                                .await?
                                .map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "start_playlist_synchronization",
                            auth.usr.id = %auth_usr.id,
                            playlist.id = %id,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "playlist_tracks",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_conn.playlist_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
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
        // search_playlist_tracks_by_title_artists_album
        .route(
            &format!("{PATH_PLAYLIST}/:id{PATH_TRACK}{PATH_SEARCH}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_playlist_tracks_by_title_artists_album",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                            playlist.id = %id,
                        );
                        async {
                            let playlist = db_conn.playlist_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
                            let page = db_conn
                                .search_playlist_tracks_by_title_artists_album(id, &params.q, req.into())
                                .await?;
                            Ok((StatusCode::OK, Json(page)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "sources",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let page = db_conn.sources(req.into())
                                .await?
                                .map(|src| state.svc.converter().convert_source(src, &auth_usr));
                            Ok((StatusCode::OK, Json(page)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "source_by_id",
                            auth.usr.id = %auth_usr.id,
                            src.id = %id,
                        );
                        async {
                            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, src.owner);
                            let resp = state.svc.converter().convert_source(src, &auth_usr);
                            Ok((StatusCode::OK, Json(resp)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "source_tracks",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            src.id = %id,
                        );
                        async {
                            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, src.owner);
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
        // search_source_tracks_by_title_artists_album
        .route(
            &format!("{PATH_SRC}/:id{PATH_TRACK}{PATH_SEARCH}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_source_tracks_by_title_artists_album",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                            src.id = %id,
                        );
                        async {
                            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            ensure_user_is_admin_or_owner!(auth_usr, src.owner);
                            let page = db_conn
                                .search_source_tracks_by_title_artists_album(id, &params.q, req.into())
                                .await?;
                            Ok((StatusCode::OK, Json(page)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "start_source_synchronization",
                            auth.usr.id = %auth_usr.id,
                            src.id = %id,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "tracks",
                            auth.usr.id = %auth_usr.id,
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "track_by_id",
                            auth.usr.id = %auth_usr.id,
                            track.id = %id,
                        );
                        async {
                            let track = db_conn.track_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            Ok((StatusCode::OK, Json(track)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        req.validate()?;
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_conn.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "update_track",
                            auth.usr.id = %auth_usr.id,
                            track.album = req.album.name,
                            track.artists = ?req.artists,
                            track.id = %id,
                            track.title = req.title,
                            track.year = req.year,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let mut track = db_conn.track_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            track.album = req.album;
                            track.artists = req.artists;
                            track.title = req.title;
                            track.year = req.year;
                            db_conn.update_track(&track).await?;
                            info!(%track.platform, track.platform_id, "track updated");
                            Ok((StatusCode::OK, Json(track)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, db_conn.as_client_mut())
                            .await?;
                        let span = info_span!(
                            "delete_track",
                            auth.usr.id = %auth_usr.id,
                            track.id = %id,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let deleted = db_conn.delete_track(id).await?;
                            if deleted {
                                info!(%id, "track deleted");
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
        // search_tracks_by_title_artists_album
        .route(
            &format!("{PATH_TRACK}{PATH_SEARCH}"),
            routing::get(
                |headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 Query(params): Query<SearchQueryParam>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_tracks_by_title_artists_album",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            let page = db_conn
                                .search_tracks_by_title_artists_album(&params.q, req.into())
                                .await?;
                            Ok((StatusCode::OK, Json(page)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "users",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let page = db_conn.users(req.into()).await?.map(|usr| state.svc.converter().convert_user(usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "user_by_id",
                            auth.usr.id = %auth_usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
                            let usr = db_conn.user_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            let resp = state.svc.converter().convert_user(usr);
                            Ok((StatusCode::OK, Json(resp)))
                        }
                        .instrument(span)
                        .await
                    })
                    .await
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
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "update_user",
                            auth.usr.id = %auth_usr.id,
                            usr.id = %id,
                            usr.role = %req.role,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let mut usr = db_conn.user_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            usr.role = req.role;
                            db_conn.update_user(&usr).await?;
                            info!("user updated");
                            let resp = state.svc.converter().convert_user(usr);
                            Ok((StatusCode::OK, Json(resp)))
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "delete_user",
                            auth.usr.id = %auth_usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
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
                 params: Option<Query<SearchQueryParam>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let q = params.map(|Query(params)| params.q);
                        let span = info_span!(
                            "user_playlists",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = q,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
                            if db_conn.user_exists(id).await? {
                                let page = if let Some(q) = q {
                                    db_conn.search_user_playlists_by_name(id, &q, req.into()).await?
                                } else {
                                    db_conn.user_playlists(id, req.into())
                                    .await?
                                };
                                let page = page
                                    .map(|playlist| {
                                        state.svc.converter().convert_playlist(playlist, &auth_usr)
                                    });
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
        // user_spotify_playlists
        .route(
            &format!("{PATH_USR}/:id{PATH_PLAYLIST}{PATH_SPOTIFY}"),
            routing::get(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>,
                 params: Option<Query<SearchQueryParam>>,
                 Query(req): Query<PageRequestQueryParams<25>>| async move {
                     handling_error(async {
                        let mut db_conn = state.db.acquire().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let q = params.map(|Query(params)| params.q);
                        let span = info_span!(
                            "user_spotify_playlists",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = q,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
                            if db_conn.user_exists(id).await? {
                                let page = if let Some(q) = q {
                                    db_conn
                                        .search_user_platform_playlists_by_name(id, Platform::Spotify, &q, req.into())
                                        .await?
                                } else {
                                    db_conn.user_platform_playlists(id, Platform::Spotify, req.into()).await?
                                };
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
        // refresh_user_spotify_playlists
        .route(
            &format!("{PATH_USR}/:id{PATH_PLAYLIST}{PATH_SPOTIFY}{PATH_REFRESH}"),
            routing::put(
                |Path(id): Path<Uuid>,
                 headers: HeaderMap,
                 State(state): State<Arc<AppState<DBCONN, DBTX, DB, SVC>>>| async move {
                     handling_error(async {
                        let mut db_tx = state.db.begin().await?;
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_tx)
                            .await?;
                        let span = info_span!(
                            "refresh_user_spotify_playlists",
                            auth.usr.id = %auth_usr.id,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
                            let mut usr = db_tx.user_by_id(id).await?.ok_or(ApiError::NotFound)?;
                            transactional!(db_tx, async {
                                let spotify = state.svc.spotify();
                                state.svc.playlists_puller().pull_spotify(&mut usr, spotify, db_tx.as_client_mut()).await?;
                                Ok(StatusCode::NO_CONTENT.into_response())
                            })
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "search_users_by_email",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            params.q = params.q,
                        );
                        async {
                            ensure_user_is_admin!(auth_usr);
                            let page = db_conn
                                .search_users_by_email(&params.q, req.into())
                                .await?
                                .map(|usr| state.svc.converter().convert_user(usr));
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
                        let auth_usr = state
                            .svc
                            .auth()
                            .authenticate(&headers, &mut db_conn)
                            .await?;
                        let span = info_span!(
                            "user_sources",
                            auth.usr.id = %auth_usr.id,
                            params.limit = req.limit,
                            params.offset = req.offset,
                            usr.id = %id,
                        );
                        async {
                            ensure_user_is_admin_or_itself!(auth_usr, id);
                            if db_conn.user_exists(id).await? {
                                let page = db_conn.user_sources(id, req.into()).await?.map(|src| state.svc.converter().convert_source(src, &auth_usr));
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

// Mods

mod auth;
mod conv;
mod jwt;
mod pull;

// Tests

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeSet, HashMap},
        io::stderr,
    };

    use autoplaylist_common::{
        api::{PlaylistResponse, SourceResponse, UserResponse, ValidationErrorKind},
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Album, Page, PageRequest, Platform, PlatformPlaylist, Playlist, Predicate, Role,
            Source, SourceKind, SpotifySourceKind, SpotifyToken, Synchronization, Target, Track,
            User,
        },
        spotify::{MockSpotifyClient, SpotifyUser},
    };
    use axum_test::{TestResponse, TestServer};
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::{always, eq};

    use crate::{
        auth::MockAuthenticator, conv::MockConverter, jwt::MockJwtProvider,
        pull::MockPlaylistsPuller,
    };

    use super::*;

    // MockServices

    #[derive(Default)]
    struct MockServices {
        auth: MockAuthenticator,
        broker: MockBrokerClient,
        conv: MockConverter,
        playlists_puller: MockPlaylistsPuller,
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
            pull_playlists: Mock<()>,
            update_usr: Mock<()>,
            usr_by_spotify_id: Mock<Option<User>, User>,
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
                        email: spotify_usr.email.clone(),
                        id: spotify_usr.id.clone(),
                        token: token.clone(),
                    }),
                },
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = "jwt";
            let db = MockDatabasePool {
                begin: Mock::once({
                    let spotify_usr = spotify_usr.clone();
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut tx = MockDatabaseTransaction::new();
                        tx.client
                            .expect_user_by_spotify_id()
                            .with(eq(spotify_usr.id.clone()))
                            .times(mocks.usr_by_spotify_id.times())
                            .returning({
                                let usr = usr.clone();
                                let mock = mocks.usr_by_spotify_id.clone();
                                move |_| Ok(mock.call_with_args(usr.clone()))
                            });
                        tx.client
                            .expect_update_user()
                            .with(eq(usr.clone()))
                            .times(mocks.update_usr.times())
                            .returning({
                                let mock = mocks.update_usr.clone();
                                move |_| {
                                    mock.call();
                                    Ok(true)
                                }
                            });
                        tx.client
                            .expect_create_user()
                            .with(eq(usr.creds.clone()))
                            .times(mocks.create_usr.times())
                            .returning({
                                let usr = usr.clone();
                                move |_| Ok(usr.clone())
                            });
                        tx
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
                .with(eq(usr.clone()))
                .times(1)
                .returning(|_| Ok(expected.into()));
            let mut spotify_puller = MockPlaylistsPuller::new();
            spotify_puller
                .expect_pull_spotify()
                .with(eq(usr.clone()), always(), always())
                .times(mocks.pull_playlists.times())
                .returning(|_, _, _| Box::pin(async { Ok(()) }));
            let state = AppState {
                db,
                svc: MockServices {
                    jwt: jwt_prov,
                    spotify,
                    playlists_puller: spotify_puller,
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
        async fn ok_when_user_didnt_exist() {
            let mocks = Mocks {
                create_usr: Mock::once(|| ()),
                pull_playlists: Mock::once(|| ()),
                usr_by_spotify_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::CREATED);
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_was_created() {
            let mocks = Mocks {
                update_usr: Mock::once(|| ()),
                usr_by_spotify_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
        }
    }

    mod authenticated_user {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            convert: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, UserResponse) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = DefaultConverter.convert_user(auth_usr.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_user()
                .with(eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
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
            convert: Mock<()>,
            playlists: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let page = Page {
                first: true,
                items: vec![playlist.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let playlist_resp = DefaultConverter.convert_playlist(playlist.clone(), &auth_usr);
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| playlist_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist), eq(auth_usr))
                .times(mocks.convert.times())
                .returning({
                    let playlist_resp = playlist_resp.clone();
                    move |_, _| playlist_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
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
            convert: Mock<()>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<SourceResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: auth_usr.clone(),
                sync: Synchronization::Pending,
            };
            let src_resp = DefaultConverter.convert_source(src.clone(), &auth_usr);
            let page = Page {
                first: true,
                items: vec![src.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| src_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_source()
                .with(eq(src), eq(auth_usr))
                .times(mocks.convert.times())
                .returning({
                    let src_resp = src_resp.clone();
                    move |_, _| src_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
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
            convert: Mock<()>,
            create_playlist: Mock<()>,
            create_spotify_playlist: Mock<()>,
            create_src: Mock<()>,
            publish_playlist_msg: Mock<()>,
            publish_src_msg: Mock<()>,
            src_by_owner_kind: Mock<Option<Source>, Source>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, PlaylistResponse) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Credentials {
                    spotify: data.usr_creds,
                },
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let spotify_id = "id";
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: data.req.name.clone(),
                predicate: data.req.predicate.clone(),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: data.req.src.clone(),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify(spotify_id.into()),
            };
            let expected = DefaultConverter.convert_playlist(playlist.clone(), &auth_usr);
            let src_msg = SourceMessage {
                id: playlist.src.id,
                kind: SourceMessageKind::Created,
            };
            let playlist_msg = PlaylistMessage {
                id: playlist.id,
                kind: PlaylistMessageKind::Created,
            };
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_create_playlist()
                .with(eq(playlist.name.clone()), eq(data.creds.clone()))
                .times(mocks.create_spotify_playlist.times())
                .returning(|_, _| Ok(spotify_id.into()));
            let db = MockDatabasePool {
                begin: Mock::once({
                    let playlist = playlist.clone();
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
                    let usr = auth_usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_, _| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    broker,
                    conv,
                    spotify,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.post(PATH_PLAYLIST).json(&data.req).await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn bad_request() {
            let creds = SpotifyCredentials {
                email: "user@test".into(),
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
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn unauthorized() {
            let creds = SpotifyCredentials {
                email: "user@test".into(),
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
        async fn precondition_failed() {
            let creds = SpotifyCredentials {
                email: "user@test".into(),
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
            let expected = PreconditionFailedResponse {
                details: ApiError::NoSpotifyCredentials.to_string(),
            };
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn created_when_source_didnt_exist() {
            let creds = SpotifyCredentials {
                email: "user@test".into(),
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
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
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
                email: "user@test".into(),
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
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                },
                usr_creds: Some(creds),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                            .with(eq(auth_usr.id))
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
                            .with(eq(playlist.src.id))
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

    mod delete_track {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            del: Mock<bool>,
        }

        // Tests

        async fn run(mocks: Mocks) -> TestResponse {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                            .expect_delete_track()
                            .with(eq(id))
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
            server.delete(&format!("{PATH_TRACK}/{}", id)).await
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
                del: Mock::once(|| false),
            };
            let resp = run(mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
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
            server.delete(&format!("{PATH_USR}/{}", auth_usr.id)).await
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
            convert: Mock<()>,
        }

        // Tests

        async fn run(
            auth_usr: User,
            playlist: Playlist,
            mocks: Mocks,
        ) -> (TestResponse, PlaylistResponse) {
            let expected = DefaultConverter.convert_playlist(playlist.clone(), &playlist.src.owner);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(auth_usr))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_, _| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
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
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, playlist, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
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
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, playlist, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
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
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, playlist, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(auth_usr, playlist, mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
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
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(auth_usr, playlist, mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
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
            convert: Mock<()>,
            playlists: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let page = Page {
                first: true,
                items: vec![playlist.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let playlist_resp = DefaultConverter.convert_playlist(playlist.clone(), &auth_usr);
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| playlist_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let playlist_resp = playlist_resp.clone();
                    move |_, _| playlist_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
                playlists: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod refresh_user_spotify_playlists {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<User>, User>,
            pull_playlists: Mock<()>,
        }

        // run

        async fn run(auth_usr: User, usr: User, mocks: Mocks) -> TestResponse {
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = usr.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut tx = MockDatabaseTransaction::new();
                        tx.client
                            .expect_user_by_id()
                            .with(eq(usr.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let usr = usr.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(usr.clone()))
                            });
                        tx
                    }
                }),
                ..Default::default()
            };
            let mut spotify_puller = MockPlaylistsPuller::new();
            spotify_puller
                .expect_pull_spotify()
                .with(eq(usr.clone()), always(), always())
                .times(mocks.pull_playlists.times())
                .returning(|_, _, _| Box::pin(async { Ok(()) }));
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    playlists_puller: spotify_puller,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            server
                .put(&format!(
                    "{PATH_USR}/{}{PATH_PLAYLIST}{PATH_SPOTIFY}{PATH_REFRESH}",
                    usr.id
                ))
                .await
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let resp = run(auth_usr, usr, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                ..Default::default()
            };
            let resp = run(auth_usr, usr, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let resp = run(auth_usr, usr, mocks).await;
            resp.assert_status_not_found();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                pull_playlists: Mock::once(|| ()),
            };
            let resp: TestResponse = run(auth_usr.clone(), auth_usr, mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                pull_playlists: Mock::once(|| ()),
            };
            let resp: TestResponse = run(auth_usr, usr, mocks).await;
            resp.assert_status(StatusCode::NO_CONTENT);
            assert!(resp.as_bytes().is_empty());
        }
    }

    mod search_authenticated_user_playlists_by_name {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            convert: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let playlist_resp = DefaultConverter.convert_playlist(playlist.clone(), &auth_usr);
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let params = SearchQueryParam { q: "name".into() };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| playlist_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let playlist_resp = playlist_resp.clone();
                    move |_, _| playlist_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_playlist_tracks_by_title_artists_album {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Playlist>, Playlist>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
            let params = SearchQueryParam { q: "name".into() };
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
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
                    let usr = auth_usr.clone();
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
                            .expect_search_playlist_tracks_by_title_artists_album()
                            .with(eq(playlist.id), eq(params.q.clone()), eq(page.req))
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
                .get(&format!(
                    "{PATH_PLAYLIST}/{}{PATH_TRACK}{PATH_SEARCH}",
                    playlist.id
                ))
                .add_query_params(params)
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
            resp.assert_status_not_found();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                search: Mock::once(|| ()),
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
            convert: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
            let params = SearchQueryParam { q: "name".into() };
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let playlist = Playlist {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                name: "name".into(),
                predicate: Predicate::YearIs(1993),
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: auth_usr.clone(),
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let playlist_resp = DefaultConverter.convert_playlist(playlist.clone(), &auth_usr);
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 0,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| playlist_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let playlist_resp = playlist_resp.clone();
                    move |_, _| playlist_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_source_tracks_by_title_artists_album {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Source>, Source>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
            let params = SearchQueryParam { q: "name".into() };
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: auth_usr.clone(),
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
                    let usr = auth_usr.clone();
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
                            .expect_search_source_tracks_by_title_artists_album()
                            .with(eq(src.id), eq(params.q.clone()), eq(page.req))
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
                .get(&format!("{PATH_SRC}/{}{PATH_TRACK}{PATH_SEARCH}", src.id))
                .add_query_params(params)
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
            resp.assert_status_not_found();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                search: Mock::once(|| ()),
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
                search: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod search_tracks_by_title_artists_album {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<Track>) {
            let params = SearchQueryParam { q: "name".into() };
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
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
                    let usr = auth_usr.clone();
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
                            .expect_search_tracks_by_title_artists_album()
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
                .get(&format!("{PATH_TRACK}{PATH_SEARCH}"))
                .add_query_params(params)
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
            convert: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<UserResponse>) {
            let params = SearchQueryParam { q: "name".into() };
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let usr_resp = DefaultConverter.convert_user(usr.clone());
            let page = Page {
                first: true,
                items: vec![usr.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| usr_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_user()
                .with(eq(usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let usr_resp = usr_resp.clone();
                    move |_| usr_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
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
            convert: Mock<()>,
        }

        // Tests

        async fn run(auth_usr: User, src: Source, mocks: Mocks) -> (TestResponse, SourceResponse) {
            let expected = DefaultConverter.convert_source(src.clone(), &src.owner);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_source()
                .with(eq(src.clone()), eq(auth_usr))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_, _| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                },
                sync: Synchronization::Pending,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, src, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                },
                sync: Synchronization::Pending,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, src, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                },
                sync: Synchronization::Pending,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr, src, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: auth_usr.clone(),
                sync: Synchronization::Pending,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(auth_usr, src, mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                },
                sync: Synchronization::Pending,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(auth_usr, src, mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
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
            convert: Mock<()>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<SourceResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: auth_usr.clone(),
                sync: Synchronization::Pending,
            };
            let src_resp = DefaultConverter.convert_source(src.clone(), &auth_usr);
            let page = Page {
                first: true,
                items: vec![src.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| src_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_source()
                .with(eq(src.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let src_resp = src_resp.clone();
                    move |_, _| src_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
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
                    let usr = auth_usr.clone();
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
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
                    let usr = auth_usr.clone();
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
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
                    let usr = auth_usr.clone();
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
            resp.assert_json(&expected);
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
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
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
                    let usr = auth_usr.clone();
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

    mod update_playlist {
        use super::*;

        // Data

        struct Data {
            auth_usr: User,
            playlist: Playlist,
            req: UpdatePlaylistRequest,
            spotify_id: &'static str,
            spotify_token: SpotifyToken,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Playlist>, Playlist>,
            convert: Mock<()>,
            rollback: Mock<()>,
            spotify_update: Mock<()>,
            update_playlist: Mock<bool>,
            update_user: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, PlaylistResponse) {
            let playlist_updated = Playlist {
                name: data.req.name.clone(),
                predicate: data.req.predicate.clone(),
                ..data.playlist.clone()
            };
            let expected =
                DefaultConverter.convert_playlist(playlist_updated.clone(), &data.auth_usr);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = data.auth_usr.clone();
                    let mock = mocks.auth.clone();
                    move |_, _| {
                        Box::pin({
                            let usr = usr.clone();
                            let mock = mock.clone();
                            async move { mock.call_with_args(usr.clone()) }
                        })
                    }
                });
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_update_playlist_name()
                .with(
                    eq(data.spotify_id),
                    eq(playlist_updated.name.clone()),
                    eq(data.spotify_token.clone()),
                )
                .times(mocks.spotify_update.times())
                .returning(|_, _, _| Ok(()));
            let db = MockDatabasePool {
                begin: Mock::once({
                    let playlist = data.playlist.clone();
                    let playlist_updated = playlist_updated.clone();
                    let mocks = mocks.clone();
                    move || {
                        let mut tx = MockDatabaseTransaction::new();
                        tx.rollback = mocks.rollback.clone();
                        tx.client
                            .expect_playlist_by_id()
                            .with(eq(playlist.id))
                            .times(mocks.by_id.times())
                            .returning({
                                let playlist = playlist.clone();
                                let mock = mocks.by_id.clone();
                                move |_| Ok(mock.call_with_args(playlist.clone()))
                            });
                        tx.client
                            .expect_update_user()
                            .with(eq(playlist_updated.src.owner.clone()))
                            .times(mocks.update_user.times())
                            .returning(|_| Ok(true));
                        tx.client
                            .expect_update_playlist_safely()
                            .with(eq(playlist_updated.clone()))
                            .times(mocks.update_playlist.times())
                            .returning({
                                let mock = mocks.update_playlist.clone();
                                move |_| Ok(mock.call())
                            });
                        tx
                    }
                }),
                ..Default::default()
            };
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist_updated.clone()), eq(data.auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_, _| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
                    spotify,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .put(&format!("{PATH_PLAYLIST}/{}", playlist_updated.id))
                .json(&data.req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn bad_request() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "".into(),
                    predicate: Predicate::YearIs(1993),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks::default();
            let (resp, _) = run(data, mocks).await;
            resp.assert_status_bad_request();
            let expected = ValidationErrorResponse {
                errs: HashMap::from_iter([(
                    "name".into(),
                    vec![ValidationErrorKind::Length(1, 100)],
                )]),
            };
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn unauthorized() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
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
        async fn forbidden() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                rollback: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                rollback: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn precondition_failed_when_no_spotify_credentials() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials::default(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                rollback: Mock::once(|| ()),
                update_playlist: Mock::once(|| true),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::PRECONDITION_FAILED);
            let expected = PreconditionFailedResponse {
                details: ApiError::NoSpotifyCredentials.to_string(),
            };
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn precondition_failed_when_synchronization_is_running() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                rollback: Mock::once(|| ()),
                update_playlist: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::PRECONDITION_FAILED);
            let expected = PreconditionFailedResponse {
                details: ApiError::SynchronizationIsRunning.to_string(),
            };
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let auth_usr = User {
                creation: Utc::now(),
                creds: Credentials {
                    spotify: Some(SpotifyCredentials {
                        email: "user@test".into(),
                        id: "id".into(),
                        token: spotify_token.clone(),
                    }),
                },
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let data = Data {
                auth_usr: auth_usr.clone(),
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".into(),
                    predicate: Predicate::YearIs(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        owner: auth_usr.clone(),
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
                spotify_update: Mock::once(|| ()),
                update_playlist: Mock::once(|| true),
                update_user: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let spotify_id = "id";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                playlist: Playlist {
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
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    email: "user@test".into(),
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_id.into()),
                },
                req: UpdatePlaylistRequest {
                    name: "name 2".into(),
                    predicate: Predicate::YearIs(2004),
                },
                spotify_id,
                spotify_token,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                convert: Mock::once(|| ()),
                spotify_update: Mock::once(|| ()),
                update_playlist: Mock::once(|| true),
                update_user: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod update_track {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Track>, Track>,
            update: Mock<()>,
        }

        // Tests

        async fn run(req: UpdateTrackRequest, mocks: Mocks) -> (TestResponse, Track) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let track = Track {
                album: Album {
                    compil: false,
                    name: "album".into(),
                },
                artists: BTreeSet::from_iter(["artist".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                platform: Platform::Spotify,
                platform_id: "id".into(),
                title: "title".into(),
                year: 2020,
            };
            let expected = Track {
                album: req.album.clone(),
                artists: req.artists.clone(),
                title: req.title.clone(),
                year: req.year,
                ..track.clone()
            };
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let expected = expected.clone();
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
                        conn.0
                            .expect_update_track()
                            .with(eq(expected.clone()))
                            .times(mocks.update.times())
                            .returning(|_| Ok(true));
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
                .put(&format!("{PATH_TRACK}/{}", track.id))
                .json(&req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn bad_request() {
            let req = UpdateTrackRequest {
                album: Album {
                    compil: false,
                    name: "".into(),
                },
                artists: BTreeSet::from_iter(["artist2".into()]),
                title: "title2".into(),
                year: 2021,
            };
            let mocks = Mocks::default();
            let (resp, _) = run(req, mocks).await;
            resp.assert_status_bad_request();
            let expected = ValidationErrorResponse {
                errs: HashMap::from_iter([(
                    "album.name".into(),
                    vec![ValidationErrorKind::Length(1, usize::MAX)],
                )]),
            };
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn unauthorized() {
            let req = UpdateTrackRequest {
                album: Album {
                    compil: false,
                    name: "album2".into(),
                },
                artists: BTreeSet::from_iter(["artist2".into()]),
                title: "title2".into(),
                year: 2021,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(req, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let req = UpdateTrackRequest {
                album: Album {
                    compil: false,
                    name: "album2".into(),
                },
                artists: BTreeSet::from_iter(["artist2".into()]),
                title: "title2".into(),
                year: 2021,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::User,
                        ..usr
                    })
                }),
                ..Default::default()
            };
            let (resp, _) = run(req, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let req = UpdateTrackRequest {
                album: Album {
                    compil: false,
                    name: "album2".into(),
                },
                artists: BTreeSet::from_iter(["artist2".into()]),
                title: "title2".into(),
                year: 2021,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(req, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok() {
            let req = UpdateTrackRequest {
                album: Album {
                    compil: false,
                    name: "album2".into(),
                },
                artists: BTreeSet::from_iter(["artist2".into()]),
                title: "title2".into(),
                year: 2021,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                update: Mock::once(|| ()),
            };
            let (resp, expected) = run(req, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod update_user {
        use super::*;

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<User>, User>,
            convert: Mock<()>,
            update: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, UserResponse) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let req = UpdateUserRequest { role: Role::User };
            let usr_updated = User {
                role: req.role,
                ..auth_usr.clone()
            };
            let expected = DefaultConverter.convert_user(usr_updated.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
                    let usr_updated = usr_updated.clone();
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
                        conn.0
                            .expect_update_user()
                            .with(eq(usr_updated.clone()))
                            .times(mocks.update.times())
                            .returning(|_| Ok(true));
                        conn
                    }
                }),
                ..Default::default()
            };
            let mut conv = MockConverter::new();
            conv.expect_convert_user()
                .with(eq(usr_updated.clone()))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .put(&format!("{PATH_USR}/{}", auth_usr.id))
                .json(&req)
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
        async fn not_found() {
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
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
                convert: Mock::once(|| ()),
                update: Mock::once(|| ()),
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
            convert: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, UserResponse) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let expected = DefaultConverter.convert_user(auth_usr.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_user()
                .with(eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let expected = expected.clone();
                    move |_| expected.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server.get(&format!("{PATH_USR}/{}", auth_usr.id)).await;
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
                convert: Mock::once(|| ()),
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
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
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
                convert: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status(StatusCode::OK);
            resp.assert_json(&expected);
        }
    }

    mod user_playlists {
        use super::*;

        // Data

        struct Data {
            auth_usr: User,
            id: Uuid,
            params: Option<SearchQueryParam>,
            q: &'static str,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            convert: Mock<()>,
            exists: Mock<bool>,
            playlists: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
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
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                sync: Synchronization::Pending,
                tgt: Target::Spotify("id".into()),
            };
            let playlist_resp = DefaultConverter.convert_playlist(playlist.clone(), &data.auth_usr);
            let page = Page {
                first: true,
                items: vec![playlist.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| playlist_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = data.auth_usr.clone();
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
                            .expect_user_exists()
                            .with(eq(data.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn.0
                            .expect_user_playlists()
                            .with(eq(data.id), eq(page.req))
                            .times(mocks.playlists.times())
                            .returning({
                                let page = page.clone();
                                move |_, _| Ok(page.clone())
                            });
                        conn.0
                            .expect_search_user_playlists_by_name()
                            .with(eq(data.id), eq(data.q), eq(page.req))
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
            let mut conv = MockConverter::new();
            conv.expect_convert_playlist()
                .with(eq(playlist.clone()), eq(data.auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let playlist_resp = playlist_resp.clone();
                    move |_, _| playlist_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_USR}/{}{PATH_PLAYLIST}", data.id))
                .add_query_params(req)
                .add_query_params(data.params)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let data = Data {
                auth_usr,
                id,
                params: None,
                q: "q",
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
        async fn forbidden() {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let data = Data {
                auth_usr,
                id,
                params: None,
                q: "q",
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let data = Data {
                auth_usr,
                id,
                params: None,
                q: "q",
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id,
                role: Role::User,
            };
            let data = Data {
                auth_usr,
                id,
                params: None,
                q: "q",
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                exists: Mock::once(|| true),
                playlists: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let id = Uuid::new_v4();
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let q = "q";
            let data = Data {
                auth_usr,
                id,
                params: Some(SearchQueryParam { q: q.into() }),
                q,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                exists: Mock::once(|| true),
                search: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
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
            convert: Mock<()>,
            exists: Mock<bool>,
            srcs: Mock<()>,
        }

        // Tests

        async fn run(
            id: Uuid,
            auth_usr: User,
            mocks: Mocks,
        ) -> (TestResponse, Page<SourceResponse>) {
            let src = Source {
                creation: Utc::now(),
                id: Uuid::new_v4(),
                kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                owner: auth_usr.clone(),
                sync: Synchronization::Pending,
            };
            let src_resp = DefaultConverter.convert_source(src.clone(), &auth_usr);
            let page = Page {
                first: true,
                items: vec![src.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| src_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
                            .expect_user_exists()
                            .with(eq(id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn.0
                            .expect_user_sources()
                            .with(eq(id), eq(page.req))
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
            let mut conv = MockConverter::new();
            conv.expect_convert_source()
                .with(eq(src.clone()), eq(auth_usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let src_resp = src_resp.clone();
                    move |_, _| src_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
                    ..Default::default()
                },
                _dbconn: PhantomData,
                _dbtx: PhantomData,
            };
            let server = init(state);
            let resp = server
                .get(&format!("{PATH_USR}/{id}{PATH_SRC}"))
                .add_query_params(req)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|_| Err(ApiError::Unauthorized)),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr.id, auth_usr, mocks).await;
            resp.assert_status_unauthorized();
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn forbidden() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                ..Default::default()
            };
            let (resp, _) = run(Uuid::new_v4(), auth_usr, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(auth_usr.id, auth_usr, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                exists: Mock::once(|| true),
                srcs: Mock::once(|| ()),
            };
            let (resp, expected) = run(auth_usr.id, auth_usr, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                exists: Mock::once(|| true),
                srcs: Mock::once(|| ()),
            };
            let (resp, expected) = run(Uuid::new_v4(), auth_usr, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod user_spotify_playlists {
        use super::*;

        // Data

        struct Data {
            auth_usr: User,
            id: Uuid,
            q: &'static str,
            params: Option<SearchQueryParam>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            exists: Mock<bool>,
            playlists: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<PlatformPlaylist>) {
            let page = Page {
                first: true,
                items: vec![],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = data.auth_usr.clone();
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
                            .expect_user_exists()
                            .with(eq(data.id))
                            .times(mocks.exists.times())
                            .returning({
                                let mock = mocks.exists.clone();
                                move |_| Ok(mock.call())
                            });
                        conn.0
                            .expect_user_platform_playlists()
                            .with(eq(data.id), eq(Platform::Spotify), eq(page.req))
                            .times(mocks.playlists.times())
                            .returning({
                                let page = page.clone();
                                move |_, _, _| Ok(page.clone())
                            });
                        conn.0
                            .expect_search_user_platform_playlists_by_name()
                            .with(eq(data.id), eq(Platform::Spotify), eq(data.q), eq(page.req))
                            .times(mocks.search.times())
                            .returning({
                                let page = page.clone();
                                move |_, _, _, _| Ok(page.clone())
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
                .get(&format!(
                    "{PATH_USR}/{}{PATH_PLAYLIST}{PATH_SPOTIFY}",
                    data.id
                ))
                .add_query_params(data.params)
                .add_query_params(req)
                .await;
            (resp, page)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let id = Uuid::new_v4();
            let q = "q";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id,
                    role: Role::User,
                },
                id: Uuid::new_v4(),
                q,
                params: None,
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
        async fn forbidden() {
            let id = Uuid::new_v4();
            let q = "q";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id,
                    role: Role::User,
                },
                id: Uuid::new_v4(),
                q,
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let id = Uuid::new_v4();
            let q = "q";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id,
                    role: Role::Admin,
                },
                id: Uuid::new_v4(),
                q,
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| false),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::NOT_FOUND);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_itself() {
            let id = Uuid::new_v4();
            let q = "q";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id,
                    role: Role::User,
                },
                id,
                q,
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                playlists: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_when_user_is_admin() {
            let q = "q";
            let data = Data {
                auth_usr: User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                },
                id: Uuid::new_v4(),
                q,
                params: Some(SearchQueryParam { q: q.into() }),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                exists: Mock::once(|| true),
                search: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
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
            convert: Mock<()>,
            usrs: Mock<()>,
        }

        // Tests

        async fn run(mocks: Mocks) -> (TestResponse, Page<UserResponse>) {
            let auth_usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::Admin,
            };
            let usr = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let usr_resp = DefaultConverter.convert_user(usr.clone());
            let page = Page {
                first: true,
                items: vec![usr.clone()],
                last: true,
                req: PageRequest::new(10, 0),
                total: 1,
            };
            let req = PageRequestQueryParams::<25>::from(page.req);
            let expected = page.clone().map(|_| usr_resp.clone());
            let mut auth = MockAuthenticator::new();
            auth.expect_authenticate()
                .times(mocks.auth.times())
                .returning({
                    let usr = auth_usr.clone();
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
            let mut conv = MockConverter::new();
            conv.expect_convert_user()
                .with(eq(usr.clone()))
                .times(mocks.convert.times())
                .returning({
                    let usr_resp = usr_resp.clone();
                    move |_| usr_resp.clone()
                });
            let state = AppState {
                db,
                svc: MockServices {
                    auth,
                    conv,
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
                convert: Mock::once(|| ()),
                usrs: Mock::once(|| ()),
            };
            let (resp, expected) = run(mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }
}
