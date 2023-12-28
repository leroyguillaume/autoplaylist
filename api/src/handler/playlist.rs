use autoplaylist_common::{
    api::{
        CreatePlaylistRequest, PageRequestQueryParams, SearchQueryParam, UpdatePlaylistRequest,
        Validate,
    },
    broker::{PlaylistMessage, PlaylistMessageKind, SourceMessage, SourceMessageKind},
    db::{DatabaseConnection, DatabasePool, DatabaseTransaction, PlaylistCreation, SourceCreation},
    model::{Playlist, SourceKind, Target},
    transactional,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::{info, info_span, Instrument};
use uuid::Uuid;

use crate::{handling_error, ApiError, AppState, Services};

// create_playlist

#[inline]
pub async fn create_playlist<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    headers: &HeaderMap,
    req: CreatePlaylistRequest,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        req.validate()?;
        let mut db_tx = state.db.begin().await?;
        let mut auth_usr = state
            .svc
            .auth()
            .authenticate(headers, db_tx.as_client_mut())
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
                    let id = state
                        .svc
                        .spotify()
                        .create_playlist(&req.name, creds)
                        .await?;
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
}

// delete_playlist

#[inline]
pub async fn delete_playlist<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_tx = state.db.begin().await?;
        let auth_usr = state
            .svc
            .auth()
            .authenticate(headers, db_tx.as_client_mut())
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
}

// playlist_by_id

#[inline]
pub async fn playlist_by_id<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
        let span = info_span!(
            "playlist_by_id",
            auth.usr.id = %auth_usr.id,
            playlist.id = %id,
        );
        async {
            let playlist = db_conn
                .playlist_by_id(id)
                .await?
                .ok_or(ApiError::NotFound)?;
            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
            let resp = state.svc.converter().convert_playlist(playlist, &auth_usr);
            Ok((StatusCode::OK, Json(resp)))
        }
        .instrument(span)
        .await
    })
    .await
}

// playlist_tracks

#[inline]
pub async fn playlist_tracks<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    req: PageRequestQueryParams<25>,
    params: Option<SearchQueryParam>,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
        let q = params.map(|params| params.q);
        let span = info_span!(
            "playlist_tracks",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = q,
            playlist.id = %id,
        );
        async {
            let playlist = db_conn
                .playlist_by_id(id)
                .await?
                .ok_or(ApiError::NotFound)?;
            ensure_user_is_admin_or_owner!(auth_usr, playlist.src.owner);
            let page = if let Some(q) = q {
                db_conn
                    .search_playlist_tracks_by_title_artists_album(id, &q, req.into())
                    .await?
            } else {
                db_conn.playlist_tracks(id, req.into()).await?
            };
            Ok((StatusCode::OK, Json(page)).into_response())
        }
        .instrument(span)
        .await
    })
    .await
}

// playlists

#[inline]
pub async fn playlists<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    headers: &HeaderMap,
    req: PageRequestQueryParams<25>,
    params: Option<SearchQueryParam>,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
        let q = params.map(|params| params.q);
        let span = info_span!(
            "playlists",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = q,
        );
        async {
            ensure_user_is_admin!(auth_usr);
            let page = if let Some(q) = q {
                db_conn.search_playlists_by_name(&q, req.into()).await?
            } else {
                db_conn.playlists(req.into()).await?
            };
            let page =
                page.map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
            Ok((StatusCode::OK, Json(page)))
        }
        .instrument(span)
        .await
    })
    .await
}

// start_playlist_synchronization

#[inline]
pub async fn start_playlist_synchronization<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
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
}

// update_playlist

#[inline]
pub async fn update_playlist<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    req: UpdatePlaylistRequest,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        req.validate()?;
        let mut db_tx = state.db.begin().await?;
        let auth_usr = state
            .svc
            .auth()
            .authenticate(headers, db_tx.as_client_mut())
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
                        let creds = playlist
                            .src
                            .owner
                            .creds
                            .spotify
                            .as_mut()
                            .ok_or(ApiError::NoSpotifyCredentials)?;
                        state
                            .svc
                            .spotify()
                            .update_playlist_name(id, &playlist.name, &mut creds.token)
                            .await?;
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
            let msg = PlaylistMessage {
                id: playlist.id,
                kind: PlaylistMessageKind::Updated,
            };
            state.svc.broker().publish_playlist_message(&msg).await?;
            let resp = state.svc.converter().convert_playlist(playlist, &auth_usr);
            Ok((StatusCode::OK, Json(resp)))
        }
        .instrument(span)
        .await
    })
    .await
}

// Tests

#[cfg(test)]
mod test {
    use std::{collections::HashMap, marker::PhantomData};

    use autoplaylist_common::{
        api::{
            PlaylistResponse, PreconditionFailedResponse, ValidationErrorKind,
            ValidationErrorResponse, PATH_PLAYLIST, PATH_SYNC, PATH_TRACK,
        },
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Credentials, Page, PageRequest, Playlist, Predicate, Role, Source, SourceKind,
            SpotifyCredentials, SpotifySourceKind, SpotifyToken, Synchronization, Target, Track,
            User,
        },
        spotify::MockSpotifyClient,
    };
    use axum_test::TestResponse;
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use crate::{
        auth::MockAuthenticator,
        conv::{Converter, DefaultConverter, MockConverter},
        test::init,
        ApiError, ApiResult, MockServices,
    };

    use super::*;

    // Mods

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

        // Data

        struct Data {
            q: &'static str,
            params: Option<SearchQueryParam>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Playlist>, Playlist>,
            search: Mock<()>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<Track>) {
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
                        conn.0
                            .expect_search_playlist_tracks_by_title_artists_album()
                            .with(eq(playlist.id), eq(data.q), eq(page.req))
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
                .get(&format!("{PATH_PLAYLIST}/{}{PATH_TRACK}", playlist.id))
                .add_query_params(req)
                .add_query_params(data.params)
                .await;
            (resp, page)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let data = Data {
                q: "q",
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
            let data = Data {
                q: "q",
                params: None,
            };
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
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn not_found() {
            let data = Data {
                q: "q",
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(|_| None),
                ..Default::default()
            };
            let (resp, _) = run(data, mocks).await;
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_when_user_is_owner() {
            let data = Data {
                q: "q",
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                by_id: Mock::once_with_args(Some),
                tracks: Mock::once(|| ()),
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
                q,
                params: Some(SearchQueryParam { q: q.into() }),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(|usr| {
                    Ok(User {
                        role: Role::Admin,
                        ..usr
                    })
                }),
                by_id: Mock::once_with_args(Some),
                search: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }
    }

    mod playlists {
        use super::*;

        // Data

        struct Data {
            q: &'static str,
            params: Option<SearchQueryParam>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            convert: Mock<()>,
            playlists: Mock<()>,
            search: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<PlaylistResponse>) {
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
                        conn.0
                            .expect_search_playlists_by_name()
                            .with(eq(data.q), eq(page.req))
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
                .get(PATH_PLAYLIST)
                .add_query_params(req)
                .add_query_params(&data.params)
                .await;
            (resp, expected)
        }

        // Tests

        #[tokio::test]
        async fn unauthorized() {
            let data = Data {
                q: "q",
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
            let data = Data {
                q: "q",
                params: None,
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
            let (resp, _) = run(data, mocks).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.as_bytes().is_empty());
        }

        #[tokio::test]
        async fn ok_without_search() {
            let data = Data {
                q: "q",
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                playlists: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
        }

        #[tokio::test]
        async fn ok_with_search() {
            let q = "q";
            let data = Data {
                q,
                params: Some(SearchQueryParam { q: q.into() }),
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                convert: Mock::once(|| ()),
                search: Mock::once(|| ()),
                ..Default::default()
            };
            let (resp, expected) = run(data, mocks).await;
            resp.assert_status_ok();
            resp.assert_json(&expected);
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
            publish: Mock<()>,
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
            let msg = PlaylistMessage {
                id: playlist_updated.id,
                kind: PlaylistMessageKind::Updated,
            };
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
            let mut broker = MockBrokerClient::new();
            broker
                .expect_publish_playlist_message()
                .with(eq(msg))
                .times(mocks.publish.times())
                .returning(|_| Ok(()));
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
                    broker,
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
                publish: Mock::once(|| ()),
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
                publish: Mock::once(|| ()),
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
}
