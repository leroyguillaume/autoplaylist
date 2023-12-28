use autoplaylist_common::{
    api::{PageRequestQueryParams, SearchQueryParam, UpdateTrackRequest, Validate},
    db::{DatabaseConnection, DatabasePool, DatabaseTransaction},
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use tracing::{info, info_span, Instrument};
use uuid::Uuid;

use crate::{handling_error, ApiError, AppState, Services};

// delete_track

#[inline]
pub async fn delete_track<
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
        let auth_usr = state
            .svc
            .auth()
            .authenticate(headers, db_conn.as_client_mut())
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
}

// track_by_id

#[inline]
pub async fn track_by_id<
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
}

// tracks

#[inline]
pub async fn tracks<
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
            "tracks",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = q,
        );
        async {
            let page = if let Some(q) = q {
                db_conn
                    .search_tracks_by_title_artists_album(&q, req.into())
                    .await?
            } else {
                db_conn.tracks(req.into()).await?
            };
            Ok((StatusCode::OK, Json(page)))
        }
        .instrument(span)
        .await
    })
    .await
}

// update_track

#[inline]
pub async fn update_track<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    req: UpdateTrackRequest,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        req.validate()?;
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state
            .svc
            .auth()
            .authenticate(headers, db_conn.as_client_mut())
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
}

// Tests

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeSet, HashMap},
        marker::PhantomData,
    };

    use autoplaylist_common::{
        api::{ValidationErrorKind, ValidationErrorResponse, PATH_TRACK},
        db::{MockDatabaseConnection, MockDatabasePool},
        model::{Album, Page, PageRequest, Platform, Role, Track, User},
    };
    use axum_test::TestResponse;
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use crate::{auth::MockAuthenticator, test::init, ApiError, ApiResult, MockServices};

    use super::*;

    // Mods

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

        // Data

        struct Data {
            q: &'static str,
            params: Option<SearchQueryParam>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            search: Mock<()>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<Track>) {
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
                        conn.0
                            .expect_search_tracks_by_title_artists_album()
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
                .get(PATH_TRACK)
                .add_query_params(req)
                .add_query_params(&data.params)
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
        async fn ok_without_search() {
            let data = Data {
                q: "q",
                params: None,
            };
            let mocks = Mocks {
                auth: Mock::once_with_args(Ok),
                tracks: Mock::once(|| ()),
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
                search: Mock::once(|| ()),
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
}
