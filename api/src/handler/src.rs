use autoplaylist_common::{
    api::{PageRequestQueryParams, SearchQueryParam},
    broker::{SourceMessage, SourceMessageKind},
    db::{DatabaseConnection, DatabasePool, DatabaseTransaction},
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tracing::{info_span, Instrument};
use uuid::Uuid;

use crate::{handling_error, ApiError, AppState, Services};

// source_by_id

#[inline]
pub async fn source_by_id<
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
}

// source_tracks

#[inline]
pub async fn source_tracks<
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
            "source_tracks",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = q,
            src.id = %id,
        );
        async {
            let src = db_conn.source_by_id(id).await?.ok_or(ApiError::NotFound)?;
            ensure_user_is_admin_or_owner!(auth_usr, src.owner);
            let page = if let Some(q) = q {
                db_conn
                    .search_source_tracks_by_title_artists_album(id, &q, req.into())
                    .await?
            } else {
                db_conn.source_tracks(id, req.into()).await?
            };
            Ok((StatusCode::OK, Json(page)).into_response())
        }
        .instrument(span)
        .await
    })
    .await
}

// sources

#[inline]
pub async fn sources<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    headers: &HeaderMap,
    req: PageRequestQueryParams<25>,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
        let span = info_span!(
            "sources",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            ensure_user_is_admin!(auth_usr);
            let page = db_conn
                .sources(req.into())
                .await?
                .map(|src| state.svc.converter().convert_source(src, &auth_usr));
            Ok((StatusCode::OK, Json(page)))
        }
        .instrument(span)
        .await
    })
    .await
}

// start_source_synchronization

#[inline]
pub async fn start_source_synchronization<
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
}

// Tests

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use autoplaylist_common::{
        api::{SourceResponse, PATH_SRC, PATH_SYNC, PATH_TRACK},
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool},
        model::{
            Page, PageRequest, Role, Source, SourceKind, SpotifySourceKind, Synchronization, Track,
            User,
        },
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

        // Data

        struct Data {
            q: &'static str,
            params: Option<SearchQueryParam>,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            auth: Mock<ApiResult<User>, User>,
            by_id: Mock<Option<Source>, Source>,
            search: Mock<()>,
            tracks: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<Track>) {
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
                        conn.0
                            .expect_search_source_tracks_by_title_artists_album()
                            .with(eq(src.id), eq(data.q), eq(page.req))
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
                .get(&format!("{PATH_SRC}/{}{PATH_TRACK}", src.id))
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
}
