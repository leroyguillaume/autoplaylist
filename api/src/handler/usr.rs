use autoplaylist_common::{
    api::{PageRequestQueryParams, SearchQueryParam, UpdateUserRequest},
    db::{DatabaseConnection, DatabasePool, DatabaseTransaction},
    model::Platform,
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

// delete_user

#[inline]
pub async fn delete_user<
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
}

// refresh_user_spotify_playlists

#[inline]
pub async fn refresh_user_spotify_playlists<
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
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_tx).await?;
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
                state
                    .svc
                    .playlists_puller()
                    .pull_spotify(&mut usr, spotify, db_tx.as_client_mut())
                    .await?;
                Ok(StatusCode::NO_CONTENT.into_response())
            })
        }
        .instrument(span)
        .await
    })
    .await
}

// update_user

#[inline]
pub async fn update_user<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    req: UpdateUserRequest,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
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
}

// user_by_id

#[inline]
pub async fn user_by_id<
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
}

// user_playlists

#[inline]
pub async fn user_playlists<
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
                let page = if let Some(Some(q)) = q {
                    db_conn
                        .search_user_playlists_by_name(id, &q, req.into())
                        .await?
                } else {
                    db_conn.user_playlists(id, req.into()).await?
                };
                let page = page
                    .map(|playlist| state.svc.converter().convert_playlist(playlist, &auth_usr));
                Ok((StatusCode::OK, Json(page)).into_response())
            } else {
                Ok(StatusCode::NOT_FOUND.into_response())
            }
        }
        .instrument(span)
        .await
    })
    .await
}

// user_spotify_playlists

#[inline]
pub async fn user_spotify_playlists<
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
                let page = if let Some(Some(q)) = q {
                    db_conn
                        .search_user_platform_playlists_by_name(
                            id,
                            Platform::Spotify,
                            &q,
                            req.into(),
                        )
                        .await?
                } else {
                    db_conn
                        .user_platform_playlists(id, Platform::Spotify, req.into())
                        .await?
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
}

// user_sources

#[inline]
pub async fn user_sources<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    id: Uuid,
    headers: &HeaderMap,
    req: PageRequestQueryParams<25>,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    handling_error(async {
        let mut db_conn = state.db.acquire().await?;
        let auth_usr = state.svc.auth().authenticate(headers, &mut db_conn).await?;
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
                let page = db_conn
                    .user_sources(id, req.into())
                    .await?
                    .map(|src| state.svc.converter().convert_source(src, &auth_usr));
                Ok((StatusCode::OK, Json(page)).into_response())
            } else {
                Ok(StatusCode::NOT_FOUND.into_response())
            }
        }
        .instrument(span)
        .await
    })
    .await
}

// users

#[inline]
pub async fn users<
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
            "users",
            auth.usr.id = %auth_usr.id,
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = q,
        );
        async {
            ensure_user_is_admin!(auth_usr);
            let page = if let Some(Some(q)) = q {
                db_conn.search_users_by_email(&q, req.into()).await?
            } else {
                db_conn.users(req.into()).await?
            };
            let page = page.map(|usr| state.svc.converter().convert_user(usr));
            Ok((StatusCode::OK, Json(page)))
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
        api::{
            PlaylistResponse, SourceResponse, UserResponse, PATH_PLAYLIST, PATH_REFRESH,
            PATH_SPOTIFY, PATH_SRC, PATH_USR,
        },
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Page, PageRequest, Platform, PlatformPlaylist, Playlist, Predicate, Role, Source,
            SourceKind, SpotifySourceKind, Synchronization, Target, User,
        },
    };
    use axum_test::TestResponse;
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::{always, eq};
    use uuid::Uuid;

    use crate::{
        auth::MockAuthenticator,
        conv::{Converter, DefaultConverter, MockConverter},
        pull::MockPlaylistsPuller,
        test::init,
        ApiError, ApiResult, MockServices,
    };

    use super::*;

    // Mods

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
                params: Some(SearchQueryParam { q: Some(q.into()) }),
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
                params: Some(SearchQueryParam { q: Some(q.into()) }),
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
            search: Mock<()>,
            usrs: Mock<()>,
        }

        // Tests

        async fn run(data: Data, mocks: Mocks) -> (TestResponse, Page<UserResponse>) {
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
                        conn.0
                            .expect_search_users_by_email()
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
                .get(PATH_USR)
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
                usrs: Mock::once(|| ()),
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
                params: Some(SearchQueryParam { q: Some(q.into()) }),
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
}
