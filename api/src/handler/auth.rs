use autoplaylist_common::{
    api::{AuthenticateViaSpotifyQueryParams, JwtResponse, RedirectUriQueryParam},
    db::{DatabaseConnection, DatabasePool, DatabaseTransaction},
    model::{Credentials, SpotifyCredentials},
    transactional,
};
use axum::{
    http::{header, StatusCode},
    response::Response,
    Json,
};
use tracing::{info, info_span, Instrument};

use crate::{handling_error, AppState, Services};

// authenticate_via_spotify

#[inline]
pub async fn authenticate_via_spotify<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    params: AuthenticateViaSpotifyQueryParams,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    let span = info_span!("authenticate_via_spotify", params.code, params.redirect_uri);
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
                    state
                        .svc
                        .playlists_puller()
                        .pull_spotify(&mut usr, spotify, db_tx.as_client_mut())
                        .await?;
                    (usr, true)
                }
            };
            let jwt = state.svc.jwt().encode(&usr)?;
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
}

// spotify_authorize_url

#[inline]
pub async fn spotify_authorize_url<
    DBCONN: DatabaseConnection + 'static,
    DBTX: DatabaseTransaction + 'static,
    DB: DatabasePool<DBCONN, DBTX> + 'static,
    SVC: Services + 'static,
>(
    params: RedirectUriQueryParam,
    state: &AppState<DBCONN, DBTX, DB, SVC>,
) -> Response {
    let span = info_span!("spotify_authorize_url", params.redirect_uri);
    handling_error(async {
        let url = state.svc.spotify().authorize_url(&params.redirect_uri)?;
        Ok(([(header::LOCATION, url)], StatusCode::MOVED_PERMANENTLY))
    })
    .instrument(span)
    .await
}

// Tests

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use autoplaylist_common::{
        api::{PATH_AUTH, PATH_SPOTIFY, PATH_TOKEN},
        db::{MockDatabasePool, MockDatabaseTransaction},
        model::{Role, SpotifyToken, User},
        spotify::{MockSpotifyClient, SpotifyUser},
    };
    use axum_test::TestResponse;
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::{always, eq};
    use uuid::Uuid;

    use crate::{jwt::MockJwtProvider, pull::MockPlaylistsPuller, test::init, MockServices};

    use super::*;

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
                .expect_encode()
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
}
