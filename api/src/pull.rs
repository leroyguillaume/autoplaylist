use std::{future::Future, pin::Pin};

use autoplaylist_common::{
    db::DatabaseClient,
    model::{PageRequest, Platform, User},
    spotify::{self, SpotifyClient},
};

use crate::{ApiError, ApiResult};

// PlaylistsPuller

#[cfg_attr(test, mockall::automock)]
pub trait PlaylistsPuller: Send + Sync {
    fn pull_spotify<'a, 'b, 'c, 'd, 'e>(
        &'a self,
        usr: &'b mut User,
        spotify: &'c dyn SpotifyClient,
        db_conn: &'d mut dyn DatabaseClient,
    ) -> Pin<Box<dyn Future<Output = ApiResult<()>> + Send + 'e>>
    where
        'a: 'e,
        'b: 'e,
        'c: 'e,
        'd: 'e;
}

// DefaultPlaylistsPuller

pub struct DefaultPlaylistsPuller;

impl PlaylistsPuller for DefaultPlaylistsPuller {
    fn pull_spotify<'a, 'b, 'c, 'd, 'e>(
        &'a self,
        usr: &'b mut User,
        spotify: &'c dyn SpotifyClient,
        db_conn: &'d mut dyn DatabaseClient,
    ) -> Pin<Box<dyn Future<Output = ApiResult<()>> + Send + 'e>>
    where
        'a: 'e,
        'b: 'e,
        'c: 'e,
        'd: 'e,
    {
        Box::pin(async move {
            let creds = usr
                .creds
                .spotify
                .as_mut()
                .ok_or(ApiError::NoSpotifyCredentials)?;
            db_conn
                .delete_user_platform_playlists(usr.id, Platform::Spotify)
                .await?;
            let mut req = PageRequest::new(spotify::PAGE_LIMIT_MAX, 0);
            loop {
                let page = spotify
                    .authenticated_user_playlists(req, &mut creds.token)
                    .await?;
                for playlist in page.items {
                    db_conn
                        .save_user_platform_playlist(usr.id, &playlist)
                        .await?;
                }
                if page.last {
                    break;
                } else {
                    req.offset += spotify::PAGE_LIMIT_MAX;
                }
            }
            db_conn.update_user(usr).await?;
            Ok(())
        })
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::{
        db::MockDatabaseClient,
        model::{Credentials, Page, PlatformPlaylist, Role, SpotifyCredentials, SpotifyToken},
        spotify::MockSpotifyClient,
    };
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use super::*;

    // Mods

    mod default_playlists_puller {
        use super::*;

        mod pull_spotify {
            use super::*;

            // Mocks

            #[derive(Default)]
            struct Mocks {
                del: Mock<()>,
                playlists: Mock<()>,
                save: Mock<()>,
                update: Mock<()>,
            }

            // Tests

            async fn run(mut usr: User, token: SpotifyToken, mocks: Mocks) -> ApiResult<()> {
                let playlist_1 = PlatformPlaylist {
                    id: "id_1".into(),
                    name: "name_1".into(),
                    platform: Platform::Spotify,
                };
                let playlist_2 = PlatformPlaylist {
                    id: "id_2".into(),
                    name: "name_2".into(),
                    platform: Platform::Spotify,
                };
                let req_1 = PageRequest::new(spotify::PAGE_LIMIT_MAX, 0);
                let req_2 = PageRequest::new(spotify::PAGE_LIMIT_MAX, spotify::PAGE_LIMIT_MAX);
                let mut spotify = MockSpotifyClient::new();
                spotify
                    .expect_authenticated_user_playlists()
                    .with(eq(req_1), eq(token.clone()))
                    .times(mocks.playlists.times())
                    .returning({
                        let playlist = playlist_1.clone();
                        move |_, _| {
                            Ok(Page {
                                first: true,
                                items: vec![playlist.clone()],
                                last: false,
                                req: req_1,
                                total: 2,
                            })
                        }
                    });
                spotify
                    .expect_authenticated_user_playlists()
                    .with(eq(req_2), eq(token.clone()))
                    .times(mocks.playlists.times())
                    .returning({
                        let playlist = playlist_2.clone();
                        move |_, _| {
                            Ok(Page {
                                first: false,
                                items: vec![playlist.clone()],
                                last: true,
                                req: req_2,
                                total: 2,
                            })
                        }
                    });
                let mut db_conn = MockDatabaseClient::new();
                db_conn
                    .expect_delete_user_platform_playlists()
                    .with(eq(usr.id), eq(Platform::Spotify))
                    .times(mocks.del.times())
                    .returning(|_, _| Ok(1));
                db_conn
                    .expect_save_user_platform_playlist()
                    .with(eq(usr.id), eq(playlist_1))
                    .times(mocks.save.times())
                    .returning(|_, _| Ok(()));
                db_conn
                    .expect_save_user_platform_playlist()
                    .with(eq(usr.id), eq(playlist_2))
                    .times(mocks.save.times())
                    .returning(|_, _| Ok(()));
                db_conn
                    .expect_update_user()
                    .with(eq(usr.clone()))
                    .times(mocks.update.times())
                    .returning(|_| Ok(true));
                let puller = DefaultPlaylistsPuller;
                puller.pull_spotify(&mut usr, &spotify, &mut db_conn).await
            }

            // Tests

            #[tokio::test]
            async fn no_spotify_credentials() {
                let token = SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                };
                let usr = User {
                    id: Uuid::new_v4(),
                    creation: Utc::now(),
                    creds: Default::default(),
                    role: Role::User,
                };
                let mocks = Mocks::default();
                let err = run(usr, token, mocks)
                    .await
                    .expect_err("pulling playlists should fail");
                assert!(matches!(err, ApiError::NoSpotifyCredentials));
            }

            #[tokio::test]
            async fn unit() {
                let token = SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                };
                let usr = User {
                    id: Uuid::new_v4(),
                    creation: Utc::now(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "user@test".into(),
                            id: "id".into(),
                            token: token.clone(),
                        }),
                    },
                    role: Role::User,
                };
                let mocks = Mocks {
                    del: Mock::once(|| ()),
                    playlists: Mock::once(|| ()),
                    save: Mock::once(|| ()),
                    update: Mock::once(|| ()),
                };
                run(usr, token, mocks)
                    .await
                    .expect("failed to pull playlists");
            }
        }
    }
}
