use magic_crypt::{MagicCrypt256, MagicCryptTrait};
use sqlx::{query_file, query_file_as, Acquire, PgConnection, Postgres};
use tracing::{debug, info_span, trace, Instrument};
use uuid::Uuid;

use crate::model::{
    Credentials, Page, PageRequest, Platform, PlatformPlaylist, Playlist, Role, Source, User,
};

use super::{
    PlatformPlaylistRecord, PlaylistRecord, PostgresResult, SourceRecord, SpotifyPublicCredentials,
    UserRecord,
};

// create_user

#[inline]
pub async fn create_user<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creds: &Credentials,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<User> {
    let span = info_span!("create_user");
    async {
        let spotify_creds = creds
            .spotify
            .as_ref()
            .map(|creds| SpotifyPublicCredentials::from(creds.clone()));
        trace!("serializing Spotify credentials");
        let spotify_creds = serde_json::to_value(&spotify_creds)?;
        let creds = encrypt_credentials(creds, key)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/create-user.sql",
            &spotify_creds,
            &creds,
        )
        .fetch_one(&mut *conn)
        .await?;
        let usr = record.into_entity(key)?;
        debug!(%usr.id, "user created");
        Ok(usr)
    }
    .instrument(span)
    .await
}

// delete_user

#[inline]
pub async fn delete_user<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "delete_user",
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting user");
        let res = query_file!("resources/main/db/pg/queries/delete-user.sql", id,)
            .execute(&mut *conn)
            .await?;
        let deleted = res.rows_affected() > 0;
        if deleted {
            debug!("user deleted");
        }
        Ok(deleted)
    }
    .instrument(span)
    .await
}

// delete_user_platform_playlists

#[inline]
pub async fn delete_user_platform_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    platform: Platform,
    conn: A,
) -> PostgresResult<u64> {
    let span = info_span!(
        "delete_user_platform_playlists",
        platform_playlist.platform = %platform,
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting user platform playlists");
        let res = query_file!(
            "resources/main/db/pg/queries/delete-user-platform-playlists.sql",
            id,
            platform as _,
        )
        .execute(&mut *conn)
        .await?;
        let count = res.rows_affected();
        debug!(count, "user platform playlists deleted");
        Ok(count)
    }
    .instrument(span)
    .await
}

// save_user_platform_playlist

#[inline]
pub async fn save_user_platform_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    playlist: &PlatformPlaylist,
    conn: A,
) -> PostgresResult<()> {
    let span = info_span!(
        "save_user_platform_playlist",
        platform_playlist.id = playlist.id,
        platform_playlist.name = playlist.name,
        platform_playlist.platform = %playlist.platform,
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("saving user platform playlist");
        query_file!(
            "resources/main/db/pg/queries/save-user-platform-playlist.sql",
            playlist.id,
            id,
            playlist.name,
            playlist.platform as _,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// search_user_platform_playlists_by_name

#[inline]
pub async fn search_user_platform_playlists_by_name<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    platform: Platform,
    q: &str,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<PlatformPlaylist>> {
    let span = info_span!(
        "search_user_platform_playlists_by_name",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
        playlist.platform = %platform,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user platform playlists matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-user-platform-playlists-by-name.sql",
            &id,
            platform as _,
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user platform playlists matching query");
        let records = query_file_as!(
            PlatformPlaylistRecord,
            "resources/main/db/pg/queries/search-user-platform-playlists-by-name.sql",
            &id,
            platform as _,
            q,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity())
                .collect(),
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// search_user_playlists_by_name

#[inline]
pub async fn search_user_playlists_by_name<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    q: &str,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = info_span!(
        "search_user_playlists_by_name",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user playlists matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-user-playlists-by-name.sql",
            id,
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user playlists matching query");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/search-user-playlists-by-name.sql",
            id,
            q,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// search_users_by_email

#[inline]
pub async fn search_users_by_email<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    q: &str,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<User>> {
    let span = info_span!(
        "search_users_by_email",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting users matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-users-by-email.sql",
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching users matching query");
        let records = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/search-users-by-email.sql",
            q,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// update_user

#[inline]
pub async fn update_user<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    usr: &User,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "update_user",
        %usr.id,
        %usr.role,
    );
    async {
        let spotify_creds = usr
            .creds
            .spotify
            .as_ref()
            .map(|creds| SpotifyPublicCredentials::from(creds.clone()));
        trace!("serializing Spotify credentials");
        let spotify_creds = serde_json::to_value(&spotify_creds)?;
        let creds = encrypt_credentials(&usr.creds, key)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating user");
        let res = query_file!(
            "resources/main/db/pg/queries/update-user.sql",
            usr.id,
            usr.role as _,
            &spotify_creds,
            creds,
        )
        .execute(&mut *conn)
        .await?;
        let updated = res.rows_affected() > 0;
        if updated {
            debug!("user updated");
        }
        Ok(updated)
    }
    .instrument(span)
    .await
}

// user_by_id

#[inline]
pub async fn user_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<User>> {
    let span = info_span!(
        "user_by_id",
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/user-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let usr = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(usr)
    }
    .instrument(span)
    .await
}

// user_by_spotify_id

#[inline]
pub async fn user_by_spotify_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: &str,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<User>> {
    let span = info_span!(
        "user_by_spotify_id",
        usr.creds.spotify.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching user");
        let record = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/user-by-spotify-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let usr = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(usr)
    }
    .instrument(span)
    .await
}

// user_exists

#[inline]
pub async fn user_exists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "user_exists",
        usr.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if user exists");
        let record = query_file!("resources/main/db/pg/queries/user-exists.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let exists = record.exists.unwrap_or(false);
        Ok(exists)
    }
    .instrument(span)
    .await
}

// user_platform_playlists

#[inline]
pub async fn user_platform_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    platform: Platform,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<PlatformPlaylist>> {
    let span = info_span!(
        "user_platform_playlists",
        params.limit = req.limit,
        params.offset = req.offset,
        playlist_platform.platform = %platform,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user platform playlists");
        let record = query_file!(
            "resources/main/db/pg/queries/count-user-platform-playlists.sql",
            id,
            platform as _,
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user platform playlists");
        let records = query_file_as!(
            PlatformPlaylistRecord,
            "resources/main/db/pg/queries/user-platform-playlists.sql",
            id,
            platform as _,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity())
                .collect(),
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// user_playlists

#[inline]
pub async fn user_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = info_span!(
        "user_playlists",
        params.limit = req.limit,
        params.offset = req.offset,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user playlists");
        let record = query_file!("resources/main/db/pg/queries/count-user-playlists.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user playlists");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/user-playlists.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// user_sources

#[inline]
pub async fn user_sources<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Source>> {
    let span = info_span!(
        "user_sources",
        params.limit = req.limit,
        params.offset = req.offset,
        usr.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting user playlists");
        let record = query_file!("resources/main/db/pg/queries/count-user-sources.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching user sources");
        let records = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/user-sources.sql",
            id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// users

#[inline]
pub async fn users<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<User>> {
    let span = info_span!(
        "users",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting users");
        let record = query_file!("resources/main/db/pg/queries/count-users.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching users");
        let records = query_file_as!(
            UserRecord,
            "resources/main/db/pg/queries/users.sql",
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records
                .into_iter()
                .map(|record| record.into_entity(key))
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// encrypt_credentials

#[inline]
fn encrypt_credentials(creds: &Credentials, key: &MagicCrypt256) -> PostgresResult<String> {
    trace!("serializing user credentials");
    let creds = serde_json::to_string(creds)?;
    trace!("encrypting user credentials");
    Ok(key.encrypt_str_to_base64(creds))
}

// Tests

#[cfg(test)]
mod test {
    use chrono::Utc;
    use sqlx::PgPool;

    use crate::{
        db::{
            pg::test::{init, Data},
            DatabaseClient, DatabasePool,
        },
        model::{Credentials, SpotifyCredentials, SpotifyToken},
    };

    use super::*;

    // Mods

    mod client {
        use super::*;

        // Mods

        mod create_user {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn user(db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let spotify_id = "user_4";
                let creds = Credentials {
                    spotify: Some(SpotifyCredentials {
                        email: "user_4@test".into(),
                        id: spotify_id.into(),
                        token: SpotifyToken {
                            access: "access".into(),
                            expiration: Utc::now(),
                            refresh: "refresh".into(),
                        },
                    }),
                };
                let usr = conn
                    .create_user(&creds)
                    .await
                    .expect("failed to create user");
                assert_eq!(usr.creds, creds);
                let usr_fetched = conn
                    .user_by_id(usr.id)
                    .await
                    .expect("failed to fetch user")
                    .expect("user doesn't exist");
                assert_eq!(usr, usr_fetched);
                let usr_fetched = conn
                    .user_by_spotify_id(spotify_id)
                    .await
                    .expect("failed to fetch user")
                    .expect("user doesn't exist");
                assert_eq!(usr, usr_fetched);
            }
        }

        mod delete_user {
            use super::*;

            // run

            async fn run(id: Uuid, db: PgPool) -> bool {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let deleted = conn.delete_user(id).await.expect("failed to delete user");
                let usr = conn.user_by_id(id).await.expect("failed to fetch user");
                assert!(usr.is_none());
                deleted
            }

            // Tests

            #[sqlx::test]
            async fn no(db: PgPool) {
                let deleted = run(Uuid::new_v4(), db).await;
                assert!(!deleted);
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let id = data.usrs[0].usr.id;
                let deleted = run(id, db).await;
                assert!(deleted);
            }
        }

        mod delete_user_platform_playlists {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn count(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let id = data.usrs[0].usr.id;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let count = conn
                    .delete_user_platform_playlists(id, Platform::Spotify)
                    .await
                    .expect("failed to delete user platform playlists");
                assert_eq!(count, 4);
            }
        }

        mod save_user_platform_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let id = data.usrs[0].usr.id;
                let playlist = PlatformPlaylist {
                    id: "playlist_5".into(),
                    name: "playlist_5".into(),
                    platform: Platform::Spotify,
                };
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.save_user_platform_playlist(id, &playlist)
                    .await
                    .expect("failed to save user platform playlist");
                let playlists = conn
                    .user_platform_playlists(id, playlist.platform, PageRequest::new(100, 0))
                    .await
                    .expect("failed to fetch user platform playlists");
                assert!(playlists.items.contains(&playlist));
            }
        }

        mod search_user_platform_playlists_by_name {
            use super::*;

            // run

            async fn run(id: Uuid, q: &str, expected: Page<PlatformPlaylist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_user_platform_playlists_by_name(id, Platform::Spotify, q, expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                let expected = Page {
                    first: true,
                    items: vec![
                        usr.spotify_playlists[0].clone(),
                        usr.spotify_playlists[1].clone(),
                        usr.spotify_playlists[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(usr.usr.id, "lAyLiSt", expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                let expected = Page {
                    first: false,
                    items: vec![usr.spotify_playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(usr.usr.id, "lAyLiSt", expected, db).await;
            }
        }

        mod search_user_playlists_by_name {
            use super::*;

            // run

            async fn run(id: Uuid, q: &str, expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_user_playlists_by_name(id, q, expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.playlists[0].clone(),
                        data.playlists[1].clone(),
                        data.playlists[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(data.usrs[0].usr.id, "lAyLiSt", expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.usrs[0].usr.id, "lAyLiSt", expected, db).await;
            }
        }

        mod search_users_by_email {
            use super::*;

            // run

            async fn run(q: &str, expected: Page<User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_users_by_email(q, expected.req)
                    .await
                    .expect("failed to fetch users");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.usrs[0].usr.clone(),
                        data.usrs[1].usr.clone(),
                        data.usrs[4].usr.clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run("sEr", expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.usrs[1].usr.clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run("sEr", expected, db).await;
            }
        }

        mod update_user {
            use super::*;

            // run

            async fn run(id: Uuid, usr: &User, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let spotify_id = "user_1_2";
                let usr_expected = User {
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            email: "user_1_2@test".into(),
                            id: spotify_id.into(),
                            token: SpotifyToken {
                                access: "access".into(),
                                expiration: Utc::now(),
                                refresh: "refresh".into(),
                            },
                        }),
                    },
                    role: Role::User,
                    ..usr.clone()
                };
                let usr_updated = User {
                    creation: Utc::now(),
                    id,
                    ..usr_expected.clone()
                };
                let updated = conn
                    .update_user(&usr_updated)
                    .await
                    .expect("failed to update user");
                if expected {
                    assert!(updated);
                    let usr = conn
                        .user_by_id(id)
                        .await
                        .expect("failed to fetch user")
                        .expect("user doesn't exist");
                    assert_eq!(usr, usr_expected);
                    let usr = conn
                        .user_by_spotify_id(spotify_id)
                        .await
                        .expect("failed to fetch user")
                        .expect("user doesn't exist");
                    assert_eq!(usr, usr_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.usrs[0].usr, false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0].usr;
                run(usr.id, usr, true, db).await;
            }
        }

        mod user_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let usr = conn.user_by_id(id).await.expect("failed to fetch user");
                assert_eq!(usr, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn user(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0].usr;
                run(usr.id, Some(usr), db).await;
            }
        }

        mod user_by_spotify_id {
            use super::*;

            // run

            async fn run(id: &str, expected: Option<&User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let usr = conn
                    .user_by_spotify_id(id)
                    .await
                    .expect("failed to fetch user");
                assert_eq!(usr, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run("user_0", None, db).await;
            }

            #[sqlx::test]
            async fn user(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0].usr;
                run("user_1", Some(usr), db).await;
            }
        }

        mod user_exists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let exists = conn
                    .user_exists(id)
                    .await
                    .expect("failed to check if user exists");
                assert_eq!(exists, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_user_doesnt_exist(db: PgPool) {
                run(Uuid::new_v4(), false, db).await;
            }

            #[sqlx::test]
            async fn true_when_user_exists(db: PgPool) {
                let data = Data::new();
                let id = data.usrs[3].usr.id;
                run(id, true, db).await;
            }
        }

        mod user_playlists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .user_playlists(id, expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.playlists[0].clone(),
                        data.playlists[1].clone(),
                        data.playlists[2].clone(),
                        data.playlists[5].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 4,
                };
                run(data.usrs[0].usr.id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 4,
                };
                run(data.usrs[0].usr.id, expected, db).await;
            }
        }

        mod user_sources {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Page<Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .user_sources(id, expected.req)
                    .await
                    .expect("failed to fetch sources");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.srcs[0].clone(),
                        data.srcs[1].clone(),
                        data.srcs[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(data.usrs[0].usr.id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.srcs[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.usrs[0].usr.id, expected, db).await;
            }
        }

        mod user_platform_playlists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Page<PlatformPlaylist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .user_platform_playlists(id, Platform::Spotify, expected.req)
                    .await
                    .expect("failed to fetch playlists");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                let expected = Page {
                    first: true,
                    items: usr.spotify_playlists.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 4,
                };
                run(usr.usr.id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let usr = &data.usrs[0];
                let expected = Page {
                    first: false,
                    items: vec![usr.spotify_playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 4,
                };
                run(usr.usr.id, expected, db).await;
            }
        }

        mod users {
            use super::*;

            // run

            async fn run(expected: Page<User>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .users(expected.req)
                    .await
                    .expect("failed to fetch users");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.usrs.clone().into_iter().map(|usr| usr.usr).collect(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 5,
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.usrs[1].usr.clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 5,
                };
                run(expected, db).await;
            }
        }
    }
}
