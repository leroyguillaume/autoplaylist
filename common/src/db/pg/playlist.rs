use magic_crypt::MagicCrypt256;
use sqlx::{query_file, query_file_as, Acquire, PgConnection, Postgres};
use tracing::{debug, info_span, trace, Instrument};
use uuid::Uuid;

use crate::{
    db::PlaylistCreation,
    model::{Page, PageRequest, Platform, Playlist, Role, Track},
};

use super::{PlaylistRecord, PostgresResult, TrackRecord};

// add_track_to_playlist

#[inline]
pub async fn add_track_to_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = info_span!(
        "add_track_to_playlist",
        playlist.id = %playlist_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("adding track to playlist");
        query_file!(
            "resources/main/db/pg/queries/add-track-to-playlist.sql",
            playlist_id,
            track_id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// create_playlist

#[inline]
pub async fn create_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &PlaylistCreation,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Playlist> {
    let span = info_span!(
        "create_playlist",
        playlist.name = creation.name,
        playlist.src.kind = %creation.src.kind,
        playlist.src.owner.id = %creation.src.owner.id,
        playlist.src.sync = %creation.src.sync,
    );
    async {
        trace!("serializing playlist predicate");
        let predicate = serde_json::to_value(&creation.predicate)?;
        trace!("serializing playlist target");
        let tgt = serde_json::to_value(&creation.tgt)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating playlist");
        let record = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/create-playlist.sql",
            creation.name,
            &predicate,
            creation.src.id,
            &tgt,
        )
        .fetch_one(&mut *conn)
        .await?;
        let playlist = record.into_entity(key)?;
        debug!(%playlist.id, %playlist.sync, "playlist created");
        Ok(playlist)
    }
    .instrument(span)
    .await
}

// delete_playlist

#[inline]
pub async fn delete_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "delete_playlist",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting playlist");
        let res = query_file!("resources/main/db/pg/queries/delete-playlist.sql", id,)
            .execute(&mut *conn)
            .await?;
        let deleted = res.rows_affected() > 0;
        if deleted {
            debug!("playlist deleted");
        }
        Ok(deleted)
    }
    .instrument(span)
    .await
}

// delete_tracks_from_playlist

#[inline]
pub async fn delete_tracks_from_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<u64> {
    let span = info_span!(
        "delete_tracks_from_playlist",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting tracks");
        let res = query_file!(
            "resources/main/db/pg/queries/delete-tracks-from-playlist.sql",
            id,
        )
        .execute(&mut *conn)
        .await?;
        let count = res.rows_affected();
        debug!(count, "tracks deleted");
        Ok(count)
    }
    .instrument(span)
    .await
}

// playlist_by_id

#[inline]
pub async fn playlist_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Playlist>> {
    let span = info_span!(
        "playlist_by_id",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching playlist");
        let record = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/playlist-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let playlist = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(playlist)
    }
    .instrument(span)
    .await
}

// playlist_contains_track

#[inline]
pub async fn playlist_contains_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "playlist_contains_track",
        playlist.id = %playlist_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if playlist contains track");
        let record = query_file!(
            "resources/main/db/pg/queries/playlist-contains-track.sql",
            playlist_id,
            track_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let contains = record.contains.unwrap_or(false);
        Ok(contains)
    }
    .instrument(span)
    .await
}

// playlist_exists

#[inline]
pub async fn playlist_exists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "playlist_exists",
        playlist.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if playlist exists");
        let record = query_file!("resources/main/db/pg/queries/playlist-exists.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let exists = record.exists.unwrap_or(false);
        Ok(exists)
    }
    .instrument(span)
    .await
}

// playlist_ids_by_source

#[inline]
pub async fn playlist_ids_by_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Uuid>> {
    let span = info_span!(
        "playlist_ids_by_source",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlists");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-playlists.sql",
            src_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlist IDs");
        let records = query_file!(
            "resources/main/db/pg/queries/playlist-ids-by-source.sql",
            src_id,
            limit,
            offset,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Page {
            first: req.offset == 0,
            items: records.into_iter().map(|record| record.id).collect(),
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// playlist_tracks

#[inline]
pub async fn playlist_tracks<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = info_span!(
        "playlist_tracks",
        params.limit = req.limit,
        params.offset = req.offset,
        playlist.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlist tracks");
        let record = query_file!("resources/main/db/pg/queries/count-playlist-tracks.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlist tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/playlist-tracks.sql",
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
                .map(|record| record.into_entity())
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// playlists

#[inline]
pub async fn playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = info_span!(
        "playlists",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlists");
        let record = query_file!("resources/main/db/pg/queries/count-playlists.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlists");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/playlists.sql",
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

// search_playlist_tracks_by_title_artists_album

#[inline]
pub async fn search_playlist_tracks_by_title_artists_album<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    q: &str,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = info_span!(
        "search_playlist_tracks_by_title_artists_album",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
        playlist.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlist tracks matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-playlist-tracks-by-title-artists-album.sql",
            id,
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlist tracks matching query");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/search-playlist-tracks-by-title-artists-album.sql",
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
                .map(|record| record.into_entity())
                .collect::<PostgresResult<Vec<_>>>()?,
            last: (req.offset + req.limit) >= total,
            req,
            total,
        })
    }
    .instrument(span)
    .await
}

// search_playlists_by_name

#[inline]
pub async fn search_playlists_by_name<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    q: &str,
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Playlist>> {
    let span = info_span!(
        "search_playlists_by_name",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting playlists matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-playlists-by-name.sql",
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching playlists matching query");
        let records = query_file_as!(
            PlaylistRecord,
            "resources/main/db/pg/queries/search-playlists-by-name.sql",
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

// update_playlist

#[inline]
pub async fn update_playlist<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    playlist: &Playlist,
    safely: bool,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "update_playlist",
        %playlist.id,
        playlist.name,
        %playlist.src.kind,
        %playlist.src.owner.id,
        %playlist.src.sync,
        %playlist.sync,
    );
    async {
        trace!("serializing playlist predicate");
        let predicate = serde_json::to_value(&playlist.predicate)?;
        trace!("serializing playlist synchronization");
        let sync = serde_json::to_value(&playlist.sync)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating playlist");
        let query = if safely {
            query_file!(
                "resources/main/db/pg/queries/update-playlist-safely.sql",
                playlist.id,
                playlist.name,
                predicate,
                sync,
            )
        } else {
            query_file!(
                "resources/main/db/pg/queries/update-playlist.sql",
                playlist.id,
                playlist.name,
                predicate,
                sync,
            )
        };
        let res = query.execute(&mut *conn).await?;
        let updated = res.rows_affected() > 0;
        if updated {
            debug!("playlist updated");
        }
        Ok(updated)
    }
    .instrument(span)
    .await
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
        model::{Predicate, Synchronization, Target},
    };

    use super::*;

    // Mods

    mod client {
        use super::*;

        // Mods

        mod add_track_to_playlist {
            use super::*;

            // run

            async fn run(track_idx: usize, db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[track_idx].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.add_track_to_playlist(playlist_id, track_id)
                    .await
                    .expect("failed to add track");
                let contains = conn
                    .playlist_contains_track(playlist_id, track_id)
                    .await
                    .expect("failed to check if playlist contains track");
                assert!(contains);
            }

            // Tests

            #[sqlx::test]
            async fn unit_when_track_was_already_added(db: PgPool) {
                run(0, db).await;
            }

            #[sqlx::test]
            async fn unit_when_track_was_added(db: PgPool) {
                run(1, db).await;
            }
        }

        mod create_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn playlist(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = PlaylistCreation {
                    name: "playlist_5".into(),
                    predicate: Predicate::YearIs(2023),
                    src: data.srcs[0].clone(),
                    tgt: Target::Spotify("playlist_5".into()),
                };
                let playlist = conn
                    .create_playlist(&creation)
                    .await
                    .expect("failed to create playlist");
                assert_eq!(playlist.name, creation.name);
                assert_eq!(playlist.predicate, creation.predicate);
                assert_eq!(playlist.src, creation.src);
                assert_eq!(playlist.tgt, creation.tgt);
                let playlist_fetched = conn
                    .playlist_by_id(playlist.id)
                    .await
                    .expect("failed to fetch playlist")
                    .expect("playlist doesn't exist");
                assert_eq!(playlist, playlist_fetched);
            }
        }

        mod delete_playlist {
            use super::*;

            // run

            async fn run(id: Uuid, db: PgPool) -> bool {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let deleted = conn
                    .delete_playlist(id)
                    .await
                    .expect("failed to delete playlist");
                let playlist = conn
                    .playlist_by_id(id)
                    .await
                    .expect("failed to fetch playlist");
                assert!(playlist.is_none());
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
                let deleted = run(data.playlists[0].id, db).await;
                assert!(deleted);
            }
        }

        mod delete_tracks_from_playlist {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn count(db: PgPool) {
                let data = Data::new();
                let id = data.playlists[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let count = conn
                    .delete_tracks_from_playlist(id)
                    .await
                    .expect("failed to delete tracks");
                let page = conn
                    .playlist_tracks(id, PageRequest::new(100, 0))
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page.total, 0);
                assert_eq!(count, 3);
            }
        }

        mod playlist_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let playlist = conn
                    .playlist_by_id(id)
                    .await
                    .expect("failed to fetch playlist");
                assert_eq!(playlist, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn playlist(db: PgPool) {
                let data = Data::new();
                let playlist = &data.playlists[0];
                run(playlist.id, Some(playlist), db).await;
            }
        }

        mod playlist_contains_track {
            use super::*;

            // run

            async fn run(playlist_id: Uuid, track_id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let contains = conn
                    .playlist_contains_track(playlist_id, track_id)
                    .await
                    .expect("failed to check if playlist contains track");
                assert_eq!(contains, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_playlist_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[1].id;
                let track_id = data.tracks[0].id;
                run(playlist_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn false_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[3].id;
                run(playlist_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn true_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let playlist_id = data.playlists[0].id;
                let track_id = data.tracks[0].id;
                run(playlist_id, track_id, true, db).await;
            }
        }

        mod playlist_exists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let exists = conn
                    .playlist_exists(id)
                    .await
                    .expect("failed to check if playlist exists");
                assert_eq!(exists, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_playlist_doesnt_exist(db: PgPool) {
                run(Uuid::new_v4(), false, db).await;
            }

            #[sqlx::test]
            async fn true_when_playlist_exists(db: PgPool) {
                let data = Data::new();
                let id = data.playlists[0].id;
                run(id, true, db).await;
            }
        }

        mod playlist_ids_by_source {
            use super::*;

            // run

            async fn run(src_id: Uuid, expected: Page<Uuid>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .playlist_ids_by_source(src_id, expected.req)
                    .await
                    .expect("failed to fetch playlist IDs");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.playlists[0].id,
                        data.playlists[1].id,
                        data.playlists[2].id,
                    ],
                    last: true,
                    req: PageRequest::new(3, 0),
                    total: 3,
                };
                run(data.srcs[0].id, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].id],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.srcs[0].id, expected, db).await;
            }
        }

        mod playlists {
            use super::*;

            // run

            async fn run(expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .playlists(expected.req)
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
                    items: data.playlists.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .playlists
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.playlists[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .playlists
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod search_playlist_tracks_by_title_artists_album {
            use super::*;

            // run

            async fn run(id: Uuid, q: &str, expected: Page<Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_playlist_tracks_by_title_artists_album(id, q, expected.req)
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last_with_title(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.tracks[1].clone()],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(data.playlists[0].id, "EvEr", expected, db).await;
            }

            #[sqlx::test]
            async fn first_and_last_with_artists(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.tracks[1].clone()],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(data.playlists[0].id, "HuCk", expected, db).await;
            }

            #[sqlx::test]
            async fn first_and_last_with_album(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.tracks[1].clone()],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(data.playlists[0].id, "OuIs", expected, db).await;
            }

            #[sqlx::test]
            async fn first_and_last_with_all(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.tracks[0].clone(),
                        data.tracks[1].clone(),
                        data.tracks[2].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                run(data.playlists[0].id, "n", expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.tracks[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                run(data.playlists[0].id, "n", expected, db).await;
            }
        }

        mod search_playlists_by_name {
            use super::*;

            // run

            async fn run(q: &str, expected: Page<Playlist>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_playlists_by_name(q, expected.req)
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
                        data.playlists[3].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 4,
                };
                run("lAyLiSt", expected, db).await;
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
                run("lAyLiSt", expected, db).await;
            }
        }

        mod update_playlist {
            use super::*;

            // run

            async fn run(id: Uuid, playlist: &Playlist, expected: bool, db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let playlist_expected = Playlist {
                    name: "playlist_1_2".into(),
                    predicate: Predicate::YearIs(1983),
                    sync: Synchronization::Running(Utc::now()),
                    ..playlist.clone()
                };
                let playlist_updated = Playlist {
                    creation: Utc::now(),
                    id,
                    name: playlist_expected.name.clone(),
                    predicate: playlist_expected.predicate.clone(),
                    src: data.srcs[1].clone(),
                    sync: playlist_expected.sync.clone(),
                    tgt: Target::Spotify("playlist_1_2".into()),
                };
                let updated = conn
                    .update_playlist(&playlist_updated)
                    .await
                    .expect("failed to update playlist");
                if expected {
                    assert!(updated);
                    let playlist = conn
                        .playlist_by_id(id)
                        .await
                        .expect("failed to fetch source")
                        .expect("source doesn't exist");
                    assert_eq!(playlist, playlist_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.playlists[0], false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let playlist = &data.playlists[0];
                run(playlist.id, playlist, true, db).await;
            }
        }

        mod update_playlist_safely {
            use super::*;

            // run

            async fn run(id: Uuid, playlist: &Playlist, expected: bool, db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let playlist_expected = Playlist {
                    name: "playlist_1_2".into(),
                    predicate: Predicate::YearIs(1983),
                    sync: Synchronization::Running(Utc::now()),
                    ..playlist.clone()
                };
                let playlist_updated = Playlist {
                    creation: Utc::now(),
                    id,
                    name: playlist_expected.name.clone(),
                    predicate: playlist_expected.predicate.clone(),
                    src: data.srcs[1].clone(),
                    sync: playlist_expected.sync.clone(),
                    tgt: Target::Spotify("playlist_1_2".into()),
                };
                let updated = conn
                    .update_playlist_safely(&playlist_updated)
                    .await
                    .expect("failed to update playlist");
                if expected {
                    assert!(updated);
                    let playlist = conn
                        .playlist_by_id(id)
                        .await
                        .expect("failed to fetch source")
                        .expect("source doesn't exist");
                    assert_eq!(playlist, playlist_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no_when_playlist_doesnt_exist(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.playlists[0], false, db).await;
            }

            #[sqlx::test]
            async fn no_when_sync_is_running(db: PgPool) {
                let data = Data::new();
                let playlist = &data.playlists[1];
                run(playlist.id, playlist, false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let playlist = &data.playlists[0];
                run(playlist.id, playlist, true, db).await;
            }
        }
    }
}
