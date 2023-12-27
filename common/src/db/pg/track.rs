use sqlx::{query_file, query_file_as, Acquire, PgConnection, Postgres};
use tracing::{debug, info_span, trace, Instrument};
use uuid::Uuid;

use crate::{
    db::TrackCreation,
    model::{Page, PageRequest, Platform, Track},
};

use super::{PostgresResult, TrackRecord};

// create_track

#[inline]
pub async fn create_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &TrackCreation,
    conn: A,
) -> PostgresResult<Track> {
    let album = creation.album.name.to_lowercase();
    let artists = creation
        .artists
        .iter()
        .map(|artist| artist.to_lowercase())
        .collect::<Vec<_>>();
    let title = creation.title.to_lowercase();
    let span = info_span!(
        "create_track",
        track.album.name = album,
        track.artists = ?artists,
        track.platform = %creation.platform,
        track.platform_id = creation.platform_id,
        track.title = title,
        track.year = creation.year,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/create-track.sql",
            title,
            &artists,
            album,
            creation.album.compil,
            creation.year,
            creation.platform as _,
            creation.platform_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let track = record.into_entity()?;
        debug!(%track.id, "track created");
        Ok(track)
    }
    .instrument(span)
    .await
}

// delete_track

#[inline]
pub async fn delete_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "delete_track",
        track.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting track");
        let res = query_file!("resources/main/db/pg/queries/delete-track.sql", id,)
            .execute(&mut *conn)
            .await?;
        let deleted = res.rows_affected() > 0;
        if deleted {
            debug!("track deleted");
        }
        Ok(deleted)
    }
    .instrument(span)
    .await
}

// search_tracks_by_title_artists_album

#[inline]
pub async fn search_tracks_by_title_artists_album<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    q: &str,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = info_span!(
        "search_tracks_by_title_artists_album",
        params.limit = req.limit,
        params.offset = req.offset,
        params.q = q,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting tracks matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-tracks-by-title-artists-album.sql",
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching tracks matching query");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/search-tracks-by-title-artists-album.sql",
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

// track_by_id

#[inline]
pub async fn track_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<Option<Track>> {
    let span = info_span!(
        "track_by_id",
        track.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/track-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let track = record.map(|record| record.into_entity()).transpose()?;
        Ok(track)
    }
    .instrument(span)
    .await
}

// track_by_platform_id

#[inline]
pub async fn track_by_platform_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    platform: Platform,
    id: &str,
    conn: A,
) -> PostgresResult<Option<Track>> {
    let span = info_span!(
        "track_by_platform_id",
        track.platform = %platform,
        track.platform_id = id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching track");
        let record = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/track-by-platform-id.sql",
            platform as _,
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let track = record.map(|record| record.into_entity()).transpose()?;
        Ok(track)
    }
    .instrument(span)
    .await
}

// tracks

#[inline]
pub async fn tracks<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = info_span!(
        "tracks",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting tracks");
        let record = query_file!("resources/main/db/pg/queries/count-tracks.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/tracks.sql",
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

// update_track

#[inline]
pub async fn update_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    track: &Track,
    conn: A,
) -> PostgresResult<bool> {
    let album = track.album.name.to_lowercase();
    let artists = track
        .artists
        .iter()
        .map(|artist| artist.to_lowercase())
        .collect::<Vec<_>>();
    let title = track.title.to_lowercase();
    let span = info_span!(
        "update_track",
        track.album.name = album,
        track.artists = ?artists,
        %track.id,
        %track.platform,
        track.platform_id,
        track.title = title,
        track.year,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating track");
        let res = query_file!(
            "resources/main/db/pg/queries/update-track.sql",
            track.id,
            title,
            &artists,
            album,
            track.album.compil,
            track.year,
        )
        .execute(&mut *conn)
        .await?;
        let updated = res.rows_affected() > 0;
        if updated {
            debug!("track updated");
        }
        Ok(updated)
    }
    .instrument(span)
    .await
}

// Tests

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use chrono::Utc;
    use sqlx::PgPool;

    use crate::{
        db::{
            pg::test::{init, Data},
            DatabaseClient, DatabasePool,
        },
        model::Album,
    };

    use super::*;

    // Mods

    mod client {
        use super::*;

        // Mods

        mod create_track {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn track(db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = TrackCreation {
                    album: Album {
                        compil: false,
                        name: "The Dark Side of the Moon".into(),
                    },
                    artists: vec!["Pink Floyd".into()].into_iter().collect(),
                    platform: Platform::Spotify,
                    platform_id: "track_5".into(),
                    title: "Time".into(),
                    year: 1973,
                };
                let track = conn
                    .create_track(&creation)
                    .await
                    .expect("failed to create track");
                assert_eq!(track.album.name, creation.album.name.to_lowercase());
                assert_eq!(track.album.compil, creation.album.compil);
                let artists: BTreeSet<String> = creation
                    .artists
                    .into_iter()
                    .map(|artist| artist.to_lowercase())
                    .collect();
                assert_eq!(track.artists, artists);
                assert_eq!(track.platform, creation.platform);
                assert_eq!(track.platform_id, creation.platform_id);
                assert_eq!(track.title, creation.title.to_lowercase());
                assert_eq!(track.year, creation.year);
                let track_fetched = conn
                    .track_by_id(track.id)
                    .await
                    .expect("failed to fetch track")
                    .expect("track doesn't exist");
                assert_eq!(track, track_fetched);
            }
        }

        mod delete_track {
            use super::*;

            // run

            async fn run(id: Uuid, db: PgPool) -> bool {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let deleted = conn.delete_track(id).await.expect("failed to delete tack");
                let track = conn.track_by_id(id).await.expect("failed to fetch track");
                assert!(track.is_none());
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
                let id = data.tracks[0].id;
                let deleted = run(id, db).await;
                assert!(deleted);
            }
        }

        mod search_tracks_by_title_artists_album {
            use super::*;

            // run

            async fn run(q: &str, expected: Page<Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_tracks_by_title_artists_album(q, expected.req)
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
                run("EvEr", expected, db).await;
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
                run("HuCk", expected, db).await;
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
                run("OuIs", expected, db).await;
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
                        data.tracks[3].clone(),
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 4,
                };
                run("n", expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.tracks[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 4,
                };
                run("n", expected, db).await;
            }
        }

        mod track_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let track = conn.track_by_id(id).await.expect("failed to fetch track");
                assert_eq!(track, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn track(db: PgPool) {
                let data = Data::new();
                let track = &data.tracks[0];
                run(track.id, Some(track), db).await;
            }
        }

        mod track_by_platform_id {
            use super::*;

            // run

            async fn run(platform: Platform, id: &str, expected: Option<&Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let track = conn
                    .track_by_platform_id(platform, id)
                    .await
                    .expect("failed to fetch track");
                assert_eq!(track, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Platform::Spotify, "", None, db).await;
            }

            #[sqlx::test]
            async fn track(db: PgPool) {
                let data = Data::new();
                let track = &data.tracks[0];
                run(track.platform, &track.platform_id, Some(track), db).await;
            }
        }

        mod tracks {
            use super::*;

            // run

            async fn run(expected: Page<Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .tracks(expected.req)
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: data.tracks.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .tracks
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
                    items: vec![data.tracks[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .tracks
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod update_track {
            use super::*;

            // run

            async fn unit(id: Uuid, track: &Track, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let track_expected = Track {
                    album: Album {
                        compil: false,
                        name: "i/o".into(),
                    },
                    artists: BTreeSet::from_iter(["peter gabriel".into()]),
                    title: "track_2".into(),
                    year: 2023,
                    ..track.clone()
                };
                let track_updated = Track {
                    album: Album {
                        compil: track_expected.album.compil,
                        name: track_expected.album.name.to_uppercase(),
                    },
                    artists: track_expected
                        .artists
                        .iter()
                        .map(|a| a.to_uppercase())
                        .collect::<BTreeSet<_>>(),
                    creation: Utc::now(),
                    id,
                    platform: track_expected.platform,
                    platform_id: "track_1_1".into(),
                    title: track_expected.title.to_uppercase(),
                    year: track_expected.year,
                };
                let updated = conn
                    .update_track(&track_updated)
                    .await
                    .expect("failed to update track");
                if expected {
                    assert!(updated);
                    let track = conn
                        .track_by_id(id)
                        .await
                        .expect("failed to fetch track")
                        .expect("track doesn't exist");
                    assert_eq!(track, track_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no(db: PgPool) {
                let data = Data::new();
                unit(Uuid::new_v4(), &data.tracks[0], false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let track = &data.tracks[0];
                unit(track.id, track, true, db).await;
            }
        }
    }
}
