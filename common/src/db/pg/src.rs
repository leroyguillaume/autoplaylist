use chrono::{DateTime, Utc};
use magic_crypt::MagicCrypt256;
use sqlx::{query_file, query_file_as, Acquire, PgConnection, Postgres};
use tracing::{debug, info_span, trace, Instrument};
use uuid::Uuid;

use crate::{
    db::SourceCreation,
    model::{Page, PageRequest, Platform, Role, Source, SourceKind, SynchronizationStatus, Track},
};

use super::{PostgresResult, SourceRecord, TrackRecord};

// add_track_to_source

#[inline]
pub async fn add_track_to_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<()> {
    let span = info_span!(
        "add_track_to_source",
        src.id = %src_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("adding track to source");
        query_file!(
            "resources/main/db/pg/queries/add-track-to-source.sql",
            src_id,
            track_id,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
    .instrument(span)
    .await
}

// count_source_playlists

#[inline]
pub async fn count_source_playlists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<u32> {
    let span = info_span!(
        "count_source_playlists",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting source playlists");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-playlists.sql",
            id,
        )
        .fetch_one(&mut *conn)
        .await?;
        let count = record.count.unwrap_or(0).try_into()?;
        Ok(count)
    }
    .instrument(span)
    .await
}

// create_source

#[inline]
pub async fn create_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    creation: &SourceCreation,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Source> {
    let span = info_span!(
        "create_source",
        src.kind = %creation.kind,
        src.owner.id = %creation.owner.id,
    );
    async {
        trace!("serializing source kind");
        let kind = serde_json::to_value(&creation.kind)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("creating source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/create-source.sql",
            creation.owner.id,
            &kind,
        )
        .fetch_one(&mut *conn)
        .await?;
        let src = record.into_entity(key)?;
        debug!(%src.id, %src.sync, "source created");
        Ok(src)
    }
    .instrument(span)
    .await
}

// delete_source

#[inline]
pub async fn delete_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "delete_source",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting source");
        let res = query_file!("resources/main/db/pg/queries/delete-source.sql", id,)
            .execute(&mut *conn)
            .await?;
        let deleted = res.rows_affected() > 0;
        if deleted {
            debug!("source deleted");
        }
        Ok(deleted)
    }
    .instrument(span)
    .await
}

// delete_tracks_from_source

#[inline]
pub async fn delete_tracks_from_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<u64> {
    let span = info_span!(
        "delete_tracks_from_source",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("deleting tracks");
        let res = query_file!(
            "resources/main/db/pg/queries/delete-tracks-from-source.sql",
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

// search_source_tracks_by_title_artists_album

#[inline]
pub async fn search_source_tracks_by_title_artists_album<
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
        src.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting source tracks matching query");
        let record = query_file!(
            "resources/main/db/pg/queries/count-search-source-tracks-by-title-artists-album.sql",
            id,
            q
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching source tracks matching query");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/search-source-tracks-by-title-artists-album.sql",
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

// source_by_id

#[inline]
pub async fn source_by_id<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Source>> {
    let span = info_span!(
        "source_by_id",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/source-by-id.sql",
            id,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let src = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(src)
    }
    .instrument(span)
    .await
}

// source_by_owner_kind

#[inline]
pub async fn source_by_owner_kind<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    owner_id: Uuid,
    kind: &SourceKind,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Option<Source>> {
    let span = info_span!(
        "source_by_owner_kind",
        src.owner.id = %owner_id,
    );
    async {
        trace!("serializing source kind");
        let kind = serde_json::to_value(kind)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("fetching source");
        let record = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/source-by-owner-kind.sql",
            owner_id,
            &kind,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let src = record.map(|record| record.into_entity(key)).transpose()?;
        Ok(src)
    }
    .instrument(span)
    .await
}

// source_contains_track

#[inline]
pub async fn source_contains_track<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src_id: Uuid,
    track_id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "source_contains_track",
        src.id = %src_id,
        track.id = %track_id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if source contains track");
        let record = query_file!(
            "resources/main/db/pg/queries/source-contains-track.sql",
            src_id,
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

// source_exists

#[inline]
pub async fn source_exists<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    conn: A,
) -> PostgresResult<bool> {
    let span = info_span!(
        "source_exists",
        src.id = %id,
    );
    async {
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("checking if source exists");
        let record = query_file!("resources/main/db/pg/queries/source-exists.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let exists = record.exists.unwrap_or(false);
        Ok(exists)
    }
    .instrument(span)
    .await
}

// source_ids_by_last_synchronization_date

#[inline]
pub async fn source_ids_by_last_synchronization_date<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    date: DateTime<Utc>,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Uuid>> {
    let span = info_span!(
        "source_ids_by_last_synchronization_date",
        params.date = %date,
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting sources");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-by-last-synchronization-date.sql",
            date,
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching source IDs");
        let records = query_file!(
            "resources/main/db/pg/queries/source-ids-by-last-synchronization-date.sql",
            date,
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

// source_ids_by_synchronization_status

#[inline]
pub async fn source_ids_by_synchronization_status<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    status: SynchronizationStatus,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Uuid>> {
    let span = info_span!(
        "source_ids_by_synchronization_status",
        params.limit = req.limit,
        params.offset = req.offset,
        src.sync = %status,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        let sync = match status {
            SynchronizationStatus::Aborted => "aborted",
            SynchronizationStatus::Failed => "failed",
            SynchronizationStatus::Pending => "pending",
            SynchronizationStatus::Running => "running",
            SynchronizationStatus::Succeeded => "succeeded",
        };
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting sources");
        let record = query_file!(
            "resources/main/db/pg/queries/count-source-by-synchronization-status.sql",
            sync,
        )
        .fetch_one(&mut *conn)
        .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching source IDs");
        let records = query_file!(
            "resources/main/db/pg/queries/source-ids-by-synchronization-status.sql",
            sync,
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

// source_tracks

#[inline]
pub async fn source_tracks<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    id: Uuid,
    req: PageRequest,
    conn: A,
) -> PostgresResult<Page<Track>> {
    let span = info_span!(
        "source_tracks",
        params.limit = req.limit,
        params.offset = req.offset,
        src.id = %id,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting source tracks");
        let record = query_file!("resources/main/db/pg/queries/count-source-tracks.sql", id,)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching source tracks");
        let records = query_file_as!(
            TrackRecord,
            "resources/main/db/pg/queries/source-tracks.sql",
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

// sources

#[inline]
pub async fn sources<'a, A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>>(
    req: PageRequest,
    key: &MagicCrypt256,
    conn: A,
) -> PostgresResult<Page<Source>> {
    let span = info_span!(
        "sources",
        params.limit = req.limit,
        params.offset = req.offset,
    );
    async {
        let limit: i64 = req.limit.into();
        let offset: i64 = req.offset.into();
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("counting sources");
        let record = query_file!("resources/main/db/pg/queries/count-sources.sql",)
            .fetch_one(&mut *conn)
            .await?;
        let total = record.count.unwrap_or(0).try_into()?;
        debug!("fetching sources");
        let records = query_file_as!(
            SourceRecord,
            "resources/main/db/pg/queries/sources.sql",
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

// update_source

#[inline]
pub async fn update_source<
    'a,
    A: Acquire<'a, Database = Postgres, Connection = &'a mut PgConnection>,
>(
    src: &Source,
    safely: bool,
    conn: A,
) -> PostgresResult<bool> {
    let span: tracing::Span = info_span!(
        "update_source",
        %src.id,
    );
    async {
        trace!("serializing source synchronization");
        let sync = serde_json::to_value(&src.sync)?;
        trace!("acquiring database connection");
        let conn = conn.acquire().await?;
        debug!("updating playlist");
        let query = if safely {
            query_file!(
                "resources/main/db/pg/queries/update-source-safely.sql",
                src.id,
                sync,
            )
        } else {
            query_file!(
                "resources/main/db/pg/queries/update-source.sql",
                src.id,
                sync,
            )
        };
        let res = query.execute(&mut *conn).await?;
        let updated = res.rows_affected() > 0;
        if updated {
            debug!("source updated");
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
        model::{SourceKind, SpotifySourceKind, Synchronization},
    };

    use super::*;

    // Mods

    mod client {
        use super::*;

        // Mods

        mod add_track_to_source {
            use super::*;

            // run

            async fn run(track_idx: usize, db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[track_idx].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                conn.add_track_to_source(src_id, track_id)
                    .await
                    .expect("failed to add track");
                let contains = conn
                    .source_contains_track(src_id, track_id)
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

        mod count_source_playlists {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn unit(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let count = conn
                    .count_source_playlists(src_id)
                    .await
                    .expect("failed to count source playlists");
                assert_eq!(count, 3);
            }
        }

        mod create_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let creation = SourceCreation {
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: data.usrs[1].usr.clone(),
                };
                let src = conn
                    .create_source(&creation)
                    .await
                    .expect("failed to create source");
                assert_eq!(src.kind, creation.kind);
                assert_eq!(src.owner, creation.owner);
                let src_fetched = conn
                    .source_by_id(src.id)
                    .await
                    .expect("failed to fetch source")
                    .expect("source doesn't exist");
                assert_eq!(src, src_fetched);
            }
        }

        mod delete_source {
            use super::*;

            // run

            async fn run(id: Uuid, db: PgPool) -> bool {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let deleted = conn
                    .delete_source(id)
                    .await
                    .expect("failed to delete source");
                let src = conn.source_by_id(id).await.expect("failed to fetch source");
                assert!(src.is_none());
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
                let id = data.srcs[0].id;
                let deleted = run(id, db).await;
                assert!(deleted);
            }
        }

        mod delete_tracks_from_source {
            use super::*;

            // Tests

            #[sqlx::test]
            async fn count(db: PgPool) {
                let data = Data::new();
                let id = data.srcs[0].id;
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let count = conn
                    .delete_tracks_from_source(id)
                    .await
                    .expect("failed to delete tracks");
                let page = conn
                    .source_tracks(id, PageRequest::new(100, 0))
                    .await
                    .expect("failed to fetch tracks");
                assert_eq!(page.total, 0);
                assert_eq!(count, 3);
            }
        }

        mod search_source_tracks_by_title_artists_album {
            use super::*;

            // run

            async fn run(id: Uuid, q: &str, expected: Page<Track>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .search_source_tracks_by_title_artists_album(id, q, expected.req)
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
                run(data.srcs[0].id, "EvEr", expected, db).await;
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
                run(data.srcs[0].id, "HuCk", expected, db).await;
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
                run(data.srcs[0].id, "OuIs", expected, db).await;
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
                run(data.srcs[0].id, "n", expected, db).await;
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
                run(data.srcs[0].id, "n", expected, db).await;
            }
        }

        mod source_by_id {
            use super::*;

            // run

            async fn run(id: Uuid, expected: Option<&Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src = conn.source_by_id(id).await.expect("failed to fetch source");
                assert_eq!(src, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none(db: PgPool) {
                run(Uuid::new_v4(), None, db).await;
            }

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.id, Some(src), db).await;
            }
        }

        mod source_by_owner_kind {
            use super::*;

            // run

            async fn run(owner_id: Uuid, kind: &SourceKind, expected: Option<&Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src = conn
                    .source_by_owner_kind(owner_id, kind)
                    .await
                    .expect("failed to fetch source");
                assert_eq!(src, expected.cloned());
            }

            // Tests

            #[sqlx::test]
            async fn none_when_owner_doesnt_match(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.srcs[0].kind, None, db).await;
            }

            #[sqlx::test]
            async fn none_when_kind_doesnt_match(db: PgPool) {
                let data = Data::new();
                run(data.srcs[0].owner.id, &data.srcs[3].kind, None, db).await;
            }

            #[sqlx::test]
            async fn source(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.owner.id, &src.kind, Some(src), db).await;
            }
        }

        mod source_contains_track {
            use super::*;

            // run

            async fn run(src_id: Uuid, track_id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let contains = conn
                    .source_contains_track(src_id, track_id)
                    .await
                    .expect("failed to check if source contains track");
                assert_eq!(contains, expected);
            }

            // Tests

            #[sqlx::test]
            async fn false_when_source_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[1].id;
                let track_id = data.tracks[0].id;
                run(src_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn false_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[3].id;
                run(src_id, track_id, false, db).await;
            }

            #[sqlx::test]
            async fn true_when_track_doesnt_match(db: PgPool) {
                let data = Data::new();
                let src_id = data.srcs[0].id;
                let track_id = data.tracks[0].id;
                run(src_id, track_id, true, db).await;
            }
        }

        mod source_exists {
            use super::*;

            // run

            async fn run(id: Uuid, expected: bool, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let exists = conn
                    .source_exists(id)
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
                let id = data.srcs[0].id;
                run(id, true, db).await;
            }
        }

        mod source_ids_by_last_synchronization_date {
            use super::*;

            // run

            async fn run(date: DateTime<Utc>, expected: Page<Uuid>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .source_ids_by_last_synchronization_date(date, expected.req)
                    .await
                    .expect("failed to fetch source IDs");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.srcs[0].id, data.srcs[2].id, data.srcs[3].id],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 3,
                };
                let date = DateTime::parse_from_rfc3339("2023-01-05T03:05:00Z")
                    .expect("failed to parse date")
                    .into();
                run(date, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.srcs[2].id],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 3,
                };
                let date = DateTime::parse_from_rfc3339("2023-01-05T03:05:00Z")
                    .expect("failed to parse date")
                    .into();
                run(date, expected, db).await;
            }
        }

        mod source_ids_by_synchronization_status {
            use super::*;

            // run

            async fn run(status: SynchronizationStatus, expected: Page<Uuid>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .source_ids_by_synchronization_status(status, expected.req)
                    .await
                    .expect("failed to fetch source IDs");
                assert_eq!(page, expected);
            }

            // Tests

            #[sqlx::test]
            async fn first_and_last(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![
                        data.srcs[0].id,
                        data.srcs[2].id,
                        data.srcs[3].id,
                        data.srcs[4].id,
                    ],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 4,
                };
                run(SynchronizationStatus::Succeeded, expected, db).await;
            }

            #[sqlx::test]
            async fn middle(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: false,
                    items: vec![data.srcs[2].id],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: 4,
                };
                run(SynchronizationStatus::Succeeded, expected, db).await;
            }

            #[sqlx::test]
            async fn aborted(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.srcs[5].id],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(SynchronizationStatus::Aborted, expected, db).await;
            }

            #[sqlx::test]
            async fn failed(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.srcs[6].id],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(SynchronizationStatus::Failed, expected, db).await;
            }

            #[sqlx::test]
            async fn pending(db: PgPool) {
                let data = Data::new();
                let expected = Page {
                    first: true,
                    items: vec![data.srcs[7].id],
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: 1,
                };
                run(SynchronizationStatus::Pending, expected, db).await;
            }
        }

        mod sources {
            use super::*;

            // run

            async fn run(expected: Page<Source>, db: PgPool) {
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let page = conn
                    .sources(expected.req)
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
                    items: data.srcs.clone(),
                    last: true,
                    req: PageRequest::new(100, 0),
                    total: data
                        .srcs
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
                    items: vec![data.srcs[1].clone()],
                    last: false,
                    req: PageRequest::new(1, 1),
                    total: data
                        .srcs
                        .len()
                        .try_into()
                        .expect("failed to convert usize to u32"),
                };
                run(expected, db).await;
            }
        }

        mod update_source {
            use super::*;

            // run

            async fn run(id: Uuid, src: &Source, expected: bool, db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src_expected = Source {
                    sync: Synchronization::Running(Utc::now()),
                    ..src.clone()
                };
                let src_updated = Source {
                    creation: Utc::now(),
                    id,
                    kind: SourceKind::Spotify(SpotifySourceKind::Playlist("id".into())),
                    owner: data.usrs[1].usr.clone(),
                    sync: src_expected.sync.clone(),
                };
                let updated = conn
                    .update_source(&src_updated)
                    .await
                    .expect("failed to update source");
                if expected {
                    assert!(updated);
                    let src = conn
                        .source_by_id(id)
                        .await
                        .expect("failed to fetch source")
                        .expect("source doesn't exist");
                    assert_eq!(src, src_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.srcs[0], false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.id, src, true, db).await;
            }
        }

        mod update_source_safely {
            use super::*;

            // run

            async fn run(id: Uuid, src: &Source, expected: bool, db: PgPool) {
                let data = Data::new();
                let db = init(db).await;
                let mut conn = db.acquire().await.expect("failed to acquire connection");
                let src_expected = Source {
                    sync: Synchronization::Running(Utc::now()),
                    ..src.clone()
                };
                let src_updated = Source {
                    creation: Utc::now(),
                    id,
                    kind: SourceKind::Spotify(SpotifySourceKind::Playlist("id".into())),
                    owner: data.usrs[1].usr.clone(),
                    sync: src_expected.sync.clone(),
                };
                let updated = conn
                    .update_source_safely(&src_updated)
                    .await
                    .expect("failed to update source");
                if expected {
                    assert!(updated);
                    let src = conn
                        .source_by_id(id)
                        .await
                        .expect("failed to fetch source")
                        .expect("source doesn't exist");
                    assert_eq!(src, src_expected);
                } else {
                    assert!(!updated);
                }
            }

            // Tests

            #[sqlx::test]
            async fn no_when_source_doesnt_exist(db: PgPool) {
                let data = Data::new();
                run(Uuid::new_v4(), &data.srcs[0], false, db).await;
            }

            #[sqlx::test]
            async fn no_when_sync_is_running(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[1];
                run(src.id, src, false, db).await;
            }

            #[sqlx::test]
            async fn yes(db: PgPool) {
                let data = Data::new();
                let src = &data.srcs[0];
                run(src.id, src, true, db).await;
            }
        }
    }
}
