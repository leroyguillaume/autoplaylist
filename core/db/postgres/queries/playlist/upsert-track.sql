INSERT INTO playlist_track
VALUES ($1, $2, $3)
ON CONFLICT (playlist_id, track_id) DO
UPDATE SET last_sync_id = EXCLUDED.last_sync_id;
