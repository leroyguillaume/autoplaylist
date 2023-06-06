INSERT INTO base_track
VALUES ($1, $2, $3)
ON CONFLICT (base_id, track_id)
UPDATE SET sync_id = EXCLUDED.sync_id;
