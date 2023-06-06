DELETE FROM base_track
WHERE
    base_id = $1 AND
    last_sync_id != $2;
