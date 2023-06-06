DELETE FROM base_track
WHERE
    base_id = $1 AND
    sync_id != $2;
