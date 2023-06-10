DELETE FROM playlist_track
WHERE
    playlist_id = $1 AND
    last_sync_id != $2;
