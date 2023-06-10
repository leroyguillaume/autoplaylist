UPDATE playlist
SET
    sync_state = 'running',
    last_sync_id = $2,
    last_sync_start_date = $3,
    last_sync_err_msg = NULL
WHERE
    id = $1 AND
    sync_state IS DISTINCT FROM 'running'
RETURNING
sync_state AS playlist_sync_state,
last_sync_id AS playlist_last_sync_id,
last_sync_start_date AS playlist_last_sync_start_date,
last_sync_success_date AS playlist_last_sync_success_date,
last_sync_duration AS playlist_last_sync_duration,
last_sync_err_msg AS playlist_last_sync_err_msg,
last_sync_offset AS playlist_last_sync_offset,
last_sync_total AS playlist_last_sync_total;
