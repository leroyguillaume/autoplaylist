SELECT
    playlist.id AS playlist_id,
    playlist.creation_date AS playlist_creation_date,
    playlist.user_id AS playlist_user_id,
    playlist.base_id AS playlist_base_id,
    playlist.name AS playlist_name,
    playlist.sync_state AS playlist_sync_state,
    playlist.last_sync_id AS playlist_last_sync_id,
    playlist.last_sync_start_date AS playlist_last_sync_start_date,
    playlist.last_sync_success_date AS playlist_last_sync_success_date,
    playlist.last_sync_duration AS playlist_last_sync_duration,
    playlist.last_sync_err_msg AS playlist_last_sync_err_msg,
    playlist.last_sync_offset AS playlist_last_sync_offset,
    playlist.last_sync_total AS playlist_last_sync_total
FROM playlist
WHERE
    playlist.user_id = $1 AND
    playlist.name = $2;
