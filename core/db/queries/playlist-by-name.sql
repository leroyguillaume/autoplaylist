SELECT
    playlist.id AS playlist_id,
    playlist.creation_date AS playlist_creation_date,
    playlist.user_id AS playlist_user_id,
    playlist.base_id AS playlist_base_id,
    playlist.name AS playlist_name,
    base.id AS base_id,
    base.creation_date AS base_creation_date,
    base.user_id AS base_user_id,
    base.platform AS base_platform,
    base.kind AS base_kind,
    base.platform_id AS base_platform_id,
    base.sync_state AS base_sync_state,
    base.last_sync_start_date AS base_last_sync_start_date,
    base.last_sync_success_date AS base_last_sync_success_date,
    base.last_sync_err_msg AS base_last_sync_err_msg
FROM playlist
INNER JOIN base
    ON base.id = playlist.base_id
WHERE playlist.name = $1;
