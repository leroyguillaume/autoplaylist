UPDATE base
SET
    sync_state = 'running',
    last_sync_start_date = NOW()
WHERE
    id = $1 AND
    sync_state IS DISTINCT FROM 'running'
RETURNING
sync_state AS base_sync_state,
last_sync_start_date AS base_last_sync_start_date,
last_sync_success_date AS base_last_sync_success_date,
last_sync_err_msg AS base_last_sync_err_msg,
last_sync_offset AS base_last_sync_offset;
