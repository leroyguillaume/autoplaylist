UPDATE playlist
SET
    sync_state = $2,
    last_sync_id = $3,
    last_sync_start_date = $4,
    last_sync_success_date = $5,
    last_sync_duration = $6,
    last_sync_err_msg = $7,
    last_sync_offset = $8,
    last_sync_total = $9
WHERE id = $1;
