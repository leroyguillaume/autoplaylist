UPDATE base
SET
    sync_state = $2,
    last_sync_id = $3,
    last_sync_start_date = $4,
    last_sync_success_date = $5,
    last_sync_err_msg = $6,
    last_sync_offset = $7,
    last_sync_total = $8
WHERE id = $1;
