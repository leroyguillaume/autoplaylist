UPDATE base
SET
    base.sync_state = $2,
    base.last_sync_id = $3,
    base.last_sync_start_date = $4,
    base.last_sync_success_date = $5,
    base.last_sync_err_msg = $6,
    base.last_sync_offset = $7,
    base.last_sync_total = $8
WHERE id = $1;
