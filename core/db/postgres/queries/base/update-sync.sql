UPDATE base
SET
    base.sync_state = $2,
    base.last_sync_start_date = $3,
    base.last_sync_success_date = $4,
    base.last_sync_err_msg = $5,
    base.last_sync_offset = $6,
    base.last_sync_total = $7
WHERE base.id = $1;
