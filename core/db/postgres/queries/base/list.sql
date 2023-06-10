SELECT
    base.id AS base_id,
    base.creation_date AS base_creation_date,
    base.user_id AS base_user_id,
    base.platform AS base_platform,
    base.kind AS base_kind,
    base.platform_id AS base_platform_id,
    base.sync_state AS base_sync_state,
    base.last_sync_id AS base_last_sync_id,
    base.last_sync_start_date AS base_last_sync_start_date,
    base.last_sync_success_date AS base_last_sync_success_date,
    base.last_sync_duration AS base_last_sync_duration,
    base.last_sync_err_msg AS base_last_sync_err_msg,
    base.last_sync_offset AS base_last_sync_offset,
    base.last_sync_total AS base_last_sync_total,
    "user".id AS base_user_id,
    "user".creation_date AS base_user_creation_date,
    "user".role AS base_user_role
FROM base
INNER JOIN "user"
    ON "user".id = base.user_id
ORDER BY base.creation_date DESC
LIMIT $1
OFFSET $2;
