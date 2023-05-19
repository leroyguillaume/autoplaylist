SELECT
    base.id AS base_id,
    base.creation_date AS base_creation_date,
    base.user_id AS base_user_id,
    base.platform AS base_platform,
    base.kind AS base_kind,
    base.platform_id AS base_platform_id
FROM base
WHERE
    base.user_id = $1 AND
    base.platform = $2 AND
    base.kind = $3 AND
    base.platform_id IS NOT DISTINCT FROM $4;
