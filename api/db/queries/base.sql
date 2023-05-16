SELECT
    base.id,
    base.creation_date,
    base.user_id,
    base.platform,
    base.kind,
    base.platform_id
FROM base
WHERE
    base.user_id = $1 AND
    base.platform = $2 AND
    base.kind = $3 AND
    base.platform_id IS NOT DISTINCT FROM $4;
