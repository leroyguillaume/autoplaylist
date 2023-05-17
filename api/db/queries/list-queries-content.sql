SELECT
    query.id AS query_id,
    query.creation_date AS query_creation_date,
    query.user_id AS query_user_id,
    query.base_id AS query_base_id,
    query.name_prefix AS query_name_prefix,
    query.grouping AS query_grouping,
    base.id AS base_id,
    base.creation_date AS base_creation_date,
    base.user_id AS base_user_id,
    base.platform AS base_platform,
    base.kind AS base_kind,
    base.platform_id AS base_platform_id
FROM query
INNER JOIN base
    ON base.id = query.base_id
WHERE query.user_id = $1
LIMIT $2
OFFSET $3;
