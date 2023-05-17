SELECT
    query.id AS query_id,
    query.creation_date AS query_creation_date,
    query.user_id AS query_user_id,
    query.base_id AS query_base_id,
    query.name_prefix AS query_name_prefix,
    query.grouping AS query_grouping
FROM query
WHERE
    query.base_id = $1 AND
    query.name_prefix IS NOT DISTINCT FROM $2 AND
    query.grouping IS NOT DISTINCT FROM $3;
