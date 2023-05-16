SELECT
    query.id,
    query.creation_date,
    query.base_id,
    query.name_prefix,
    query.grouping
FROM query
WHERE
    query.base_id = $1 AND
    query.name_prefix IS NOT DISTINCT FROM $2 AND
    query.grouping IS NOT DISTINCT FROM $3;
