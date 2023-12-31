SELECT id
FROM source
WHERE sync ? $1
ORDER BY creation, id
LIMIT $2
OFFSET $3;
