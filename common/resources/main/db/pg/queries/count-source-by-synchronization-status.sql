SELECT COUNT(id)
FROM source
WHERE sync ? $1;
