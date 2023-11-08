SELECT id
FROM playlist
WHERE src = $1
ORDER BY creation ASC, name ASC, id ASC
LIMIT $2
OFFSET $3;
