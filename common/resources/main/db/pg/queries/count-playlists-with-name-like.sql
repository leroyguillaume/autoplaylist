SELECT COUNT(id)
FROM playlist
WHERE LOWER(name) LIKE CONCAT('%', LOWER($1), '%');
