SELECT COUNT(id)
FROM "user"
WHERE LOWER(email) LIKE CONCAT('%', LOWER($1), '%');
