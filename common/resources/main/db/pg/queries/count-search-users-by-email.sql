SELECT COUNT(id)
FROM "user"
WHERE LOWER(spotify_creds ->> 'email') LIKE CONCAT('%', LOWER($1), '%');
