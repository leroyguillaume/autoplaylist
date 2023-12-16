SELECT
    id AS usr_id,
    creation AS usr_creation,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds
FROM "user"
WHERE LOWER(spotify_creds ->> 'email') LIKE CONCAT('%', LOWER($1), '%')
ORDER BY creation ASC, id ASC
LIMIT $2
OFFSET $3;
