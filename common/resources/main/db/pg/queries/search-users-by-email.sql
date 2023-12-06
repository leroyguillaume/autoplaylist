SELECT
    id AS usr_id,
    creation AS usr_creation,
    email AS usr_email,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds
FROM "user"
WHERE LOWER(email) LIKE CONCAT('%', LOWER($1), '%')
ORDER BY email ASC, creation ASC, id ASC
LIMIT $2
OFFSET $3;
