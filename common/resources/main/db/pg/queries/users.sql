SELECT
    id AS usr_id,
    creation AS usr_creation,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds
FROM "user"
ORDER BY creation ASC, id ASC
LIMIT $1
OFFSET $2;
