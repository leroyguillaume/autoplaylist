SELECT
    id AS usr_id,
    creation AS usr_creation,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds
FROM "user"
WHERE spotify_creds ->> 'id' = $1;
