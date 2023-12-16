INSERT INTO "user" (spotify_creds, creds)
VALUES ($1, $2)
RETURNING
    id AS usr_id,
    creation AS usr_creation,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds;
