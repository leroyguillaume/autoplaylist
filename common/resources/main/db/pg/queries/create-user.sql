INSERT INTO "user" (email, creds)
VALUES ($1, $2)
RETURNING
    id AS usr_id,
    creation AS usr_creation,
    email AS usr_email,
    role AS "usr_role: Role", -- noqa: disable=RF05
    creds AS usr_creds;