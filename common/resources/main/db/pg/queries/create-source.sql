WITH new_src AS (
    INSERT INTO source (owner, kind)
    VALUES ($1, $2)
    RETURNING
        id,
        creation,
        owner,
        kind,
        sync
)
SELECT
    new_src.id AS src_id,
    new_src.creation AS src_creation,
    new_src.kind AS src_kind,
    new_src.sync AS src_sync,
    "user".id AS owner_id,
    "user".creation AS owner_creation,
    "user".role AS "owner_role: Role", -- noqa: disable=RF05
    "user".creds AS owner_creds
FROM new_src
INNER JOIN "user"
    ON "user".id = new_src.owner;
