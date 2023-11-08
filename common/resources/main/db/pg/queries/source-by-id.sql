SELECT
    source.id AS src_id,
    source.creation AS src_creation,
    source.kind AS src_kind,
    source.sync AS src_sync,
    "user".id AS owner_id,
    "user".creation AS owner_creation,
    "user".email AS owner_email,
    "user".role AS "owner_role: Role", -- noqa: disable=RF05
    "user".creds AS owner_creds
FROM source
INNER JOIN "user"
    ON "user".id = source.owner
WHERE source.id = $1;
