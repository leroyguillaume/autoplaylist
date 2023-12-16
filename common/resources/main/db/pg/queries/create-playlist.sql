WITH new_playlist AS (
    INSERT INTO playlist (name, predicate, src, tgt)
    VALUES ($1, $2, $3, $4)
    RETURNING
        id,
        creation,
        name,
        predicate,
        src,
        tgt,
        sync
)
SELECT
    new_playlist.id AS playlist_id,
    new_playlist.creation AS playlist_creation,
    new_playlist.name AS playlist_name,
    new_playlist.predicate AS playlist_predicate,
    new_playlist.tgt AS playlist_tgt,
    new_playlist.sync AS playlist_sync,
    source.id AS src_id,
    source.creation AS src_creation,
    source.kind AS src_kind,
    source.sync AS src_sync,
    "user".id AS owner_id,
    "user".creation AS owner_creation,
    "user".role AS "owner_role: Role", -- noqa: disable=RF05
    "user".creds AS owner_creds
FROM new_playlist
INNER JOIN source
    ON source.id = new_playlist.src
INNER JOIN "user"
    ON "user".id = source.owner;
