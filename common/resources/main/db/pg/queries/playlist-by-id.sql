SELECT
    playlist.id AS playlist_id,
    playlist.creation AS playlist_creation,
    playlist.name AS playlist_name,
    playlist.predicate AS playlist_predicate,
    playlist.tgt AS playlist_tgt,
    playlist.sync AS playlist_sync,
    source.id AS src_id,
    source.creation AS src_creation,
    source.kind AS src_kind,
    source.sync AS src_sync,
    "user".id AS owner_id,
    "user".creation AS owner_creation,
    "user".email AS owner_email,
    "user".role AS "owner_role: Role", -- noqa: disable=RF05
    "user".creds AS owner_creds
FROM playlist
INNER JOIN source
    ON source.id = playlist.src
INNER JOIN "user"
    ON "user".id = source.owner
WHERE playlist.id = $1;
