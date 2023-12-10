SELECT
    id AS track_id,
    creation AS track_creation,
    title AS track_title,
    artists AS track_artists,
    album AS track_album,
    from_compil AS track_from_compil,
    year AS track_year,
    platform AS "track_platform: Platform", -- noqa: disable=RF05,
    platform_id AS track_platform_id
FROM track
ORDER BY creation ASC, id ASC
LIMIT $1
OFFSET $2;
