INSERT INTO track (title, artists, album, from_compil, year, platform, platform_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING
    id AS track_id,
    creation AS track_creation,
    title AS track_title,
    artists AS track_artists,
    album AS track_album,
    from_compil AS track_from_compil,
    year AS track_year,
    platform AS "track_platform: Platform", -- noqa: disable=RF05,
    platform_id AS track_platform_id;
