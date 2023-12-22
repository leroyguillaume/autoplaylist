SELECT
    t1.id AS track_id,
    t1.creation AS track_creation,
    t1.title AS track_title,
    t1.artists AS track_artists,
    t1.album AS track_album,
    t1.from_compil AS track_from_compil,
    t1.year AS track_year,
    t1.platform AS "track_platform: Platform", -- noqa: disable=RF05,
    t1.platform_id AS track_platform_id
FROM track t1
WHERE
    title LIKE CONCAT('%', LOWER($1), '%')
    OR album LIKE CONCAT('%', LOWER($1), '%')
    OR EXISTS (
        SELECT 1
        FROM (
            SELECT UNNEST (artists) AS artists
            FROM track t2
            WHERE t2.id = t1.id
        ) AS t3
        WHERE t3.artists LIKE CONCAT('%', LOWER($1), '%')
    )
ORDER BY t1.creation ASC, t1.id ASC
LIMIT $2
OFFSET $3;
