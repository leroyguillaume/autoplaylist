SELECT COUNT (t1.id)
FROM source_track
INNER JOIN track t1
    ON t1.id = source_track.track
WHERE
    source_track.src = $1
    AND (
        title LIKE CONCAT('%', LOWER($2), '%')
        OR album LIKE CONCAT('%', LOWER($2), '%')
        OR EXISTS (
            SELECT 1
            FROM (
                SELECT UNNEST (artists) AS artists
                FROM track t2
                WHERE t2.id = t1.id
            ) AS t3
            WHERE t3.artists LIKE CONCAT('%', LOWER($2), '%')
        )
    );
