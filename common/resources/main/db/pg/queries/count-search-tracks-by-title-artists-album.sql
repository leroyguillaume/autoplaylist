SELECT COUNT (*)
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
    );
