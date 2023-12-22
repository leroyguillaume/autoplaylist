SELECT COUNT(playlist.id)
FROM playlist
INNER JOIN source
    ON source.id = playlist.src
WHERE
    source.owner = $1
    AND LOWER(name) LIKE CONCAT('%', LOWER($2), '%');
