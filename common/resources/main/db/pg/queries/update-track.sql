UPDATE track
SET
    title = $2,
    artists = $3,
    album = $4,
    from_compil = $5,
    year = $6
WHERE id = $1;
