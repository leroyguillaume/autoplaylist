INSERT INTO track (title, artists, album, from_compil, year, spotify_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id AS track_id,
    creation AS track_creation,
    title AS track_title,
    artists AS track_artists,
    album AS track_album,
    from_compil AS track_from_compil,
    year AS track_year,
    spotify_id AS track_spotify_id;
