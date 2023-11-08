SELECT
    id AS track_id,
    creation AS track_creation,
    title AS track_title,
    artists AS track_artists,
    album AS track_album,
    from_compil AS track_from_compil,
    year AS track_year,
    spotify_id AS track_spotify_id
FROM track
WHERE id = $1;
