SELECT
    track.id AS track_id,
    track.creation AS track_creation,
    track.title AS track_title,
    track.artists AS track_artists,
    track.album AS track_album,
    track.from_compil AS track_from_compil,
    track.year AS track_year,
    track.spotify_id AS track_spotify_id
FROM source_track
INNER JOIN track
    ON track.id = source_track.track
WHERE source_track.src = $1
ORDER BY track.creation ASC, track.id ASC
LIMIT $2
OFFSET $3;
