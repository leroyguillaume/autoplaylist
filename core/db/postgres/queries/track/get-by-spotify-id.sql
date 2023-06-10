SELECT
    track.id AS track_id,
    track.name AS track_name,
    track.release_year AS track_release_year,
    track.from_compilation AS track_from_compilation,
    track.spotify_id AS track_spotify_id
FROM track
WHERE track.spotify_id IS NOT DISTINCT FROM $1;
