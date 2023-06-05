SELECT
    artist.id AS artist_id,
    artist.name AS artist_name,
    artist.spotify_id AS artist_spotify_id
FROM artist
WHERE artist.spotify_id IS NOT DISTINCT FROM $1;
