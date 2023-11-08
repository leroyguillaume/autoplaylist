UPDATE track
SET
    spotify_id = $2
WHERE id = $1;
