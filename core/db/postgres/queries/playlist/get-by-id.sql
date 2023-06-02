SELECT
    playlist.id AS playlist_id,
    playlist.creation_date AS playlist_creation_date,
    playlist.user_id AS playlist_user_id,
    playlist.base_id AS playlist_base_id,
    playlist.name AS playlist_name
FROM playlist
WHERE playlist.id = $1;
