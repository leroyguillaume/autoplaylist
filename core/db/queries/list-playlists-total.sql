SELECT COUNT(playlist.id)
FROM playlist
WHERE playlist.user_id = $1;
