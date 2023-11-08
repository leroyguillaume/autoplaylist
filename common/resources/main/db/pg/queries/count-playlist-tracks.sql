SELECT COUNT(track)
FROM playlist_track
WHERE playlist = $1;
