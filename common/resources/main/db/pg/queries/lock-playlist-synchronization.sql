UPDATE playlist playlist_new
SET sync = '"running"'
FROM playlist AS playlist_old
WHERE playlist_new.id = $1
RETURNING playlist_old.sync AS sync;
