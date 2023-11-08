UPDATE playlist
SET sync = $2
WHERE id = $1;
