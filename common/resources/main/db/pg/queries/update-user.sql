UPDATE "user"
SET
    role = $2,
    spotify_creds = $3,
    creds = $4
WHERE id = $1;
