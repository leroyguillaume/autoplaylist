UPDATE "user"
SET
    email = $2,
    role = $3,
    creds = $4
WHERE id = $1;
