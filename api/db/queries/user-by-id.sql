SELECT
    "user".id,
    "user".creation_date,
    "user".role
FROM "user"
WHERE "user".id = $1;
