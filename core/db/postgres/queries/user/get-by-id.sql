SELECT
    "user".id AS user_id,
    "user".creation_date AS user_creation_date,
    "user".role AS user_role
FROM "user"
WHERE "user".id = $1;
