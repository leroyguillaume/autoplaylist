SELECT
    "user".id AS user_id,
    "user".creation_date AS user_creation_date,
    "user".role AS user_role
FROM "user"
INNER JOIN spotify_auth
    ON spotify_auth.user_id = "user".id
WHERE spotify_auth.email = $1;
