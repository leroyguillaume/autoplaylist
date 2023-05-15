SELECT
    "user".id,
    "user".creation_date,
    "user".role
FROM "user"
INNER JOIN spotify_auth
    ON spotify_auth.user_id = "user".id
WHERE spotify_auth.email = $1;
