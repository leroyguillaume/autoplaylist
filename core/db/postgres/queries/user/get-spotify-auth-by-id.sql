SELECT
    spotify_auth.user_id AS auth_user_id,
    spotify_auth.email AS auth_email,
    spotify_auth.expiration_date AS auth_expiration_date,
    spotify_auth.access_token AS auth_access_token,
    spotify_auth.refresh_token AS auth_refresh_token
FROM spotify_auth
WHERE spotify_auth.user_id = $1;
