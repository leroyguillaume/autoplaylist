INSERT INTO spotify_auth
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id) DO
UPDATE SET access_token = EXCLUDED.access_token,
           expiration_date = EXCLUDED.expiration_date,
           refresh_token = EXCLUDED.refresh_token;
