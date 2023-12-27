SELECT
    id AS platform_playlist_id,
    name AS platform_playlist_name,
    platform AS "platform_playlist_platform: Platform" -- noqa: disable=RF05
FROM user_platform_playlist
WHERE
    usr = $1
    AND platform = $2
ORDER BY name ASC, id ASC
LIMIT $3
OFFSET $4;
