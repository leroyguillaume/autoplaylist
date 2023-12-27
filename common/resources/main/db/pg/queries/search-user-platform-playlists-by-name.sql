SELECT
    id AS platform_playlist_id,
    name AS platform_playlist_name,
    platform AS "platform_playlist_platform: Platform" -- noqa: disable=RF05
FROM user_platform_playlist
WHERE
    usr = $1
    AND platform = $2
    AND LOWER(name) LIKE CONCAT('%', LOWER($3), '%')
ORDER BY name ASC, id ASC
LIMIT $4
OFFSET $5;
