SELECT COUNT(id)
FROM user_platform_playlist
WHERE
    usr = $1
    AND platform = $2
    AND LOWER(name) LIKE CONCAT('%', LOWER($3), '%');
