DELETE FROM user_platform_playlist
WHERE
    usr = $1
    AND platform = $2;
