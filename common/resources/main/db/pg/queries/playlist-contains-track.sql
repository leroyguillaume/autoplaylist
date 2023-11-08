SELECT EXISTS(
    SELECT 1
    FROM playlist_track
    WHERE playlist = $1
        AND track = $2
) AS contains;
