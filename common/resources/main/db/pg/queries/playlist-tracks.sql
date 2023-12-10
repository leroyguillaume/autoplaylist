SELECT
    track.id AS track_id,
    track.creation AS track_creation,
    track.title AS track_title,
    track.artists AS track_artists,
    track.album AS track_album,
    track.from_compil AS track_from_compil,
    track.year AS track_year,
    track.platform AS "track_platform: Platform", -- noqa: disable=RF05,
    track.platform_id AS track_platform_id
FROM playlist_track
INNER JOIN track
    ON track.id = playlist_track.track
WHERE playlist_track.playlist = $1
ORDER BY track.creation ASC, track.id ASC
LIMIT $2
OFFSET $3;
