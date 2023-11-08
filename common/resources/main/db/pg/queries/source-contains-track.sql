SELECT EXISTS(
    SELECT 1
    FROM source_track
    WHERE src = $1
        AND track = $2
) AS contains;
