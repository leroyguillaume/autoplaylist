UPDATE playlist
SET sync = $2
WHERE
    id = $1
    AND sync ->> 'running' IS NULL;
