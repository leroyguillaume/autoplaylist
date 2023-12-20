UPDATE playlist
SET
    name = $2,
    predicate = $3,
    sync = $4
WHERE
    id = $1
    AND sync ->> 'running' IS NULL;
