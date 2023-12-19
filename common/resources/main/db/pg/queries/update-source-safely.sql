UPDATE source
SET sync = $2
WHERE
    id = $1
    AND sync ->> 'running' IS NULL;
