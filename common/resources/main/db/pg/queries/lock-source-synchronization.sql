UPDATE source source_new
SET sync = '"running"'
FROM source AS source_old
WHERE source_new.id = $1
RETURNING source_old.sync AS sync;
