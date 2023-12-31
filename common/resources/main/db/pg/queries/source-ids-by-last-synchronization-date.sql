SELECT id
FROM source
WHERE (sync -> 'succeeded' ->> 'end')::TIMESTAMP WITH TIME ZONE <= $1
ORDER BY creation, id
LIMIT $2
OFFSET $3;
