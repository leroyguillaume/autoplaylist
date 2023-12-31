SELECT COUNT(id)
FROM source
WHERE (sync -> 'succeeded' ->> 'end')::TIMESTAMP WITH TIME ZONE <= $1;
