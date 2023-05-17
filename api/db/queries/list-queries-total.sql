SELECT COUNT(query.id)
FROM query
WHERE query.user_id = $1;
