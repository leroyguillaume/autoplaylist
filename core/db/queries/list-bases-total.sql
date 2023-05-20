SELECT COUNT(base.id)
FROM base
WHERE base.user_id = $1;
