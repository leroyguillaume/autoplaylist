SELECT EXISTS (SELECT 1 FROM "user" WHERE id = $1);
