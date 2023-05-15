CREATE TYPE role AS ENUM (
    'admin',
    'user'
);

CREATE TABLE "user" (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    role ROLE NOT NULL
);

CREATE TABLE spotify_auth (
    user_id UUID NOT NULL PRIMARY KEY REFERENCES "user" ON DELETE CASCADE,
    email VARCHAR (255) NOT NULL UNIQUE,
    access_token TEXT NOT NULL,
    refresh_token TEXT
);
