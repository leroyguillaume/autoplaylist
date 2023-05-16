CREATE TYPE base_kind AS ENUM (
    'likes',
    'playlist'
);

CREATE TYPE grouping AS ENUM (
    'decades'
);

CREATE TYPE platform AS ENUM (
    'spotify'
);

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

CREATE TABLE base (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID NOT NULL REFERENCES "user" ON DELETE CASCADE,
    platform PLATFORM NOT NULL,
    kind BASE_KIND NOT NULL,
    platform_id VARCHAR (255),
    UNIQUE NULLS NOT DISTINCT (user_id, platform, kind, platform_id)
);

CREATE TABLE query (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    base_id UUID NOT NULL REFERENCES base ON DELETE CASCADE,
    name_prefix VARCHAR (50),
    grouping "grouping",
    UNIQUE NULLS NOT DISTINCT (base_id, name_prefix, grouping)
);
