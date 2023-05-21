CREATE TYPE base_kind AS ENUM (
    'likes',
    'playlist'
);

CREATE TYPE platform AS ENUM (
    'spotify'
);

CREATE TYPE role AS ENUM (
    'admin',
    'user'
);

CREATE TYPE sync_state AS ENUM (
    'aborted',
    'failed',
    'running',
    'succeeded'
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
    sync_state SYNC_STATE DEFAULT NULL,
    last_sync_start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_success_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_err_msg TEXT DEFAULT NULL,
    UNIQUE NULLS NOT DISTINCT (user_id, platform, kind, platform_id)
);

CREATE TABLE playlist (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID NOT NULL REFERENCES "user" ON DELETE CASCADE,
    base_id UUID NOT NULL REFERENCES base ON DELETE CASCADE,
    name VARCHAR (50) NOT NULL,
    UNIQUE NULLS NOT DISTINCT (user_id, base_id, name)
);

CREATE TABLE playlist_filter (
    playlist_id UUID NOT NULL REFERENCES playlist ON DELETE CASCADE,
    def JSONB NOT NULL
);
