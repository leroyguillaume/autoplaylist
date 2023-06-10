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
    expiration_date TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token VARCHAR (500)
);

CREATE TABLE base (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID NOT NULL REFERENCES "user" ON DELETE CASCADE,
    platform PLATFORM NOT NULL,
    kind BASE_KIND NOT NULL,
    platform_id VARCHAR (255),
    sync_state SYNC_STATE DEFAULT NULL,
    last_sync_id UUID,
    last_sync_start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_success_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_duration BIGINT DEFAULT NULL,
    last_sync_err_msg TEXT DEFAULT NULL,
    last_sync_offset BIGINT NOT NULL DEFAULT 0,
    last_sync_total BIGINT NOT NULL DEFAULT 0,
    UNIQUE NULLS NOT DISTINCT (user_id, platform, kind, platform_id)
);

CREATE TABLE playlist (
    id UUID NOT NULL PRIMARY KEY,
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID NOT NULL REFERENCES "user" ON DELETE CASCADE,
    base_id UUID NOT NULL REFERENCES base ON DELETE CASCADE,
    name VARCHAR (50) NOT NULL,
    sync_state SYNC_STATE DEFAULT NULL,
    last_sync_id UUID,
    last_sync_start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_success_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    last_sync_duration BIGINT DEFAULT NULL,
    last_sync_err_msg TEXT DEFAULT NULL,
    last_sync_offset BIGINT NOT NULL DEFAULT 0,
    last_sync_total BIGINT NOT NULL DEFAULT 0,
    UNIQUE NULLS NOT DISTINCT (user_id, base_id, name)
);

CREATE TABLE playlist_filter (
    playlist_id UUID NOT NULL REFERENCES playlist ON DELETE CASCADE,
    def JSONB NOT NULL
);

CREATE TABLE artist (
    id UUID NOT NULL PRIMARY KEY,
    name VARCHAR (255) NOT NULL,
    spotify_id VARCHAR (50) UNIQUE
);

CREATE TABLE track (
    id UUID NOT NULL PRIMARY KEY,
    name VARCHAR (255) NOT NULL,
    release_year INT NOT NULL,
    from_compilation BOOLEAN NOT NULL,
    spotify_id VARCHAR (50) UNIQUE
);

CREATE TABLE track_artist (
    track_id UUID NOT NULL REFERENCES track ON DELETE CASCADE,
    artist_id UUID NOT NULL REFERENCES artist ON DELETE CASCADE,
    PRIMARY KEY (track_id, artist_id)
);

CREATE TABLE base_track (
    base_id UUID NOT NULL REFERENCES base ON DELETE CASCADE,
    track_id UUID NOT NULL REFERENCES track ON DELETE CASCADE,
    last_sync_id UUID NOT NULL,
    PRIMARY KEY (base_id, track_id)
);

CREATE TABLE playlist_track (
    playlist_id UUID NOT NULL REFERENCES playlist ON DELETE CASCADE,
    track_id UUID NOT NULL REFERENCES track ON DELETE CASCADE,
    last_sync_id UUID NOT NULL,
    PRIMARY KEY (playlist_id, track_id)
);
