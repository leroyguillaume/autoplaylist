-- uuid-ossp

CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; -- noqa: disable=RF05

-- role

CREATE TYPE role AS ENUM ('admin', 'user');

-- platform

CREATE TYPE platform AS ENUM ('spotify');

-- track

CREATE TABLE track (
    id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
    creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    title VARCHAR (255) NOT NULL,
    artists VARCHAR (255) [] NOT NULL,
    album VARCHAR (255) NOT NULL,
    from_compil BOOLEAN NOT NULL,
    year INT NOT NULL,
    platform PLATFORM NOT NULL,
    platform_id VARCHAR (255) NOT NULL,
    UNIQUE (platform, platform_id)
);

-- user

CREATE TABLE "user" (
    id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
    creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    role ROLE NOT NULL DEFAULT 'user',
    spotify_creds JSONB DEFAULT NULL,
    creds TEXT NOT NULL
);

CREATE UNIQUE INDEX user_spotify_id_unique ON "user" ((spotify_creds ->> 'id'));

-- source

CREATE TABLE source (
    id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
    creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    owner UUID NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    kind JSONB NOT NULL,
    sync JSONB NOT NULL DEFAULT '"pending"',
    UNIQUE (owner, kind)
);

-- source_track

CREATE TABLE source_track (
    src UUID NOT NULL REFERENCES source (id) ON DELETE CASCADE,
    track UUID NOT NULL REFERENCES track (id) ON DELETE CASCADE,
    PRIMARY KEY (src, track)
);

-- playlist

CREATE TABLE playlist (
    id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
    creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    name VARCHAR (100) NOT NULL,
    predicate JSONB NOT NULL,
    src UUID NOT NULL REFERENCES source (id) ON DELETE CASCADE,
    tgt JSONB NOT NULL,
    sync JSONB NOT NULL DEFAULT '"pending"'
);

-- playlist_track

CREATE TABLE playlist_track (
    playlist UUID NOT NULL REFERENCES playlist (id) ON DELETE CASCADE,
    track UUID NOT NULL REFERENCES track (id) ON DELETE CASCADE,
    PRIMARY KEY (playlist, track)
);

-- user_platform_playlist

CREATE TABLE user_platform_playlist (
    id VARCHAR (255) NOT NULL,
    usr UUID NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    name VARCHAR (255) NOT NULL,
    platform PLATFORM NOT NULL,
    PRIMARY KEY (id, usr, platform)
);
