DO $$
DECLARE
    playlist_1 UUID := 'e1195b8b-6a5d-4896-8889-137775fc8863';
    playlist_2 UUID := '58fb7bd7-efe2-4346-ac1f-2f21b8c3dd7c';
    playlist_3 UUID := 'a80267ba-89be-4350-ac0d-8ebecb88efa0';
    playlist_4 UUID := '36f24355-f506-4b40-955e-f42a1c49c138';
    src_1 UUID := '911ca8e7-4874-4bf4-b8e1-1ddd1b6cee41';
    src_2 UUID := 'f1c418db-13c0-47a7-9ecb-9aa4cf4995eb';
    src_3 UUID := '12d423d1-3bc0-4eef-b0c6-6748beb7d52e';
    src_4 UUID := 'a23c9cc9-2b72-46db-9a52-922f1c09db01';
    track_1 UUID := 'd16eb9f1-cf4d-4a41-9515-e9a8125d7843';
    track_2 UUID := '9095b250-d4ab-427f-b38f-32aaf45afec5';
    track_3 UUID := 'f747ca3a-0cc7-4d9f-b38a-dc506f99f5df';
    user_1 UUID := 'ee21186a-990c-42e9-bcd2-69f9090a7736';
    user_2 UUID := 'ec1ca9f9-3c47-44a2-95c7-a13ff6de852d';
    user_3 UUID := '8fc899c5-f254-4966-9b5a-e8f1c4f97f7c';
BEGIN
    INSERT INTO track (id, creation, title, artists, album, from_compil, year, spotify_id)
    VALUES
        (
            track_1,
            '2023-01-02T00:00:00Z',
            'son of a preacher man',
            ARRAY['dusty springfield'],
            'dusty in memphis',
            FALSE,
            1969,
            NULL
        ),
        (
            track_2,
            '2023-01-02T00:01:00Z',
            'you never can tell',
            ARRAY['chuck berry'],
            'st. louis to liverpool',
            FALSE,
            1964,
            NULL
        ),
        (
            track_3,
            '2023-01-02T00:01:00Z',
            'the letter',
            ARRAY['the box tops'],
            'the letter/neon rainbow',
            FALSE,
            1967,
            NULL
        );

    INSERT INTO "user" (id, creation, email, role, creds)
    VALUES
        (
            user_1,
            '2023-01-01T00:00:00Z',
            'user_1@test',
            'admin',
            'aWgc5xavoR/8BEWvI9ujW8deLtjje1RNSULt49LXXNE6SLGqUNAcO1e4yLlX/46zbVFkoT0hV8jwtKncfbIfegrBB11gZUiPPhJedg4ywQwJB0HBOWTCoqrW4XWglA9FA9eBnyZ6x/dEI+m4zvphfg=='
        ),
        (
            user_2,
            '2023-02-01T00:00:00Z',
            'user_2@test',
            'user',
            'KsuJ6o6TS4XOOztpV10hd07zrgU73tIriUpsMgqsXPM='
        ),
        (
            user_3,
            '2023-03-01T00:00:00Z',
            'user_3@test',
            'user',
            'KsuJ6o6TS4XOOztpV10hd07zrgU73tIriUpsMgqsXPM='
        );

    INSERT INTO source (id, creation, owner, kind)
    VALUES
        (
            src_1,
            '2023-01-05T01:00:00Z',
            user_1,
            '{"spotify":"savedTracks"}'
        ),
        (
            src_2,
            '2023-02-05T02:00:00Z',
            user_1,
            '{"spotify":{"playlist":"src_2"}}'
        ),
        (
            src_3,
            '2023-02-05T03:00:00Z',
            user_1,
            '{"spotify":{"playlist":"src_3"}}'
        ),
        (
            src_4,
            '2023-02-05T04:00:00Z',
            user_2,
            '{"spotify":{"playlist":"src_4"}}'
        );

    INSERT INTO source_track
    VALUES (src_1, track_1);

    INSERT INTO playlist (id, creation, name, predicate, src, tgt)
    VALUES
        (
            playlist_1,
            '2023-01-05T00:00:10Z',
            'playlist_1',
            '{"yearEquals":1993}',
            src_1,
            '{"spotify":"playlist_1"}'
        ),
        (
            playlist_2,
            '2023-02-05T00:00:10Z',
            'playlist_2',
            '{"yearEquals":2013}',
            src_1,
            '{"spotify":"playlist_2"}'
        ),
        (
            playlist_3,
            '2023-03-05T00:00:10Z',
            'playlist_3',
            '{"yearEquals":1961}',
            src_1,
            '{"spotify":"playlist_3"}'
        ),
        (
            playlist_4,
            '2023-04-05T00:00:10Z',
            'playlist_4',
            '{"yearEquals":1999}',
            src_4,
            '{"spotify":"playlist_4"}'
        );

    INSERT INTO playlist_track
    VALUES (playlist_1, track_1);
END;
$$;
