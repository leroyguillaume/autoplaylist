DO $$
DECLARE
    playlist_1 UUID := 'e1195b8b-6a5d-4896-8889-137775fc8863';
    playlist_2 UUID := '58fb7bd7-efe2-4346-ac1f-2f21b8c3dd7c';
    playlist_3 UUID := 'a80267ba-89be-4350-ac0d-8ebecb88efa0';
    playlist_4 UUID := '36f24355-f506-4b40-955e-f42a1c49c138';
    playlist_5 UUID := '738c1907-1630-42ee-89b8-bd28cd3701a5';
    playlist_6 UUID := '08310fbb-14be-4b00-abf8-5a60e187b164';
    src_1 UUID := '911ca8e7-4874-4bf4-b8e1-1ddd1b6cee41';
    src_2 UUID := 'f1c418db-13c0-47a7-9ecb-9aa4cf4995eb';
    src_3 UUID := '12d423d1-3bc0-4eef-b0c6-6748beb7d52e';
    src_4 UUID := 'a23c9cc9-2b72-46db-9a52-922f1c09db01';
    track_1 UUID := 'd16eb9f1-cf4d-4a41-9515-e9a8125d7843';
    track_2 UUID := '9095b250-d4ab-427f-b38f-32aaf45afec5';
    track_3 UUID := 'f747ca3a-0cc7-4d9f-b38a-dc506f99f5df';
    usr_1 UUID := 'ee21186a-990c-42e9-bcd2-69f9090a7736';
    usr_2 UUID := 'ec1ca9f9-3c47-44a2-95c7-a13ff6de852d';
    usr_3 UUID := '8fc899c5-f254-4966-9b5a-e8f1c4f97f7c';
    usr_4 UUID := '83e3a7ed-9d6c-4e4f-b732-8a00cab3fcb5';
    usr_5 UUID := 'ee187392-8471-43f4-a3cd-e541fd7640f4';
BEGIN
    INSERT INTO track (id, creation, title, artists, album, from_compil, year, platform, platform_id)
    VALUES
        (
            track_1,
            '2023-01-02T00:00:00Z',
            'son of a preacher man',
            ARRAY['dusty springfield'],
            'dusty in memphis',
            FALSE,
            1969,
            'spotify',
            'track_1'
        ),
        (
            track_2,
            '2023-01-02T00:01:00Z',
            'you never can tell',
            ARRAY['chuck berry'],
            'st. louis to liverpool',
            FALSE,
            1964,
            'spotify',
            'track_2'
        ),
        (
            track_3,
            '2023-01-02T00:01:00Z',
            'the letter',
            ARRAY['the box tops'],
            'the letter/neon rainbow',
            FALSE,
            1967,
            'spotify',
            'track_3'
        );

    INSERT INTO "user" (id, creation, role, spotify_creds, creds)
    VALUES
        (
            usr_1,
            '2023-01-01T00:00:00Z',
            'admin',
            '{"id":"user_1","email":"user_1@test"}',
            'NumtB/0HwFNYAEVUoRI6/K9nYyUw5XfJT4HX6LDrtZtjEmGL+yeI5FKjvnknSxz/hgSlxfRj3T2Eh8+JY/xmkMgbU443Qt7OPLn/9tnUjrcCGkSk6nxtsV3Zyvecmg3GptMPWqV/j5GJQIz67lQ/hjoHs6zR5Cdiym97dq7AL/UgxDlw1lYTVMTvx4+qqXUS'
        ),
        (
            usr_2,
            '2023-02-01T00:00:00Z',
            'user',
            '{"id":"user_2","email":"user_2@test"}',
            'NumtB/0HwFNYAEVUoRI6/I8ArpJqKJjjHMXDxA5NvgGH10lsbLtvAKjwePIUk1Qd/SYXNHc7Lad/6CRXQ/848JF5WTi2FYAJ7/TeY0UHf5v0DlmIjFj/hwpiO9FjBL5LVNEV/l6PtxceLynyp6FwDUhh5Ft93QsMDLNQAs8Q1eoYFe79p0JEPLy35c7YWWVg'
        ),
        (
            usr_3,
            '2023-03-01T00:00:00Z',
            'user',
            '{"id":"user_3","email":"test_3@test"}',
            'NumtB/0HwFNYAEVUoRI6/N4gu2ADVSVC21T7w1h3gvlFzXlFw0Oauj5T2mSPl/hCKKQTAPw/y7AuXkQdJC98N5IHuva2WvzWMyNSOTodhFboM8r9PkUECi+VbP0SHx0jDwFchjH5LP5pvXc/V8CTbz8vdYqJYclFlUxTxq3S8/YhdodJ34yP1+TjUIrsBdGl'
        ),
        (
            usr_4,
            '2023-04-01T00:00:00Z',
            'user',
            NULL,
            'KsuJ6o6TS4XOOztpV10hd07zrgU73tIriUpsMgqsXPM='
        ),
        (
            usr_5,
            '2023-05-01T00:00:00Z',
            'user',
            '{"id":"user_5","email":"user_5@test"}',
            'NumtB/0HwFNYAEVUoRI6/NDtmfpPvXEA7vrJeiDZqeNvkvR3eudGriwtbqmmCLBPvapEoaM73cSC9CpA48ApXibqS9y3bZ9f9KXECzfm97InoK5gNuPcokkv2oDtJPH8A4tP03BPfHADOHoig1BU41UtYw4UpC7mC6X0SrYcHZ3+MEPeDOFGrqmcmSpuwx4D'
        );

    INSERT INTO source (id, creation, owner, kind, sync)
    VALUES
        (
            src_1,
            '2023-01-05T01:00:00Z',
            usr_1,
            '{"spotify":"savedTracks"}',
            '"pending"'
        ),
        (
            src_2,
            '2023-02-05T02:00:00Z',
            usr_1,
            '{"spotify":{"playlist":"src_2"}}',
            '{"running":"2023-02-05T00:00:10Z"}'
        ),
        (
            src_3,
            '2023-02-05T03:00:00Z',
            usr_1,
            '{"spotify":{"playlist":"src_3"}}',
            '"pending"'
        ),
        (
            src_4,
            '2023-02-05T04:00:00Z',
            usr_2,
            '{"spotify":{"playlist":"src_4"}}',
            '"pending"'
        );

    INSERT INTO source_track
    VALUES (src_1, track_1);

    INSERT INTO playlist (id, creation, name, predicate, src, tgt, sync)
    VALUES
        (
            playlist_1,
            '2023-01-05T00:00:10Z',
            'playlist_1',
            '{"yearIs":1993}',
            src_1,
            '{"spotify":"playlist_1"}',
            '"pending"'
        ),
        (
            playlist_2,
            '2023-02-05T00:00:10Z',
            'playlist_2',
            '{"yearIs":2013}',
            src_1,
            '{"spotify":"playlist_2"}',
            '{"running":"2023-02-05T00:00:10Z"}'
        ),
        (
            playlist_3,
            '2023-03-05T00:00:10Z',
            'playlist_3',
            '{"yearIs":1961}',
            src_1,
            '{"spotify":"playlist_3"}',
            '"pending"'
        ),
        (
            playlist_4,
            '2023-04-05T00:00:10Z',
            'playlist_4',
            '{"yearIs":1999}',
            src_4,
            '{"spotify":"playlist_4"}',
            '"pending"'
        ),
        (
            playlist_5,
            '2023-05-05T00:00:10Z',
            'test_5',
            '{"yearIs":1999}',
            src_4,
            '{"spotify":"playlist_5"}',
            '"pending"'
        ),
        (
            playlist_6,
            '2023-06-05T00:00:10Z',
            'test_6',
            '{"yearIs":1999}',
            src_2,
            '{"spotify":"playlist_6"}',
            '"pending"'
        );

    INSERT INTO playlist_track
    VALUES (playlist_1, track_1);
END;
$$;
