# AutoPlaylist

Automatically create playlists based on predicate.

## Getting started

### With Docker

Spotify API credentials are required to run the services.
You need to set the following environment variables:
- `SPOTIFY_CLIENT_ID`
- `SPOTIFY_CLIENT_SECRET`

You can run the services with the following command:
```bash
docker compose --profile main up -d
```

### With cargo

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Concepts

### Predicate

The predicate is a statement to filter tracks.

### Source

A *source* is a track list on which apply a predicate to filter them. It can be shared between several playlists.
A *source* can be:
- the saved tracks of the user (*Liked Songs*)
- a Spotify playlist

### Target

A *target* is the platform on which create the playlist.
A *target* can be:
- Spotify

## Synchronization flow

1. Fetch the tracks from the playlist *source*
2. Start synchronization of all playlists based on this *source*:
   1. Fetch the tracks from the playlist *target*
   2. For each track of the *source*, if it matches the playlist predicate, add it to the *target*
   3. For each track of the *target*, if it doesn't match the playlist predicate, remove it from the *target*

Note a synchronization can be triggered manually via the REST API by an admin.

## Architecture

AutoPlaylist is composed of 2 services:
- API which exposes the REST API to manage the playlists
- Synchronizer which synchronizes the playlists

## Contributing

[See CONTRIBUTING.md](CONTRIBUTING.md).
