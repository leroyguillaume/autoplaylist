# AutoPlaylist

Automatically create playlists based on predicate.

## Getting started

For the moment, you need to build the project from source. See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

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

## Synchronization workflow

For every 6 hours, the synchronizer will:
1. fetch the tracks from the playlist *source*
2. start synchronization of all playlists based on this *source*:
   1. fetch the tracks from the playlist *target*
   2. for each track of the *source*, if it matches the playlist predicate, add it to the *target*
   3. for each track of the *target*, if it doesn't match the playlist predicate, remove it from the *target*

Note a synchronization can be triggered manually via the REST API.

## Architecture

AutoPlaylist is composed of 2 services:
- API which exposes the REST API to manage the playlists
- Synchronizer which synchronizes the playlists

## CLI

The CLI can be used to interract with the API or to do administrative tasks.
You can see the available commands by running:
```bash
cargo run --bin autoplaylist -- help
```

## Contributing

[See CONTRIBUTING.md](CONTRIBUTING.md)
