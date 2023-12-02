# Contributing

## Prerequisites
- [Docker](https://www.docker.com/)
- [pre-commit](https://pre-commit.com/)
- [Rust](https://rustup.rs/)
- [sqlfluff](https://sqlfluff.com/)
- [Spotify API credentials](https://developer.spotify.com/)

## Getting started

```bash
git clone https://github.com/leroyguillaume/autoplaylist
cd autoplaylist
pre-commit install
docker compose up -d
```

## How to build

```bash
cargo build
```

## How to test

```bash
cargo test
```

## Services

### Configuration

Spotify API credentials are required to run the services.
You need to set the following environment variables:
- `SPOTIFY_CLIENT_ID`
- `SPOTIFY_CLIENT_SECRET`

You can find the list of all available environment variables in the [`.env.example`](.env.example) file. **Note AutoPlaylist doesn't load .env file, you need to source it manually or edit the `env` section of [cargo configuration file](./.cargo/config.toml).**

### API

This service is the main entry point of the application.

#### How to run

```bash
cargo run --bin autoplaylist-api
```

### Synchronizer

This service is responsible for synchronizing the playlists with the music providers.

#### How to run

```bash
cargo run --bin autoplaylist-sync
```

## CLI

The CLI can be used to interract with the API or to do administrative tasks.

### How to run

```bash
cargo run --bin autoplaylist -- help
```
