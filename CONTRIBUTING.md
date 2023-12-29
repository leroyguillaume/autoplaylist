# Contributing

## Prerequisites
- [Docker](https://www.docker.com/)
- [Node.JS](https://nodejs.org/en/)
- [pre-commit](https://pre-commit.com/)
- [Rust](https://rustup.rs/)
- [sqlfluff](https://sqlfluff.com/)
- [sqlx-cli](https://crates.io/crates/sqlx-cli)
- [Spotify API credentials](https://developer.spotify.com/)

## Getting started

```bash
git clone https://github.com/leroyguillaume/autoplaylist
cd autoplaylist
pre-commit install
docker compose up -d
./sh/recreate-db.sh
```

## How to build

```bash
cargo build
```

## How to test

```bash
docker compose --profile test up -d
cargo test
```

## Admin

If you want to promote your user as admin, you can run the following commands:
```bash
export AUTOPLAYLIST_TOKEN=$(cargo run --bin autoplaylist -- auth spotify | jq -r '.jwt')
id=$(cargo run --bin autoplaylist -- me | jq -r .id)
cargo run --bin autoplaylist -- adm usr update-role $id admin
```

## Services

### Configuration

Spotify API credentials are required to run the services. You can generate credentials [here](https://developer.spotify.com/dashboard/create).

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

It listens playlist/source events on RabbitMQ queues.

#### How to run

```bash
cargo run --bin autoplaylist-sync
```

## WebPapp

The WebApp is a React application which allows to manage the playlists.

By default, the WebApp is configured to call the API on `http://localhost:8000` but you can change it by modifying `public/config.json`.

It is particularly ugly because I'm not a frontend developer, feel free to contribute to improve it.

### How to run

```bash
cd webapp
npm install
npm start
```

## CLI

The CLI can be used to interract with the API or to do administrative tasks.

The administrative tasks don't call the API but directly the database/the broker.

### How to run

```bash
cargo run --bin autoplaylist -- help
```
