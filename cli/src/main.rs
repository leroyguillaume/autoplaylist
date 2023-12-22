use std::{
    fs::File,
    io::{stderr, stdout, Write},
    marker::PhantomData,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use autoplaylist_common::{
    api::{
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, PageRequestQueryParams,
        RedirectUriQueryParam, SearchQueryParam, UpdatePlaylistRequest, UpdateTrackRequest,
        UpdateUserRequest,
    },
    db::{
        pg::{PostgresConfig, PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseConnection, DatabasePool, DatabaseTransaction,
    },
    model::Role,
    TracingConfig,
};
use clap::{Parser, Subcommand, ValueEnum};
use mockable::{DefaultEnv, DefaultHttpServer, DefaultSystem, HttpResponse, HttpServer, System};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, error, info_span, trace, Instrument};
use uuid::Uuid;

use crate::api::{ApiClient, DefaultApiClient};

// main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    TracingConfig::new("autoplaylist", stderr)
        .with_filter(&args.log_filter)
        .init(&DefaultEnv);
    let runner = CommandRunner::new(DefaultServices);
    let mut out = stdout();
    runner.run(args.cmd, &mut out).await
}

// Consts - Query params

const CODE_QUERY_PARAM: &str = "code";

// AdminCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Admin commands (not using API)")]
enum AdminCommand {
    #[command(subcommand, alias = "usr")]
    User(AdminUserCommand),
}

// AdminUserCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Admin commands about users")]
enum AdminUserCommand {
    #[command(about = "Update user role")]
    UpdateRole(AdminUserUpdateRoleCommandArgs),
}

// AdminUserUpdateRoleCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct AdminUserUpdateRoleCommandArgs {
    #[command(flatten)]
    db: DatabaseArgs,
    #[arg(help = "User ID")]
    id: Uuid,
    #[arg(help = "User role")]
    role: RoleArg,
}

// ApiBaseUrlArg

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct ApiBaseUrlArg {
    #[arg(
        long = "api-base-url",
        env = "AUTOPLAYLIST_API_BASE_URL",
        default_value = "http://localhost:8000",
        help = "Autoplaylist API URL",
        name = "API_BASE_URL"
    )]
    value: String,
}

// Args

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
    #[arg(long, env = "LOG_FILTER", default_value = "warn")]
    log_filter: String,
}

// AuthCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Authentication commands")]
enum AuthCommand {
    #[command(about = "Authenticate via Spotify")]
    Spotify(AuthSpotifyCommandArgs),
}

// AuthSpotifyCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct AuthSpotifyCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[arg(
        short,
        long,
        default_value_t = 8080,
        help = "Port on which to listen for the callback from Spotify"
    )]
    port: u16,
}

// Command

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum Command {
    #[command(subcommand, alias = "adm")]
    Admin(AdminCommand),
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(about = "Get your account information")]
    Me(MeCommandArgs),
    #[command(subcommand)]
    Playlist(PlaylistCommand),
    #[command(subcommand, alias = "src")]
    Source(SourceCommand),
    #[command(subcommand)]
    Track(TrackCommand),
    #[command(subcommand, alias = "usr")]
    User(UserCommand),
}

// DatabaseArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct DatabaseArgs {
    #[arg(
        long = "db-host",
        env = "DATABASE_HOST",
        default_value = "localhost",
        help = "Database host",
        name = "DATABASE_HOST"
    )]
    host: String,
    #[arg(
        long = "db-name",
        env = "DATABASE_NAME",
        default_value = "autoplaylist",
        help = "Database name",
        name = "DATABASE_NAME"
    )]
    name: String,
    #[arg(
        long = "db-password",
        env = "DATABASE_PASSWORD",
        help = "Database password",
        name = "DATABASE_PASSWORD"
    )]
    password: String,
    #[arg(
        long = "db-port",
        env = "DATABASE_PORT",
        default_value_t = 5432,
        help = "Database port",
        name = "DATABASE_PORT"
    )]
    port: u16,
    #[arg(
        long = "db-secret",
        env = "DATABASE_SECRET",
        help = "Database secret",
        name = "DATABASE_SECRET"
    )]
    secret: String,
    #[arg(
        long = "db-user",
        env = "DATABASE_USER",
        default_value = "autoplaylist",
        help = "Database user",
        name = "DATABASE_USER"
    )]
    user: String,
}

// MeCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct MeCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(short, long, default_value_t = false, help = "Delete your account")]
    delete: bool,
}

// PageRequestArgs

#[derive(clap::Args, Clone, Copy, Debug, Eq, PartialEq)]
struct PageRequestArgs<const LIMIT: u32> {
    #[arg(
        long,
        default_value_t = LIMIT,
        help = "Page size",
        name = "LIMIT"
    )]
    limit: u32,
    #[arg(long, default_value_t = 0, help = "Page offset", name = "OFFSET")]
    offset: u32,
}

// PlaylistGetCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistGetCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist ID")]
    id: Uuid,
}

// PlaylistCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Playlist commands")]
enum PlaylistCommand {
    #[command(about = "Create a playlist")]
    Create(PlaylistCreateCommandArgs),
    #[command(about = "Delete a playlist", alias = "del")]
    Delete(PlaylistDeleteCommandArgs),
    #[command(about = "Get a playlist")]
    Get(PlaylistGetCommandArgs),
    #[command(about = "List playlists", alias = "ls")]
    List(PlaylistListCommandArgs),
    #[command(about = "Start playlist synchronization", alias = "sync")]
    Synchronize(PlaylistSynchronizeCommandArgs),
    #[command(about = "List playlist tracks")]
    Tracks(PlaylistTracksCommandArgs),
    #[command(about = "Update a playlist")]
    Update(PlaylistUpdateCommandArgs),
}

// PlaylistCreateCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistCreateCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist creation JSON file")]
    file: PathBuf,
}

// PlaylistDeleteCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistDeleteCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist ID")]
    id: Uuid,
}

// PlaylistListCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistListCommandArgs {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "List all playlists, not just yours"
    )]
    all: bool,
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by name")]
    search: Option<String>,
}

// PlaylistSynchronizeCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistSynchronizeCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist ID")]
    id: Uuid,
}

// PlaylistTracksCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistTracksCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist ID")]
    id: Uuid,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by title, artists or album")]
    search: Option<String>,
}

// PlaylistUpdateCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct PlaylistUpdateCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Playlist update JSON file", index = 2)]
    file: PathBuf,
    #[arg(help = "Playlist ID", index = 1)]
    id: Uuid,
}

// RoleArg

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RoleArg {
    Admin,
    User,
}

// SourceGetCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct SourceGetCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Source ID")]
    id: Uuid,
}

// SourceCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Source commands")]
enum SourceCommand {
    #[command(about = "Get a source")]
    Get(SourceGetCommandArgs),
    #[command(about = "List sources", alias = "ls")]
    List(SourceListCommandArgs),
    #[command(about = "Start source synchronization", alias = "sync")]
    Synchronize(SourceSynchronizeCommandArgs),
    #[command(about = "List source tracks")]
    Tracks(SourceTracksCommandArgs),
}

// SourceListCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct SourceListCommandArgs {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "List all sources, not just yours"
    )]
    all: bool,
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[command(flatten)]
    req: PageRequestArgs<25>,
}

// SourceSynchronizeCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct SourceSynchronizeCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Source ID")]
    id: Uuid,
}

// SourceTracksCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct SourceTracksCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Source ID")]
    id: Uuid,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by title, artists or album")]
    search: Option<String>,
}

// TokenArg

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct TokenArg {
    #[arg(
        long = "token",
        env = "AUTOPLAYLIST_TOKEN",
        help = "Autoplaylist token",
        name = "TOKEN"
    )]
    value: String,
}

// TrackGetCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct TrackGetCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Track ID")]
    id: Uuid,
}

// TrackCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Track commands")]
enum TrackCommand {
    #[command(about = "Get a track")]
    Get(TrackGetCommandArgs),
    #[command(about = "List tracks", alias = "ls")]
    List(TrackListCommandArgs),
    #[command(about = "Update a track")]
    Update(TrackUpdateCommandArgs),
}

// TrackListCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct TrackListCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by title, artists or album")]
    search: Option<String>,
}

// TrackUpdateCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct TrackUpdateCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Track update JSON file", index = 2)]
    file: PathBuf,
    #[arg(help = "Track ID", index = 1)]
    id: Uuid,
}

// UserGetCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserGetCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User ID")]
    id: Uuid,
}

// UserCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Playlist commands")]
enum UserCommand {
    #[command(about = "Delete user", alias = "del")]
    Delete(UserDeleteCommandArgs),
    #[command(about = "Get an user")]
    Get(UserGetCommandArgs),
    #[command(about = "List users", alias = "ls")]
    List(UserListCommandArgs),
    #[command(about = "List user playlists")]
    Playlists(UserPlaylistsCommandArgs),
    #[command(about = "List user sources")]
    Sources(UserSourcesCommandArgs),
    #[command(about = "Update user")]
    Update(UserUpdateCommandArgs),
}

// UserDeleteCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserDeleteCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User ID")]
    id: Uuid,
}

// UserListCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserListCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by email")]
    search: Option<String>,
}

// UserPlaylistsCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserPlaylistsCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User ID")]
    id: Uuid,
    #[command(flatten)]
    req: PageRequestArgs<25>,
}

// UserSourcesCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserSourcesCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User ID")]
    id: Uuid,
    #[command(flatten)]
    req: PageRequestArgs<25>,
}

// UserUpdateCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserUpdateCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User update JSON file", index = 2)]
    file: PathBuf,
    #[arg(help = "User ID", index = 1)]
    id: Uuid,
}

// Services

#[async_trait]
trait Services<
    API: ApiClient,
    SERVER: HttpServer,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
>: Send + Sync
{
    fn api(&self, base_url: String) -> API;

    async fn create_database_pool(&self, args: DatabaseArgs) -> anyhow::Result<DB>;

    async fn start_server(&self, port: u16) -> anyhow::Result<SERVER>;

    fn system(&self) -> &dyn System;
}

// CommandRunner

struct CommandRunner<
    API: ApiClient,
    SERVER: HttpServer,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    SVC: Services<API, SERVER, DBCONN, DBTX, DB>,
> {
    svc: SVC,
    _api: PhantomData<API>,
    _db: PhantomData<DB>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
    _server: PhantomData<SERVER>,
}

impl
    CommandRunner<
        DefaultApiClient,
        DefaultHttpServer,
        PostgresConnection,
        PostgresTransaction<'_>,
        PostgresPool,
        DefaultServices,
    >
{
    fn new(svc: DefaultServices) -> Self {
        Self {
            svc,
            _api: PhantomData,
            _db: PhantomData,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
            _server: PhantomData,
        }
    }
}

impl<
        API: ApiClient,
        SERVER: HttpServer,
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services<API, SERVER, DBCONN, DBTX, DB>,
    > CommandRunner<API, SERVER, DBCONN, DBTX, DB, SVC>
{
    async fn run(&self, cmd: Command, mut out: &mut dyn Write) -> anyhow::Result<()> {
        match cmd {
            Command::Admin(AdminCommand::User(AdminUserCommand::UpdateRole(args))) => {
                let span = info_span!(
                    "update_user_role",
                    db.host = args.db.host,
                    db.name = args.db.name,
                    db.port = args.db.port,
                    db.user = args.db.user,
                    usr.id = %args.id,
                );
                async {
                    let pool = self.svc.create_database_pool(args.db).await?;
                    let mut db_conn = pool.acquire().await?;
                    let mut usr = match db_conn.user_by_id(args.id).await? {
                        Some(usr) => usr,
                        None => bail!("user doesn't exist"),
                    };
                    let role = Role::from(args.role);
                    usr.role = role;
                    if !db_conn.update_user(&usr).await? {
                        bail!("user doesn't exist");
                    }
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Auth(AuthCommand::Spotify(args)) => {
                let span = info_span!(
                    "authenticate_via_spotify",
                    api_base_url = %args.api_base_url.value,
                    server.port = args.port
                );
                async {
                    let param = RedirectUriQueryParam {
                        redirect_uri: format!("http://localhost:{}", args.port),
                    };
                    let mut server = self.svc.start_server(args.port).await?;
                    let api = self.svc.api(args.api_base_url.value);
                    let authorize_url = api.spotify_authorize_url(&param).await?;
                    if let Err(err) = self.svc.system().open_url(&authorize_url) {
                        error!(
                            details = %err,
                            url = authorize_url,
                            "failed to open web browser, please open URL"
                        );
                    }
                    debug!("waiting for callback");
                    let req = match server.next().await {
                        Some(req) => req,
                        None => bail!("no request received"),
                    };
                    let code = req
                        .query
                        .get(CODE_QUERY_PARAM)
                        .ok_or_else(|| anyhow!("missing code"))?
                        .first()
                        .ok_or_else(|| anyhow!("missing code"))?;
                    let params = AuthenticateViaSpotifyQueryParams {
                        code: code.into(),
                        redirect_uri: param.redirect_uri,
                    };
                    let resp = api.authenticate_via_spotify(&params).await?;
                    trace!("writing response on output");
                    serde_json::to_writer(&mut out, &resp)?;
                    writeln!(out)?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Me(args) => {
                let span = info_span!(
                    "me",
                    api_base_url = %args.api_base_url.value,
                    params.delete = args.delete
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    if args.delete {
                        api.delete_authenticated_user(&args.api_token.value).await?;
                    } else {
                        let resp = api.authenticated_user(&args.api_token.value).await?;
                        Self::write_to_output(out, &resp)?;
                    }
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Create(args)) => {
                let span = info_span!(
                    "create_playlist",
                    api_base_url = %args.api_base_url.value,
                    params.file = %args.file.display()
                );
                async {
                    let req: CreatePlaylistRequest = Self::read_json_file(&args.file)?;
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.create_playlist(&req, &args.api_token.value).await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Delete(args)) => {
                let span = info_span!(
                    "delete_playlist",
                    api_base_url = %args.api_base_url.value,
                    playlist.id = %args.id
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    api.delete_playlist(args.id, &args.api_token.value).await?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Get(args)) => {
                let span = info_span!(
                    "playlist_by_id",
                    api_base_url = %args.api_base_url.value,
                    playlist.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.playlist_by_id(args.id, &args.api_token.value).await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::List(args)) => {
                let span = info_span!(
                    "playlists",
                    api_base_url = %args.api_base_url.value,
                    params.all = args.all,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if let Some(q) = args.search {
                        let params = SearchQueryParam { q };
                        if args.all {
                            api.search_playlists_by_name(&params, req, &args.api_token.value)
                                .await?
                        } else {
                            api.search_authenticated_user_playlists_by_name(
                                &params,
                                req,
                                &args.api_token.value,
                            )
                            .await?
                        }
                    } else if args.all {
                        api.playlists(req, &args.api_token.value).await?
                    } else {
                        api.authenticated_user_playlists(req, &args.api_token.value)
                            .await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Synchronize(args)) => {
                let span = info_span!(
                    "synchronize_playlist",
                    api_base_url = %args.api_base_url.value,
                    playlist.id = %args.id
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    api.start_playlist_synchronization(args.id, &args.api_token.value)
                        .await?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Tracks(args)) => {
                let span = info_span!(
                    "playlist_tracks",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                    playlist.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if let Some(q) = args.search {
                        let params = SearchQueryParam { q };
                        api.search_playlist_tracks_by_title_artists_album(
                            args.id,
                            &params,
                            req,
                            &args.api_token.value,
                        )
                        .await?
                    } else {
                        api.playlist_tracks(args.id, req, &args.api_token.value)
                            .await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Playlist(PlaylistCommand::Update(args)) => {
                let span = info_span!(
                    "update_playlist",
                    api_base_url = %args.api_base_url.value,
                    params.file = %args.file.display(),
                    playlist.id = %args.id,
                );
                async {
                    let req: UpdatePlaylistRequest = Self::read_json_file(&args.file)?;
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api
                        .update_playlist(args.id, &req, &args.api_token.value)
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Source(SourceCommand::Get(args)) => {
                let span = info_span!(
                    "source_by_id",
                    api_base_url = %args.api_base_url.value,
                    src.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.source_by_id(args.id, &args.api_token.value).await?;
                    trace!("writing response on output");
                    serde_json::to_writer(&mut out, &resp)?;
                    writeln!(out)?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Source(SourceCommand::List(args)) => {
                let span = info_span!(
                    "sources",
                    api_base_url = %args.api_base_url.value,
                    params.all = args.all,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if args.all {
                        api.sources(req, &args.api_token.value).await?
                    } else {
                        api.authenticated_user_sources(req, &args.api_token.value)
                            .await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Source(SourceCommand::Synchronize(args)) => {
                let span = info_span!(
                    "synchronize_source",
                    api_base_url = %args.api_base_url.value,
                    src.id = %args.id
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    api.start_source_synchronization(args.id, &args.api_token.value)
                        .await?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::Source(SourceCommand::Tracks(args)) => {
                let span = info_span!(
                    "source_tracks",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                    src.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if let Some(q) = args.search {
                        let params = SearchQueryParam { q };
                        api.search_source_tracks_by_title_artists_album(
                            args.id,
                            &params,
                            req,
                            &args.api_token.value,
                        )
                        .await?
                    } else {
                        api.source_tracks(args.id, req, &args.api_token.value)
                            .await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Track(TrackCommand::Get(args)) => {
                let span = info_span!(
                    "track_by_id",
                    api_base_url = %args.api_base_url.value,
                    track.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.track_by_id(args.id, &args.api_token.value).await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Track(TrackCommand::List(args)) => {
                let span = info_span!(
                    "tracks",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if let Some(q) = args.search {
                        let params = SearchQueryParam { q };
                        api.search_tracks_by_title_artists_album(
                            &params,
                            req,
                            &args.api_token.value,
                        )
                        .await?
                    } else {
                        api.tracks(req, &args.api_token.value).await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Track(TrackCommand::Update(args)) => {
                let span = info_span!(
                    "update_track",
                    api_base_url = %args.api_base_url.value,
                    params.file = %args.file.display(),
                    track.id = %args.id,
                );
                async {
                    let req: UpdateTrackRequest = Self::read_json_file(&args.file)?;
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api
                        .update_track(args.id, &req, &args.api_token.value)
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::Delete(args)) => {
                let span = info_span!(
                    "delete_user",
                    api_base_url = %args.api_base_url.value,
                    usr.id = %args.id
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    api.delete_user(args.id, &args.api_token.value).await?;
                    Ok(())
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::Get(args)) => {
                let span = info_span!(
                    "user_by_id",
                    api_base_url = %args.api_base_url.value,
                    usr.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.user_by_id(args.id, &args.api_token.value).await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::List(args)) => {
                let span = info_span!(
                    "users",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = if let Some(q) = args.search {
                        let params = SearchQueryParam { q };
                        api.search_users_by_email(&params, args.req.into(), &args.api_token.value)
                            .await?
                    } else {
                        api.users(req, &args.api_token.value).await?
                    };
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::Playlists(args)) => {
                let span = info_span!(
                    "user_playlists",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    usr.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = api
                        .user_playlists(args.id, req, &args.api_token.value)
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::Sources(args)) => {
                let span = info_span!(
                    "user_sources",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    usr.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = api
                        .user_sources(args.id, req, &args.api_token.value)
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::User(UserCommand::Update(args)) => {
                let span = info_span!(
                    "update_user",
                    api_base_url = %args.api_base_url.value,
                    params.file = %args.file.display(),
                    usr.id = %args.id,
                );
                async {
                    let req: UpdateUserRequest = Self::read_json_file(&args.file)?;
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api
                        .update_user(args.id, &req, &args.api_token.value)
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
        }
    }

    #[inline]
    fn read_json_file<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
        debug!("opening file");
        let file = File::open(path)?;
        debug!("deserializing file");
        let req: T = serde_json::from_reader(file)?;
        Ok(req)
    }

    #[inline]
    fn write_to_output<T: Serialize>(mut out: &mut dyn Write, resp: &T) -> anyhow::Result<()> {
        trace!("writing response on output");
        serde_json::to_writer(&mut out, resp)?;
        writeln!(&mut out)?;
        Ok(())
    }
}

// DefaultServices

struct DefaultServices;

#[async_trait]
impl
    Services<
        DefaultApiClient,
        DefaultHttpServer,
        PostgresConnection,
        PostgresTransaction<'_>,
        PostgresPool,
    > for DefaultServices
{
    fn api(&self, base_url: String) -> DefaultApiClient {
        DefaultApiClient::new(base_url)
    }

    async fn create_database_pool(&self, args: DatabaseArgs) -> anyhow::Result<PostgresPool> {
        let db_cfg = PostgresConfig::from(args);
        let pool = PostgresPool::init(db_cfg).await?;
        Ok(pool)
    }

    async fn start_server(&self, port: u16) -> anyhow::Result<DefaultHttpServer> {
        let html = include_str!("../resources/main/html/close.html");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        debug!(%addr, "starting server");
        let server =
            DefaultHttpServer::with_response(&addr, HttpResponse::Html(html.into())).await?;
        Ok(server)
    }

    fn system(&self) -> &dyn System {
        &DefaultSystem
    }
}

// PageRequestQueryParams

impl<const LIMIT: u32> From<PageRequestArgs<LIMIT>> for PageRequestQueryParams<LIMIT> {
    fn from(args: PageRequestArgs<LIMIT>) -> Self {
        Self {
            limit: Some(args.limit),
            offset: Some(args.offset),
        }
    }
}

// PostgresConfig

impl From<DatabaseArgs> for PostgresConfig {
    fn from(args: DatabaseArgs) -> Self {
        Self {
            host: args.host,
            name: args.name,
            password: args.password,
            port: args.port,
            secret: args.secret,
            user: args.user,
        }
    }
}

// Role

impl From<RoleArg> for Role {
    fn from(arg: RoleArg) -> Self {
        match arg {
            RoleArg::Admin => Self::Admin,
            RoleArg::User => Self::User,
        }
    }
}

// Mods

mod api;

// Tests

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use autoplaylist_common::{
        api::{
            JwtResponse, PlaylistResponse, SourceResponse, SynchronizationResponse, UserResponse,
        },
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Album, PageRequest, Platform, Predicate, SourceKind, SpotifySourceKind, Target, Track,
            User,
        },
    };
    use chrono::Utc;
    use mockable::{HttpRequest, Mock, MockHttpServer, MockSystem};
    use mockall::predicate::eq;
    use tempdir::TempDir;
    use uuid::Uuid;

    use crate::api::MockApiClient;

    use super::*;

    // MockServices

    #[derive(Default)]
    struct MockServices {
        api: Mock<MockApiClient, String>,
        create_db_pool: Mock<MockDatabasePool, DatabaseArgs>,
        start_server: Mock<MockHttpServer, u16>,
        sys: MockSystem,
    }

    #[async_trait]
    impl
        Services<
            MockApiClient,
            MockHttpServer,
            MockDatabaseConnection,
            MockDatabaseTransaction,
            MockDatabasePool,
        > for MockServices
    {
        fn api(&self, base_url: String) -> MockApiClient {
            self.api.call_with_args(base_url)
        }

        async fn create_database_pool(
            &self,
            args: DatabaseArgs,
        ) -> anyhow::Result<MockDatabasePool> {
            Ok(self.create_db_pool.call_with_args(args))
        }

        async fn start_server(&self, port: u16) -> anyhow::Result<MockHttpServer> {
            Ok(self.start_server.call_with_args(port))
        }

        fn system(&self) -> &dyn System {
            &self.sys
        }
    }

    mod command_runner {
        use super::*;

        mod run {
            use autoplaylist_common::model::Page;

            use super::*;

            // Data

            #[derive(Clone)]
            struct Data<const LIMIT: u32> {
                api_base_url: &'static str,
                api_token: &'static str,
                cmd: Command,
                create_playlist_req: CreatePlaylistRequest,
                db: DatabaseArgs,
                id: Uuid,
                port: u16,
                q: &'static str,
                req: PageRequestArgs<LIMIT>,
                role: Role,
                update_playlist_req: UpdatePlaylistRequest,
                update_track_req: UpdateTrackRequest,
                update_usr_req: UpdateUserRequest,
            }

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                auth_usr: Mock<UserResponse>,
                auth_usr_playlists: Mock<Page<PlaylistResponse>>,
                auth_usr_srcs: Mock<Page<SourceResponse>>,
                auth_via_spotify: Mock<JwtResponse>,
                create_playlist: Mock<PlaylistResponse>,
                db_update_usr: Mock<()>,
                db_usr_by_id: Mock<User, User>,
                delete_auth_usr: Mock<()>,
                delete_playlist: Mock<()>,
                delete_usr: Mock<()>,
                open_spotify_authorize_url: Mock<()>,
                next_http_req: Mock<()>,
                playlist_by_id: Mock<PlaylistResponse>,
                playlist_tracks: Mock<Page<Track>>,
                playlists: Mock<Page<PlaylistResponse>>,
                search_auth_usr_plalists: Mock<Page<PlaylistResponse>>,
                search_playlist_tracks: Mock<Page<Track>>,
                search_plalists: Mock<Page<PlaylistResponse>>,
                search_src_tracks: Mock<Page<Track>>,
                search_tracks: Mock<Page<Track>>,
                search_usrs: Mock<Page<UserResponse>>,
                spotify_authorize_url: Mock<()>,
                src_by_id: Mock<SourceResponse>,
                src_tracks: Mock<Page<Track>>,
                srcs: Mock<Page<SourceResponse>>,
                start_playlist_sync: Mock<()>,
                start_src_sync: Mock<()>,
                track_by_id: Mock<Track>,
                tracks: Mock<Page<Track>>,
                update_playlist: Mock<PlaylistResponse>,
                update_track: Mock<Track>,
                update_usr: Mock<UserResponse>,
                usr_by_id: Mock<UserResponse>,
                usr_playlists: Mock<Page<PlaylistResponse>>,
                usr_srcs: Mock<Page<SourceResponse>>,
                usrs: Mock<Page<UserResponse>>,
            }

            // run

            async fn run<const LIMIT: u32>(data: Data<LIMIT>, mocks: Mocks) -> String {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let spotify_authorize_url = "https://spotify.com/authorize";
                let redirect_uri_param = RedirectUriQueryParam {
                    redirect_uri: format!("http://localhost:{}", data.port),
                };
                let auth_via_spotify_params = AuthenticateViaSpotifyQueryParams {
                    code: "code".into(),
                    redirect_uri: redirect_uri_param.redirect_uri.clone(),
                };
                let api = Mock::once_with_args({
                    let data = data.clone();
                    let mocks = mocks.clone();
                    let redirect_uri_param = redirect_uri_param.clone();
                    let auth_via_spotify_params = auth_via_spotify_params.clone();
                    move |base_url| {
                        assert_eq!(base_url, data.api_base_url);
                        let req = PageRequestQueryParams {
                            limit: Some(data.req.limit),
                            offset: Some(data.req.offset),
                        };
                        let params = SearchQueryParam { q: data.q.into() };
                        let mut api = MockApiClient::new();
                        api.expect_spotify_authorize_url()
                            .with(eq(redirect_uri_param.clone()))
                            .times(mocks.spotify_authorize_url.times())
                            .returning(move |_| Ok(spotify_authorize_url.into()));
                        api.expect_authenticate_via_spotify()
                            .with(eq(auth_via_spotify_params.clone()))
                            .times(mocks.auth_via_spotify.times())
                            .returning({
                                let mock = mocks.auth_via_spotify.clone();
                                move |_| Ok(mock.call())
                            });
                        api.expect_create_playlist()
                            .with(eq(data.create_playlist_req.clone()), eq(data.api_token))
                            .times(mocks.create_playlist.times())
                            .returning({
                                let mock = mocks.create_playlist.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_start_playlist_synchronization()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.start_playlist_sync.times())
                            .returning(|_, _| Ok(()));
                        api.expect_start_source_synchronization()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.start_src_sync.times())
                            .returning(|_, _| Ok(()));
                        api.expect_authenticated_user_playlists()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.auth_usr_playlists.times())
                            .returning({
                                let mock = mocks.auth_usr_playlists.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_playlists()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.playlists.times())
                            .returning({
                                let mock = mocks.playlists.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_authenticated_user_sources()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.auth_usr_srcs.times())
                            .returning({
                                let mock = mocks.auth_usr_srcs.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_sources()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.srcs.times())
                            .returning({
                                let mock = mocks.srcs.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_delete_playlist()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.delete_playlist.times())
                            .returning(|_, _| Ok(()));
                        api.expect_search_playlists_by_name()
                            .with(eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_plalists.times())
                            .returning({
                                let mock = mocks.search_plalists.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_search_authenticated_user_playlists_by_name()
                            .with(eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_auth_usr_plalists.times())
                            .returning({
                                let mock = mocks.search_auth_usr_plalists.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_users()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.usrs.times())
                            .returning({
                                let mock = mocks.usrs.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_search_users_by_email()
                            .with(eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_usrs.times())
                            .returning({
                                let mock = mocks.search_usrs.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_delete_user()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.delete_usr.times())
                            .returning(|_, _| Ok(()));
                        api.expect_delete_authenticated_user()
                            .with(eq(data.api_token))
                            .times(mocks.delete_auth_usr.times())
                            .returning(|_| Ok(()));
                        api.expect_authenticated_user()
                            .with(eq(data.api_token))
                            .times(mocks.auth_usr.times())
                            .returning({
                                let mock = mocks.auth_usr.clone();
                                move |_| Ok(mock.call())
                            });
                        api.expect_playlist_tracks()
                            .with(eq(data.id), eq(req), eq(data.api_token))
                            .times(mocks.playlist_tracks.times())
                            .returning({
                                let mock = mocks.playlist_tracks.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_source_tracks()
                            .with(eq(data.id), eq(req), eq(data.api_token))
                            .times(mocks.src_tracks.times())
                            .returning({
                                let mock = mocks.src_tracks.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_tracks()
                            .with(eq(req), eq(data.api_token))
                            .times(mocks.tracks.times())
                            .returning({
                                let mock = mocks.tracks.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_playlist_by_id()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.playlist_by_id.times())
                            .returning({
                                let mock = mocks.playlist_by_id.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_source_by_id()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.src_by_id.times())
                            .returning({
                                let mock = mocks.src_by_id.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_track_by_id()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.track_by_id.times())
                            .returning({
                                let mock = mocks.track_by_id.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_user_by_id()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.usr_by_id.times())
                            .returning({
                                let mock = mocks.usr_by_id.clone();
                                move |_, _| Ok(mock.call())
                            });
                        api.expect_user_playlists()
                            .with(eq(data.id), eq(req), eq(data.api_token))
                            .times(mocks.usr_playlists.times())
                            .returning({
                                let mock = mocks.usr_playlists.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_user_sources()
                            .with(eq(data.id), eq(req), eq(data.api_token))
                            .times(mocks.usr_srcs.times())
                            .returning({
                                let mock = mocks.usr_srcs.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_update_user()
                            .with(
                                eq(data.id),
                                eq(data.update_usr_req.clone()),
                                eq(data.api_token),
                            )
                            .times(mocks.update_usr.times())
                            .returning({
                                let mock = mocks.update_usr.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_update_track()
                            .with(
                                eq(data.id),
                                eq(data.update_track_req.clone()),
                                eq(data.api_token),
                            )
                            .times(mocks.update_track.times())
                            .returning({
                                let mock = mocks.update_track.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_update_playlist()
                            .with(
                                eq(data.id),
                                eq(data.update_playlist_req.clone()),
                                eq(data.api_token),
                            )
                            .times(mocks.update_playlist.times())
                            .returning({
                                let mock = mocks.update_playlist.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_search_playlist_tracks_by_title_artists_album()
                            .with(eq(data.id), eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_playlist_tracks.times())
                            .returning({
                                let mock = mocks.search_playlist_tracks.clone();
                                move |_, _, _, _| Ok(mock.call())
                            });
                        api.expect_search_source_tracks_by_title_artists_album()
                            .with(eq(data.id), eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_src_tracks.times())
                            .returning({
                                let mock = mocks.search_src_tracks.clone();
                                move |_, _, _, _| Ok(mock.call())
                            });
                        api.expect_search_tracks_by_title_artists_album()
                            .with(eq(params.clone()), eq(req), eq(data.api_token))
                            .times(mocks.search_tracks.times())
                            .returning({
                                let mock = mocks.search_tracks.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api
                    }
                });
                let create_db_pool = Mock::once_with_args({
                    let data = data.clone();
                    let mocks = mocks.clone();
                    move |args: DatabaseArgs| {
                        assert_eq!(args, data.db);
                        MockDatabasePool {
                            acquire: Mock::once({
                                let data = data.clone();
                                let mocks = mocks.clone();
                                let usr = usr.clone();
                                move || {
                                    let mut conn = MockDatabaseConnection::new();
                                    conn.0
                                        .expect_user_by_id()
                                        .with(eq(data.id))
                                        .times(mocks.db_usr_by_id.times())
                                        .returning({
                                            let mock = mocks.db_usr_by_id.clone();
                                            let usr = usr.clone();
                                            move |_| Ok(Some(mock.call_with_args(usr.clone())))
                                        });
                                    let usr = User {
                                        role: data.role,
                                        ..usr.clone()
                                    };
                                    conn.0
                                        .expect_update_user()
                                        .with(eq(usr))
                                        .times(mocks.db_update_usr.times())
                                        .returning(|_| Ok(true));
                                    conn
                                }
                            }),
                            ..Default::default()
                        }
                    }
                });
                let start_server = Mock::once_with_args({
                    let data = data.clone();
                    let mocks = mocks.clone();
                    let auth_via_spotify_params = auth_via_spotify_params.clone();
                    move |port: u16| {
                        assert_eq!(port, data.port);
                        let mut server = MockHttpServer::new();
                        server
                            .expect_next()
                            .times(mocks.next_http_req.times())
                            .returning({
                                let code = auth_via_spotify_params.code.clone();
                                move || {
                                    Some(HttpRequest {
                                        body: vec![],
                                        headers: Default::default(),
                                        method: "GET".into(),
                                        path: "/".into(),
                                        query: HashMap::from_iter([(
                                            CODE_QUERY_PARAM.into(),
                                            vec![code.clone()],
                                        )]),
                                    })
                                }
                            });
                        server
                    }
                });
                let mut sys = MockSystem::new();
                sys.expect_open_url()
                    .with(eq(spotify_authorize_url))
                    .times(mocks.open_spotify_authorize_url.times())
                    .returning(|_| Ok(()));
                let svc = MockServices {
                    api,
                    create_db_pool,
                    start_server,
                    sys,
                };
                let runner = CommandRunner {
                    svc,
                    _api: PhantomData,
                    _db: PhantomData,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                    _server: PhantomData,
                };
                let mut out = vec![];
                runner
                    .run(data.cmd, &mut out)
                    .await
                    .expect("failed to run command");
                String::from_utf8(out).expect("failed to decode UTF-8")
            }

            // Tests

            #[tokio::test]
            async fn authenticate_via_spotify() {
                let resp = JwtResponse { jwt: "jwt".into() };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Auth(AuthCommand::Spotify(AuthSpotifyCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        port,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    port,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    auth_via_spotify: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    next_http_req: Mock::once(|| ()),
                    open_spotify_authorize_url: Mock::once(|| ()),
                    spotify_authorize_url: Mock::once(|| ()),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn authenticated_user() {
                let resp = UserResponse {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let api_token = "jwt";
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Me(MeCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        delete: false,
                    }),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    auth_usr: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn authenticated_user_playlists() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::List(PlaylistListCommandArgs {
                        all: false,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: None,
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    port,
                    q: "name",
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    auth_usr_playlists: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn authenticated_user_sources() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Source(SourceCommand::List(SourceListCommandArgs {
                        all: false,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    port,
                    q: "name",
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    auth_usr_srcs: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn create_playlist() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let temp_dir =
                    TempDir::new("autoplaylist-cli").expect("failed to create directory");
                let file_path = temp_dir.path().join("req.json");
                let resp = PlaylistResponse {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".into(),
                    predicate: Predicate::YearIs(1993),
                    src: SourceResponse {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        owner: UserResponse {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        sync: SynchronizationResponse::Pending,
                    },
                    sync: SynchronizationResponse::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Playlist(PlaylistCommand::Create(PlaylistCreateCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        file: file_path.clone(),
                    })),
                    id: Uuid::new_v4(),
                    create_playlist_req: CreatePlaylistRequest {
                        name: resp.name.clone(),
                        predicate: resp.predicate.clone(),
                        src: resp.src.kind.clone(),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    create_playlist: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let mut file = File::create(&file_path).expect("failed to create file");
                serde_json::to_writer(&mut file, &data.create_playlist_req)
                    .expect("failed to serialize into file");
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn delete_authenticated_user() {
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let api_token = "jwt";
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Me(MeCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        delete: true,
                    }),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    delete_auth_usr: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn delete_playlist() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Playlist(PlaylistCommand::Delete(PlaylistDeleteCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    delete_playlist: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn delete_user() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::User(UserCommand::Delete(UserDeleteCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    delete_usr: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn playlist_by_id() {
                let resp = PlaylistResponse {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".into(),
                    predicate: Predicate::YearIs(1993),
                    src: SourceResponse {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        owner: UserResponse {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        sync: SynchronizationResponse::Pending,
                    },
                    sync: SynchronizationResponse::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Playlist(PlaylistCommand::Get(PlaylistGetCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    playlist_by_id: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn playlist_tracks() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::Tracks(PlaylistTracksCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                        search: None,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    playlist_tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn playlists() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::List(PlaylistListCommandArgs {
                        all: true,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: None,
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    playlists: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_authenticated_user_playlists_by_name() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let q = "name";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::List(PlaylistListCommandArgs {
                        all: false,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: Some(q.into()),
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: q.into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    port,
                    q,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_auth_usr_plalists: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_playlist_tracks_by_title_artists_album() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let id = Uuid::new_v4();
                let q = "name";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::Tracks(PlaylistTracksCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                        search: Some(q.into()),
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_playlist_tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_playlists_by_name() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let q = "name";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::List(PlaylistListCommandArgs {
                        all: true,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: Some(q.into()),
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    port,
                    q,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_plalists: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_source_tracks() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let q = "name";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Source(SourceCommand::Tracks(SourceTracksCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                        search: Some(q.into()),
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_src_tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_tracks() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let q = "name";
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Track(TrackCommand::List(TrackListCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        req,
                        search: Some(q.into()),
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn search_users_by_email() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let q = "name";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::User(UserCommand::List(UserListCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: Some(q.into()),
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    search_usrs: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn source_by_id() {
                let resp = SourceResponse {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    owner: UserResponse {
                        creation: Utc::now(),
                        creds: Default::default(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    sync: SynchronizationResponse::Pending,
                };
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Source(SourceCommand::Get(SourceGetCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    src_by_id: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn source_tracks() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Source(SourceCommand::Tracks(SourceTracksCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                        search: None,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    src_tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn sources() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Source(SourceCommand::List(SourceListCommandArgs {
                        all: true,
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    srcs: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn start_playlist_synchronization() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Playlist(PlaylistCommand::Synchronize(
                        PlaylistSynchronizeCommandArgs {
                            api_base_url: ApiBaseUrlArg {
                                value: api_base_url.into(),
                            },
                            api_token: TokenArg {
                                value: api_token.into(),
                            },
                            id,
                        },
                    )),
                    id,
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    q: "name",
                    port: 8080,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    start_playlist_sync: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn start_source_synchronization() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Source(SourceCommand::Synchronize(
                        SourceSynchronizeCommandArgs {
                            api_base_url: ApiBaseUrlArg {
                                value: api_base_url.into(),
                            },
                            api_token: TokenArg {
                                value: api_token.into(),
                            },
                            id,
                        },
                    )),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q: "name",
                    port: 8080,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    start_src_sync: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn track_by_id() {
                let resp = Track {
                    album: Album {
                        compil: false,
                        name: "album".into(),
                    },
                    artists: Default::default(),
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    platform: Platform::Spotify,
                    platform_id: "id".into(),
                    title: "title".into(),
                    year: 2020,
                };
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::Track(TrackCommand::Get(TrackGetCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    track_by_id: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn tracks() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Track(TrackCommand::List(TrackListCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        req,
                        search: None,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    tracks: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn update_playlist() {
                let temp_dir =
                    TempDir::new("autoplaylist-cli").expect("failed to create directory");
                let file_path = temp_dir.path().join("req.json");
                let req = UpdatePlaylistRequest {
                    name: "name".into(),
                    predicate: Predicate::YearIs(1993),
                };
                let resp = PlaylistResponse {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: req.name.clone(),
                    predicate: req.predicate.clone(),
                    src: SourceResponse {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        owner: UserResponse {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        sync: SynchronizationResponse::Pending,
                    },
                    sync: SynchronizationResponse::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Playlist(PlaylistCommand::Update(PlaylistUpdateCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        file: file_path.clone(),
                        id: resp.id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: resp.id,
                    q: "name",
                    port,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: req,
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    update_playlist: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let mut file = File::create(&file_path).expect("failed to create file");
                serde_json::to_writer(&mut file, &data.update_playlist_req)
                    .expect("failed to serialize into file");
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn update_track() {
                let temp_dir =
                    TempDir::new("autoplaylist-cli").expect("failed to create directory");
                let file_path = temp_dir.path().join("req.json");
                let req = UpdateTrackRequest {
                    album: Album {
                        compil: false,
                        name: "album".into(),
                    },
                    artists: Default::default(),
                    title: "title".into(),
                    year: 2020,
                };
                let resp = Track {
                    album: req.album.clone(),
                    artists: req.artists.clone(),
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    platform: Platform::Spotify,
                    platform_id: "id".into(),
                    title: req.title.clone(),
                    year: req.year,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::Track(TrackCommand::Update(TrackUpdateCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        file: file_path.clone(),
                        id: resp.id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: resp.id,
                    q: "name",
                    port,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: req,
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    update_track: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let mut file = File::create(&file_path).expect("failed to create file");
                serde_json::to_writer(&mut file, &data.update_track_req)
                    .expect("failed to serialize into file");
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn update_user_role() {
                let db = DatabaseArgs {
                    host: "host".into(),
                    name: "name".into(),
                    password: "password".into(),
                    port: 5432,
                    secret: "secret".into(),
                    user: "user".into(),
                };
                let id = Uuid::new_v4();
                let role = RoleArg::Admin;
                let data = Data {
                    api_base_url: "http://localhost:8000",
                    api_token: "jwt",
                    cmd: Command::Admin(AdminCommand::User(AdminUserCommand::UpdateRole(
                        AdminUserUpdateRoleCommandArgs {
                            db: db.clone(),
                            id,
                            role,
                        },
                    ))),
                    id,
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db,
                    q: "name",
                    port: 8080,
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::from(role),
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    db_usr_by_id: Mock::once_with_args(|usr| usr),
                    db_update_usr: Mock::once(|| ()),
                    ..Default::default()
                };
                let out = run(data, mocks).await;
                assert!(out.is_empty());
            }

            #[tokio::test]
            async fn user_by_id() {
                let resp = UserResponse {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    cmd: Command::User(UserCommand::Get(UserGetCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
                        id,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    port: 8080,
                    q: "name",
                    req: PageRequestArgs::<25> {
                        limit: 25,
                        offset: 0,
                    },
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    usr_by_id: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn user_playlists() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::User(UserCommand::Playlists(UserPlaylistsCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    usr_playlists: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn user_sources() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::User(UserCommand::Sources(UserSourcesCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        id,
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id,
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    usr_srcs: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }

            #[tokio::test]
            async fn users() {
                let resp = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(25, 0),
                    total: 0,
                };
                let api_base_url = "http://localhost:8000";
                let port = 3000;
                let req = PageRequestArgs::<25> {
                    limit: 25,
                    offset: 0,
                };
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    cmd: Command::User(UserCommand::List(UserListCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: "jwt".into(),
                        },
                        search: None,
                        req,
                    })),
                    create_playlist_req: CreatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                        src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    },
                    db: DatabaseArgs {
                        host: "host".into(),
                        name: "name".into(),
                        password: "password".into(),
                        port: 5432,
                        secret: "secret".into(),
                        user: "user".into(),
                    },
                    id: Uuid::new_v4(),
                    q: "name",
                    port,
                    req,
                    role: Role::Admin,
                    update_playlist_req: UpdatePlaylistRequest {
                        name: "name".into(),
                        predicate: Predicate::YearIs(1993),
                    },
                    update_track_req: UpdateTrackRequest {
                        album: Album {
                            compil: false,
                            name: "album".into(),
                        },
                        artists: Default::default(),
                        title: "title".into(),
                        year: 2020,
                    },
                    update_usr_req: UpdateUserRequest { role: Role::Admin },
                };
                let mocks = Mocks {
                    usrs: Mock::once({
                        let resp = resp.clone();
                        move || resp.clone()
                    }),
                    ..Default::default()
                };
                let expected = serde_json::to_string(&resp).expect("failed to serialize");
                let expected = format!("{expected}\n");
                let out = run(data, mocks).await;
                assert_eq!(out, expected);
            }
        }
    }

    mod page_request_query_params {
        use super::*;

        #[test]
        fn from() {
            let args = PageRequestArgs::<10> {
                limit: 10,
                offset: 0,
            };
            let expected = PageRequestQueryParams::<10> {
                limit: Some(args.limit),
                offset: Some(args.offset),
            };
            let params = PageRequestQueryParams::from(args);
            assert_eq!(params, expected);
        }
    }

    mod postgres_config {
        use super::*;

        mod from_database_args {
            use super::*;

            #[test]
            fn config() {
                let args = DatabaseArgs {
                    host: "host".into(),
                    name: "name".into(),
                    password: "password".into(),
                    port: 5432,
                    secret: "secret".into(),
                    user: "user".into(),
                };
                let expected = PostgresConfig {
                    host: args.host.clone(),
                    name: args.name.clone(),
                    password: args.password.clone(),
                    port: args.port,
                    secret: args.secret.clone(),
                    user: args.user.clone(),
                };
                let cfg = PostgresConfig::from(args);
                assert_eq!(cfg, expected);
            }
        }
    }

    mod role {
        use super::*;

        mod from_role_arg {
            use super::*;

            #[test]
            fn admin() {
                let arg = RoleArg::Admin;
                let expected = Role::Admin;
                let role = Role::from(arg);
                assert_eq!(role, expected);
            }

            #[test]
            fn user() {
                let arg = RoleArg::User;
                let expected = Role::User;
                let role = Role::from(arg);
                assert_eq!(role, expected);
            }
        }
    }
}
