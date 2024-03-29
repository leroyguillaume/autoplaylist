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
    broker::{
        rabbitmq::{
            RabbitMqClient, RabbitMqConfig, DEFAULT_BROKER_HOST, DEFAULT_BROKER_PASSWORD,
            DEFAULT_BROKER_PORT, DEFAULT_BROKER_USER, DEFAULT_BROKER_VHOST,
            DEFAULT_PLAYLIST_MSG_EXCH, DEFAULT_SRC_MSG_EXCH, ENV_VAR_KEY_BROKER_HOST,
            ENV_VAR_KEY_BROKER_PASSWORD, ENV_VAR_KEY_BROKER_PORT, ENV_VAR_KEY_BROKER_USER,
            ENV_VAR_KEY_BROKER_VHOST, ENV_VAR_KEY_SRC_MSG_EXCH,
        },
        BrokerClient, SourceMessage, SourceMessageKind,
    },
    db::{
        pg::{
            PostgresConfig, PostgresConnection, PostgresPool, PostgresTransaction, DEFAULT_DB_HOST,
            DEFAULT_DB_NAME, DEFAULT_DB_PORT, DEFAULT_DB_USER, ENV_VAR_KEY_DB_HOST,
            ENV_VAR_KEY_DB_NAME, ENV_VAR_KEY_DB_PASSWORD, ENV_VAR_KEY_DB_PORT,
            ENV_VAR_KEY_DB_SECRET, ENV_VAR_KEY_DB_USER,
        },
        DatabaseConnection, DatabasePool, DatabaseTransaction,
    },
    model::{PageRequest, Role, SynchronizationStatus},
    TracingConfig,
};
use chrono::Duration;
use clap::{Parser, Subcommand, ValueEnum};
use mockable::{
    Clock, DefaultClock, DefaultEnv, DefaultHttpServer, DefaultSystem, HttpResponse, HttpServer,
    System,
};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, error, info_span, trace, Instrument};
use uuid::Uuid;

use crate::{
    api::{ApiClient, DefaultApiClient},
    jwt::{DefaultJwtDecoder, JwtDecoder},
};

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

// Consts - Pages

const PAGE_LIMIT: u32 = 100;

// Macros

macro_rules! send_source_synchronize_messages {
    ($req:expr, $broker:expr, $f:block) => {{
        loop {
            let page = $f.await?;
            Self::send_source_synchronize_messages(page.items, &$broker).await?;
            if page.last {
                break;
            } else {
                $req.offset += PAGE_LIMIT;
            }
        }
    }};
}

// AdminCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Admin commands (not using API)")]
enum AdminCommand {
    #[command(subcommand, alias = "src")]
    Source(AdminSourceCommand),
    #[command(subcommand, alias = "usr")]
    User(AdminUserCommand),
}

// AdminSourceCommand

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
#[command(about = "Admin commands about sources")]
enum AdminSourceCommand {
    #[command(
        about = "Start aborted, failed, pending and succeeded synchronizations",
        alias = "sync"
    )]
    Synchronize(AdminSynchronizeCommandArgs),
}

// AdminSynchronizeCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct AdminSynchronizeCommandArgs {
    #[command(flatten)]
    broker: BrokerArgs,
    #[command(flatten)]
    db: DatabaseArgs,
    #[arg(
        long,
        default_value_t = 180,
        help = "Number of minutes since last succeeded synchronization"
    )]
    since: i64,
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

// BrokerArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct BrokerArgs {
    #[arg(
        long = "broker-source-message-exchange",
        env = ENV_VAR_KEY_SRC_MSG_EXCH,
        default_value = DEFAULT_SRC_MSG_EXCH,
        help = "Name of the exchange used to send source messages",
        name = "BROKER_SOURCE_MESSAGE_EXCHANGE"
    )]
    src_msg_exch: String,
    #[arg(
        long = "broker-host",
        env = ENV_VAR_KEY_BROKER_HOST,
        default_value = DEFAULT_BROKER_HOST,
        help = "Broker host",
        name = "BROKER_HOST"
    )]
    host: String,
    #[arg(
        long = "broker-password",
        env = ENV_VAR_KEY_BROKER_PASSWORD,
        default_value = DEFAULT_BROKER_PASSWORD,
        help = "Broker password",
        name = "BROKER_PASSWORD"
    )]
    password: String,
    #[arg(
        long = "broker-port",
        env = ENV_VAR_KEY_BROKER_PORT,
        default_value_t = DEFAULT_BROKER_PORT,
        help = "Broker port",
        name = "BROKER_PORT"
    )]
    port: u16,
    #[arg(
        long = "broker-user",
        env = ENV_VAR_KEY_BROKER_USER,
        default_value = DEFAULT_BROKER_USER,
        help = "Broker user",
        name = "BROKER_USER"
    )]
    user: String,
    #[arg(
        long = "broker-vhost",
        env = ENV_VAR_KEY_BROKER_VHOST,
        default_value = DEFAULT_BROKER_VHOST,
        help = "Broker virtual host (URL encoded)",
        name = "BROKER_VHOST"
    )]
    vhost: String,
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
        env = ENV_VAR_KEY_DB_HOST,
        default_value = DEFAULT_DB_HOST,
        help = "Database host",
        name = "DATABASE_HOST"
    )]
    host: String,
    #[arg(
        long = "db-name",
        env = ENV_VAR_KEY_DB_NAME,
        default_value = DEFAULT_DB_NAME,
        help = "Database name",
        name = "DATABASE_NAME"
    )]
    name: String,
    #[arg(
        long = "db-password",
        env = ENV_VAR_KEY_DB_PASSWORD,
        help = "Database password",
        name = "DATABASE_PASSWORD"
    )]
    password: String,
    #[arg(
        long = "db-port",
        env = ENV_VAR_KEY_DB_PORT,
        default_value_t = DEFAULT_DB_PORT,
        help = "Database port",
        name = "DATABASE_PORT"
    )]
    port: u16,
    #[arg(
        long = "db-secret",
        env = ENV_VAR_KEY_DB_SECRET,
        help = "Database secret",
        name = "DATABASE_SECRET"
    )]
    secret: String,
    #[arg(
        long = "db-user",
        env = ENV_VAR_KEY_DB_USER,
        default_value = DEFAULT_DB_USER,
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
    #[command(about = "Delete a track", alias = "del")]
    Delete(TrackDeleteCommandArgs),
    #[command(about = "Get a track")]
    Get(TrackGetCommandArgs),
    #[command(about = "List tracks", alias = "ls")]
    List(TrackListCommandArgs),
    #[command(about = "Update a track")]
    Update(TrackUpdateCommandArgs),
}

// TrackDeleteCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct TrackDeleteCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "Track ID")]
    id: Uuid,
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
    #[command(about = "Delete an user", alias = "del")]
    Delete(UserDeleteCommandArgs),
    #[command(about = "Get an user")]
    Get(UserGetCommandArgs),
    #[command(about = "List users", alias = "ls")]
    List(UserListCommandArgs),
    #[command(about = "List user playlists")]
    Playlists(UserPlaylistsCommandArgs),
    #[command(about = "List user sources")]
    Sources(UserSourcesCommandArgs),
    #[command(about = "List user Spotify playlists")]
    SpotifyPlaylists(UserSpotifyPlaylistsCommandArgs),
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
    #[arg(short, long, help = "Search by name")]
    search: Option<String>,
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

// UserSpotifyPlaylistsCommandArgs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct UserSpotifyPlaylistsCommandArgs {
    #[command(flatten)]
    api_base_url: ApiBaseUrlArg,
    #[command(flatten)]
    api_token: TokenArg,
    #[arg(help = "User ID")]
    id: Uuid,
    #[command(flatten)]
    req: PageRequestArgs<25>,
    #[arg(short, long, help = "Search by name")]
    search: Option<String>,
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
    BROKER: BrokerClient,
    SERVER: HttpServer,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
>: Send + Sync
{
    fn api(&self, base_url: String) -> API;

    fn clock(&self) -> &dyn Clock;

    async fn init_broker(&self, args: BrokerArgs) -> anyhow::Result<BROKER>;

    async fn init_database(&self, args: DatabaseArgs) -> anyhow::Result<DB>;

    fn jwt_decoder(&self) -> &dyn JwtDecoder;

    async fn start_server(&self, port: u16) -> anyhow::Result<SERVER>;

    fn system(&self) -> &dyn System;
}

// CommandRunner

struct CommandRunner<
    API: ApiClient,
    BROKER: BrokerClient,
    SERVER: HttpServer,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    SVC: Services<API, BROKER, SERVER, DBCONN, DBTX, DB>,
> {
    svc: SVC,
    _api: PhantomData<API>,
    _broker: PhantomData<BROKER>,
    _db: PhantomData<DB>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
    _server: PhantomData<SERVER>,
}

impl
    CommandRunner<
        DefaultApiClient,
        RabbitMqClient,
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
            _broker: PhantomData,
            _db: PhantomData,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
            _server: PhantomData,
        }
    }
}

impl<
        API: ApiClient,
        BROKER: BrokerClient,
        SERVER: HttpServer,
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services<API, BROKER, SERVER, DBCONN, DBTX, DB>,
    > CommandRunner<API, BROKER, SERVER, DBCONN, DBTX, DB, SVC>
{
    async fn run(&self, cmd: Command, mut out: &mut dyn Write) -> anyhow::Result<()> {
        match cmd {
            Command::Admin(AdminCommand::Source(AdminSourceCommand::Synchronize(args))) => {
                let span = info_span!(
                    "start_source_synchronizations",
                    broker.exch.src = args.broker.src_msg_exch,
                    db.host = args.db.host,
                    db.name = args.db.name,
                    db.port = args.db.port,
                    db.user = args.db.user,
                );
                async {
                    let broker = self.svc.init_broker(args.broker).await?;
                    let pool = self.svc.init_database(args.db).await?;
                    let mut db_conn = pool.acquire().await?;
                    let since = Duration::minutes(args.since);
                    let date = self.svc.clock().utc() - since;
                    let mut req = PageRequest::new(PAGE_LIMIT, 0);
                    send_source_synchronize_messages!(req, broker, {
                        async {
                            db_conn
                                .source_ids_by_last_synchronization_date(date, req)
                                .await
                        }
                    });
                    let mut req = PageRequest::new(PAGE_LIMIT, 0);
                    send_source_synchronize_messages!(req, broker, {
                        async {
                            db_conn
                                .source_ids_by_synchronization_status(
                                    SynchronizationStatus::Aborted,
                                    req,
                                )
                                .await
                        }
                    });
                    let mut req = PageRequest::new(PAGE_LIMIT, 0);
                    send_source_synchronize_messages!(req, broker, {
                        async {
                            db_conn
                                .source_ids_by_synchronization_status(
                                    SynchronizationStatus::Failed,
                                    req,
                                )
                                .await
                        }
                    });
                    let mut req = PageRequest::new(PAGE_LIMIT, 0);
                    send_source_synchronize_messages!(req, broker, {
                        async {
                            db_conn
                                .source_ids_by_synchronization_status(
                                    SynchronizationStatus::Pending,
                                    req,
                                )
                                .await
                        }
                    });
                    Ok(())
                }
                .instrument(span)
                .await
            }
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
                    let pool = self.svc.init_database(args.db).await?;
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
                );
                async {
                    let id = self.svc.jwt_decoder().decode(&args.api_token.value)?;
                    let api = self.svc.api(args.api_base_url.value);
                    let resp = api.user_by_id(id, &args.api_token.value).await?;
                    Self::write_to_output(out, &resp)?;
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
                    let resp = if args.all {
                        api.playlists(
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
                        .await?
                    } else {
                        let id = self.svc.jwt_decoder().decode(&args.api_token.value)?;
                        api.user_playlists(
                            id,
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
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
                    let resp = api
                        .playlist_tracks(
                            args.id,
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
                        .await?;
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
                        let id = self.svc.jwt_decoder().decode(&args.api_token.value)?;
                        api.user_sources(id, req, &args.api_token.value).await?
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
                    let resp = api
                        .source_tracks(
                            args.id,
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
                        .await?;
                    Self::write_to_output(out, &resp)
                }
                .instrument(span)
                .await
            }
            Command::Track(TrackCommand::Delete(args)) => {
                let span = info_span!(
                    "delete_track",
                    api_base_url = %args.api_base_url.value,
                    track.id = %args.id
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    api.delete_track(args.id, &args.api_token.value).await?;
                    Ok(())
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
                    let resp = api
                        .tracks(
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
                        .await?;
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
                    let resp = api
                        .users(
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
                        .await?;
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
                    params.search = args.search,
                    usr.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = api
                        .user_playlists(
                            args.id,
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
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
            Command::User(UserCommand::SpotifyPlaylists(args)) => {
                let span = info_span!(
                    "user_spotify_playlists",
                    api_base_url = %args.api_base_url.value,
                    params.limit = args.req.limit,
                    params.offset = args.req.offset,
                    params.search = args.search,
                    usr.id = %args.id,
                );
                async {
                    let api = self.svc.api(args.api_base_url.value);
                    let req = PageRequestQueryParams::from(args.req);
                    let resp = api
                        .user_spotify_playlists(
                            args.id,
                            req,
                            args.search.map(|q| SearchQueryParam { q: Some(q) }),
                            &args.api_token.value,
                        )
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
    async fn send_source_synchronize_messages(
        ids: Vec<Uuid>,
        broker: &BROKER,
    ) -> anyhow::Result<()> {
        for id in ids {
            let msg = SourceMessage {
                id,
                kind: SourceMessageKind::Synchronize,
            };
            broker.publish_source_message(&msg).await?;
        }
        Ok(())
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
        RabbitMqClient,
        DefaultHttpServer,
        PostgresConnection,
        PostgresTransaction<'_>,
        PostgresPool,
    > for DefaultServices
{
    fn api(&self, base_url: String) -> DefaultApiClient {
        DefaultApiClient::new(base_url)
    }

    fn clock(&self) -> &dyn Clock {
        &DefaultClock
    }

    async fn init_broker(&self, args: BrokerArgs) -> anyhow::Result<RabbitMqClient> {
        let cfg = RabbitMqConfig::from(args);
        let broker = RabbitMqClient::init(cfg).await?;
        Ok(broker)
    }

    async fn init_database(&self, args: DatabaseArgs) -> anyhow::Result<PostgresPool> {
        let cfg = PostgresConfig::from(args);
        let pool = PostgresPool::init(cfg).await?;
        Ok(pool)
    }

    fn jwt_decoder(&self) -> &dyn JwtDecoder {
        &DefaultJwtDecoder
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

// RabbitMqConfig

impl From<BrokerArgs> for RabbitMqConfig {
    fn from(args: BrokerArgs) -> Self {
        Self {
            host: args.host,
            password: args.password,
            playlist_msg_exch: DEFAULT_PLAYLIST_MSG_EXCH.into(),
            port: args.port,
            src_msg_exch: args.src_msg_exch,
            user: args.user,
            vhost: args.vhost,
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
mod jwt;

// Tests

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use autoplaylist_common::{
        api::{
            JwtResponse, PlaylistResponse, SourceResponse, SynchronizationResponse, UserResponse,
        },
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool, MockDatabaseTransaction},
        model::{
            Album, PageRequest, Platform, PlatformPlaylist, Predicate, SourceKind,
            SpotifySourceKind, Target, Track, User,
        },
    };
    use chrono::Utc;
    use mockable::{HttpRequest, Mock, MockClock, MockHttpServer, MockSystem};
    use mockall::predicate::eq;
    use tempdir::TempDir;
    use uuid::Uuid;

    use crate::{api::MockApiClient, jwt::MockJwtDecoder};

    use super::*;

    // MockServices

    #[derive(Default)]
    struct MockServices {
        api: Mock<MockApiClient, String>,
        clock: MockClock,
        init_broker: Mock<MockBrokerClient, BrokerArgs>,
        init_db: Mock<MockDatabasePool, DatabaseArgs>,
        jwt_decoder: MockJwtDecoder,
        start_server: Mock<MockHttpServer, u16>,
        sys: MockSystem,
    }

    #[async_trait]
    impl
        Services<
            MockApiClient,
            MockBrokerClient,
            MockHttpServer,
            MockDatabaseConnection,
            MockDatabaseTransaction,
            MockDatabasePool,
        > for MockServices
    {
        fn api(&self, base_url: String) -> MockApiClient {
            self.api.call_with_args(base_url)
        }

        fn clock(&self) -> &dyn Clock {
            &self.clock
        }

        async fn init_broker(&self, args: BrokerArgs) -> anyhow::Result<MockBrokerClient> {
            Ok(self.init_broker.call_with_args(args))
        }

        async fn init_database(&self, args: DatabaseArgs) -> anyhow::Result<MockDatabasePool> {
            Ok(self.init_db.call_with_args(args))
        }

        fn jwt_decoder(&self) -> &dyn JwtDecoder {
            &self.jwt_decoder
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
                broker: BrokerArgs,
                cmd: Command,
                create_playlist_req: CreatePlaylistRequest,
                db: DatabaseArgs,
                id: Uuid,
                port: u16,
                q: &'static str,
                req: PageRequestArgs<LIMIT>,
                role: Role,
                since: i64,
                update_playlist_req: UpdatePlaylistRequest,
                update_track_req: UpdateTrackRequest,
                update_usr_req: UpdateUserRequest,
            }

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                auth_via_spotify: Mock<JwtResponse>,
                broker_publish_src_msg: Mock<()>,
                create_playlist: Mock<PlaylistResponse>,
                db_src_ids_by_last_sync_date: Mock<()>,
                db_src_ids_by_sync_status: Mock<()>,
                db_update_usr: Mock<()>,
                db_usr_by_id: Mock<User, User>,
                decode_jwt: Mock<Uuid>,
                delete_playlist: Mock<()>,
                delete_track: Mock<()>,
                delete_usr: Mock<()>,
                open_spotify_authorize_url: Mock<()>,
                next_http_req: Mock<()>,
                now: Mock<()>,
                playlist_by_id: Mock<PlaylistResponse>,
                playlist_tracks: Mock<Page<Track>>,
                playlists: Mock<Page<PlaylistResponse>>,
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
                usr_spotify_playlists: Mock<Page<PlatformPlaylist>>,
                usr_srcs: Mock<Page<SourceResponse>>,
                usrs: Mock<Page<UserResponse>>,
            }

            // run

            async fn run<const LIMIT: u32>(data: Data<LIMIT>, mocks: Mocks) -> String {
                let now = Utc::now();
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
                let src_sync_msg_1 = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Synchronize,
                };
                let src_sync_msg_2 = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Synchronize,
                };
                let src_sync_msg_3 = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Synchronize,
                };
                let src_sync_msg_4 = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Synchronize,
                };
                let page_1 = Page {
                    first: true,
                    items: vec![src_sync_msg_1.id, src_sync_msg_2.id],
                    last: false,
                    req: PageRequest::new(PAGE_LIMIT, 0),
                    total: 0,
                };
                let page_2 = Page {
                    first: false,
                    items: vec![src_sync_msg_3.id, src_sync_msg_4.id],
                    last: true,
                    req: PageRequest::new(PAGE_LIMIT, PAGE_LIMIT),
                    total: 0,
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
                        let params = SearchQueryParam {
                            q: Some(data.q.into()),
                        };
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
                        api.expect_playlists()
                            .with(eq(req), eq(Some(params.clone())), eq(data.api_token))
                            .times(mocks.playlists.times())
                            .returning({
                                let mock = mocks.playlists.clone();
                                move |_, _, _| Ok(mock.call())
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
                        api.expect_users()
                            .with(eq(req), eq(Some(params.clone())), eq(data.api_token))
                            .times(mocks.usrs.times())
                            .returning({
                                let mock = mocks.usrs.clone();
                                move |_, _, _| Ok(mock.call())
                            });
                        api.expect_delete_user()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.delete_usr.times())
                            .returning(|_, _| Ok(()));
                        api.expect_playlist_tracks()
                            .with(
                                eq(data.id),
                                eq(req),
                                eq(Some(params.clone())),
                                eq(data.api_token),
                            )
                            .times(mocks.playlist_tracks.times())
                            .returning({
                                let mock = mocks.playlist_tracks.clone();
                                move |_, _, _, _| Ok(mock.call())
                            });
                        api.expect_source_tracks()
                            .with(
                                eq(data.id),
                                eq(req),
                                eq(Some(params.clone())),
                                eq(data.api_token),
                            )
                            .times(mocks.src_tracks.times())
                            .returning({
                                let mock = mocks.src_tracks.clone();
                                move |_, _, _, _| Ok(mock.call())
                            });
                        api.expect_tracks()
                            .with(eq(req), eq(Some(params.clone())), eq(data.api_token))
                            .times(mocks.tracks.times())
                            .returning({
                                let mock = mocks.tracks.clone();
                                move |_, _, _| Ok(mock.call())
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
                            .with(
                                eq(data.id),
                                eq(req),
                                eq(Some(params.clone())),
                                eq(data.api_token),
                            )
                            .times(mocks.usr_playlists.times())
                            .returning({
                                let mock = mocks.usr_playlists.clone();
                                move |_, _, _, _| Ok(mock.call())
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
                        api.expect_delete_track()
                            .with(eq(data.id), eq(data.api_token))
                            .times(mocks.delete_track.times())
                            .returning(|_, _| Ok(()));
                        api.expect_user_spotify_playlists()
                            .with(
                                eq(data.id),
                                eq(req),
                                eq(Some(params.clone())),
                                eq(data.api_token),
                            )
                            .times(mocks.usr_spotify_playlists.times())
                            .returning({
                                let mock = mocks.usr_spotify_playlists.clone();
                                move |_, _, _, _| Ok(mock.call())
                            });
                        api
                    }
                });
                let mut clock = MockClock::new();
                clock
                    .expect_utc()
                    .times(mocks.now.times())
                    .returning(move || now);
                let init_broker = Mock::once_with_args({
                    let src_sync_msg_1 = src_sync_msg_1.clone();
                    let src_sync_msg_2 = src_sync_msg_2.clone();
                    let src_sync_msg_3 = src_sync_msg_3.clone();
                    let src_sync_msg_4 = src_sync_msg_4.clone();
                    let data = data.clone();
                    let mocks = mocks.clone();
                    move |args| {
                        assert_eq!(args, data.broker);
                        let mut broker = MockBrokerClient::new();
                        broker
                            .expect_publish_source_message()
                            .with(eq(src_sync_msg_1.clone()))
                            .times(mocks.broker_publish_src_msg.times() * 4)
                            .returning(|_| Ok(()));
                        broker
                            .expect_publish_source_message()
                            .with(eq(src_sync_msg_2.clone()))
                            .times(mocks.broker_publish_src_msg.times() * 4)
                            .returning(|_| Ok(()));
                        broker
                            .expect_publish_source_message()
                            .with(eq(src_sync_msg_3.clone()))
                            .times(mocks.broker_publish_src_msg.times() * 4)
                            .returning(|_| Ok(()));
                        broker
                            .expect_publish_source_message()
                            .with(eq(src_sync_msg_4.clone()))
                            .times(mocks.broker_publish_src_msg.times() * 4)
                            .returning(|_| Ok(()));
                        broker
                    }
                });
                let init_db = Mock::once_with_args({
                    let page_1 = page_1.clone();
                    let page_2 = page_2.clone();
                    let data = data.clone();
                    let mocks = mocks.clone();
                    move |args: DatabaseArgs| {
                        assert_eq!(args, data.db);
                        MockDatabasePool {
                            acquire: Mock::once({
                                let page_1 = page_1.clone();
                                let page_2 = page_2.clone();
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
                                    let since = Duration::minutes(data.since);
                                    let date = now - since;
                                    conn.0
                                        .expect_source_ids_by_last_synchronization_date()
                                        .with(eq(date), eq(page_1.req))
                                        .times(mocks.db_src_ids_by_last_sync_date.times())
                                        .returning({
                                            let page = page_1.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_last_synchronization_date()
                                        .with(eq(date), eq(page_2.req))
                                        .times(mocks.db_src_ids_by_last_sync_date.times())
                                        .returning({
                                            let page = page_2.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Aborted), eq(page_1.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_1.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Aborted), eq(page_2.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_2.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Failed), eq(page_1.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_1.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Failed), eq(page_2.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_2.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Pending), eq(page_1.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_1.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn.0
                                        .expect_source_ids_by_synchronization_status()
                                        .with(eq(SynchronizationStatus::Pending), eq(page_2.req))
                                        .times(mocks.db_src_ids_by_sync_status.times())
                                        .returning({
                                            let page = page_2.clone();
                                            move |_, _| Ok(page.clone())
                                        });
                                    conn
                                }
                            }),
                            ..Default::default()
                        }
                    }
                });
                let mut jwt_decoder = MockJwtDecoder::new();
                jwt_decoder
                    .expect_decode()
                    .with(eq(data.api_token))
                    .times(mocks.decode_jwt.times())
                    .returning(move |_| Ok(data.id));
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
                    clock,
                    init_broker,
                    init_db,
                    jwt_decoder,
                    start_server,
                    sys,
                };
                let runner = CommandRunner {
                    svc,
                    _api: PhantomData,
                    _broker: PhantomData,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
                    cmd: Command::Me(MeCommandArgs {
                        api_base_url: ApiBaseUrlArg {
                            value: api_base_url.into(),
                        },
                        api_token: TokenArg {
                            value: api_token.into(),
                        },
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
                    since: 5,
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
                    decode_jwt: Mock::once(move || data.id),
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    decode_jwt: Mock::once(move || data.id),
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    decode_jwt: Mock::once(move || data.id),
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
            async fn delete_playlist() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
            async fn delete_track() {
                let api_base_url = "http://localhost:8000";
                let api_token = "jwt";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token,
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
                    cmd: Command::Track(TrackCommand::Delete(TrackDeleteCommandArgs {
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
                    since: 5,
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
                    delete_track: Mock::once(|| ()),
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                let q = "q";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
            async fn start_source_synchronizations() {
                let db = DatabaseArgs {
                    host: "host".into(),
                    name: "name".into(),
                    password: "password".into(),
                    port: 5432,
                    secret: "secret".into(),
                    user: "user".into(),
                };
                let id = Uuid::new_v4();
                let since = 5;
                let broker = BrokerArgs {
                    host: "host".into(),
                    password: "password".into(),
                    port: 5672,
                    src_msg_exch: "src_msg_exch".into(),
                    user: "user".into(),
                    vhost: "vhost".into(),
                };
                let data = Data {
                    api_base_url: "http://localhost:8000",
                    api_token: "jwt",
                    broker: broker.clone(),
                    cmd: Command::Admin(AdminCommand::Source(AdminSourceCommand::Synchronize(
                        AdminSynchronizeCommandArgs {
                            broker,
                            db: db.clone(),
                            since,
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
                    role: Role::Admin,
                    since,
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
                    broker_publish_src_msg: Mock::once(|| ()),
                    db_src_ids_by_last_sync_date: Mock::once(|| ()),
                    db_src_ids_by_sync_status: Mock::once(|| ()),
                    now: Mock::once(|| ()),
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
                let q = "q";
                let id = Uuid::new_v4();
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
                    cmd: Command::User(UserCommand::Playlists(UserPlaylistsCommandArgs {
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
                    since: 5,
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
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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
            async fn user_spotify_playlists() {
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
                    cmd: Command::User(UserCommand::SpotifyPlaylists(
                        UserSpotifyPlaylistsCommandArgs {
                            api_base_url: ApiBaseUrlArg {
                                value: api_base_url.into(),
                            },
                            api_token: TokenArg {
                                value: "jwt".into(),
                            },
                            id,
                            req,
                            search: Some(q.into()),
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
                    q,
                    port,
                    req,
                    role: Role::Admin,
                    since: 5,
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
                    usr_spotify_playlists: Mock::once({
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
                let q = "q";
                let data = Data {
                    api_base_url,
                    api_token: "jwt",
                    broker: BrokerArgs {
                        host: "host".into(),
                        password: "password".into(),
                        port: 5672,
                        src_msg_exch: "src_msg_exch".into(),
                        user: "user".into(),
                        vhost: "vhost".into(),
                    },
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
                    since: 5,
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

    mod rabbitmq_config {
        use super::*;

        mod from_broker_args {
            use super::*;

            #[test]
            fn config() {
                let args = BrokerArgs {
                    host: "host".into(),
                    password: "password".into(),
                    port: 5672,
                    src_msg_exch: "src".into(),
                    user: "user".into(),
                    vhost: "vhost".into(),
                };
                let expected = RabbitMqConfig {
                    host: args.host.clone(),
                    password: args.password.clone(),
                    playlist_msg_exch: DEFAULT_PLAYLIST_MSG_EXCH.into(),
                    port: args.port,
                    src_msg_exch: args.src_msg_exch.clone(),
                    user: args.user.clone(),
                    vhost: args.vhost.clone(),
                };
                let cfg = RabbitMqConfig::from(args);
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
