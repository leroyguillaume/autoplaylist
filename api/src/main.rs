use std::{
    env::{var, VarError},
    error::Error as StdError,
    io::stdout,
    result::Result as StdResult,
};

use actix_cors::Cors;
use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};
use broker::Channels;
use cfg::{JwtConfig, SpotifyConfig};
use deadpool_postgres::Pool as DeadpoolPostresPool;
use opentelemetry::{
    global::{set_text_map_propagator, shutdown_tracer_provider},
    runtime::TokioCurrentThread,
    sdk::propagation::TraceContextPropagator,
};
use opentelemetry_jaeger::new_agent_pipeline;
use tracing::{debug, error, info, subscriber::set_global_default};
use tracing_actix_web::TracingLogger;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_opentelemetry::layer;
use tracing_subscriber::{
    filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt, EnvFilter, Registry,
};

use self::{
    broker::open_channels,
    cfg::Config,
    db::init as init_database,
    handlers::{
        auth::{auth_with_spotify, spotify_redirect},
        query::{create_query, delete_query, list_queries},
    },
};

// Types

type Result<T> = StdResult<T, Box<dyn StdError>>;

// Structs

#[derive(Clone)]
struct Components {
    channels: Channels,
    db_pool: DeadpoolPostresPool,
    jwt_cfg: JwtConfig,
    spotify_cfg: SpotifyConfig,
}

// Functions - Main

#[actix_web::main]
async fn main() -> Result<()> {
    init_tracing()?;
    let res = run().await;
    if let Err(err) = &res {
        error!("{err}");
    }
    shutdown_tracer_provider();
    res
}

// Functions - Routes

#[get("/_health")]
async fn health() -> impl Responder {
    HttpResponse::NoContent()
}

// Functions - Utils

#[inline]
fn env_var(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|err| {
        if matches!(err, VarError::NotUnicode(_)) {
            eprintln!("unable to read environment variable {key}: {err}");
            eprintln!("default value will be used because of previous error");
        }
        default.into()
    })
}

#[inline]
fn init_tracing() -> Result<()> {
    let jaeger_host = env_var("JAEGER_HOST", "127.0.0.1");
    let jaeger_port = env_var("JAEGER_PORT", "6831");
    let service = env_var("JAEGER_SERVICE", "autoplaylist-api");
    set_text_map_propagator(TraceContextPropagator::new());
    let tracer = new_agent_pipeline()
        .with_endpoint(format!("{jaeger_host}:{jaeger_port}"))
        .with_service_name(&service)
        .install_batch(TokioCurrentThread)
        .map_err(Box::new)?;
    let filter = EnvFilter::builder()
        .with_env_var("LOG_FILTER")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .map_err(Box::new)?;
    let telemetry = layer().with_tracer(tracer);
    let logs = BunyanFormattingLayer::new(service, stdout);
    let subscriber = Registry::default()
        .with(filter)
        .with(telemetry)
        .with(JsonStorageLayer)
        .with(logs);
    set_global_default(subscriber).map_err(|err| Box::new(err) as Box<dyn StdError>)
}

#[inline]
async fn run() -> Result<()> {
    let cfg = Config::from_env()?;
    let db_pool = init_database(cfg.db).await.map_err(Box::new)?;
    let channels = open_channels(cfg.broker).await.map_err(Box::new)?;
    let cmpts = Components {
        channels,
        db_pool,
        jwt_cfg: cfg.jwt,
        spotify_cfg: cfg.spotify,
    };
    debug!("starting server on {}", cfg.server.addr);
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&cfg.server.allowed_origin)
            .allow_any_header()
            .allow_any_method();
        App::new()
            .app_data(Data::new(cmpts.clone()))
            .wrap(TracingLogger::default())
            .wrap(cors)
            .service(auth_with_spotify)
            .service(create_query)
            .service(delete_query)
            .service(health)
            .service(list_queries)
            .service(spotify_redirect)
    })
    .bind(cfg.server.addr)
    .map_err(Box::new)?;
    let server = server.run();
    info!("server is listening connections on {}", cfg.server.addr);
    server.await.map_err(Box::new)?;
    info!("server shutdown");
    Ok(())
}

// Mods

mod broker;
mod cfg;
mod db;
mod domain;
mod dto;
mod handlers;
