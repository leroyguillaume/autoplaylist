use std::{error::Error as StdError, io::stdout, result::Result as StdResult};

use actix_cors::Cors;
use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};
use cfg::{JwtConfig, ServerConfig, SpotifyConfig};
use deadpool_postgres::{
    tokio_postgres::NoTls, Config as DeadpoolPostgresConfig, Pool as DeadpoolPostresPool,
};
use opentelemetry::{
    global::{set_text_map_propagator, shutdown_tracer_provider},
    runtime::TokioCurrentThread,
    sdk::propagation::TraceContextPropagator,
};
use opentelemetry_jaeger::new_pipeline;
use tracing::{debug, error, info, subscriber::set_global_default, trace};
use tracing_actix_web::TracingLogger;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_opentelemetry::layer;
use tracing_subscriber::{
    filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt, EnvFilter, Registry,
};

use self::{
    cfg::Config,
    db::run_migrations,
    handlers::auth::{auth_with_spotify, spotify_redirect},
};

// Types

type Result<T> = StdResult<T, Box<dyn StdError>>;

// Structs

#[derive(Clone)]
struct Components {
    db_pool: DeadpoolPostresPool,
    jwt_cfg: JwtConfig,
    spotify_cfg: SpotifyConfig,
}

// Functions - Main

#[actix_web::main]
async fn main() -> Result<()> {
    init_tracing()?;
    let cfg = Config::from_env()?;
    let db_pool_cfg: DeadpoolPostgresConfig = cfg.db.into();
    trace!("creating database client pool");
    let db_pool = db_pool_cfg.create_pool(None, NoTls).map_err(Box::new)?;
    let cmpts = Components {
        db_pool: db_pool.clone(),
        jwt_cfg: cfg.jwt,
        spotify_cfg: cfg.spotify,
    };
    let res = run(cmpts, cfg.server).await;
    trace!("closing database client pool");
    db_pool.close();
    shutdown_tracer_provider();
    if let Err(err) = &res {
        error!("{err}");
    }
    res
}

// Functions - Routes

#[get("/_health")]
async fn health() -> impl Responder {
    HttpResponse::NoContent()
}

// Functions - Utils

#[inline]
fn init_tracing() -> Result<()> {
    let app_name = env!("CARGO_PKG_NAME");
    set_text_map_propagator(TraceContextPropagator::new());
    let tracer = new_pipeline()
        .with_service_name(app_name)
        .install_batch(TokioCurrentThread)
        .map_err(Box::new)?;
    let env_filter = EnvFilter::builder()
        .with_env_var("LOG_FILTER")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .map_err(Box::new)?;
    let telemetry = layer().with_tracer(tracer);
    let formatting_layer = BunyanFormattingLayer::new(app_name.into(), stdout);
    let subscriber = Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(JsonStorageLayer)
        .with(formatting_layer);
    set_global_default(subscriber).map_err(|err| Box::new(err) as Box<dyn StdError>)
}

#[inline]
async fn run(cmpts: Components, cfg: ServerConfig) -> Result<()> {
    run_migrations(&cmpts.db_pool).await?;
    debug!("starting server on {}", cfg.addr);
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&cfg.allowed_origin)
            .allow_any_header()
            .allow_any_method();
        App::new()
            .app_data(Data::new(cmpts.clone()))
            .wrap(TracingLogger::default())
            .wrap(cors)
            .service(auth_with_spotify)
            .service(health)
            .service(spotify_redirect)
    })
    .bind(cfg.addr)
    .map_err(Box::new)?;
    let server = server.run();
    info!("server is listening connections on {}", cfg.addr);
    server.await.map_err(Box::new)?;
    info!("server shutdown");
    Ok(())
}

// Mods

mod cfg;
mod db;
mod domain;
mod dto;
mod handlers;
