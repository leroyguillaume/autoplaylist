use std::{error::Error as StdError, result::Result as StdResult};

use actix_cors::Cors;
use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};
use autoplaylist_core::{
    broker::{open_channels, Channels, Config as BrokerConfig},
    db::{init as init_database, Config as DatabaseConfig},
    init_tracing,
};
use cfg::{JwtConfig, SpotifyConfig};
use deadpool_postgres::Pool as DeadpoolPostresPool;
use opentelemetry::global::shutdown_tracer_provider;
use tracing::{debug, error, info};
use tracing_actix_web::TracingLogger;

use self::{
    cfg::Config,
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
    init_tracing("autoplaylist-api")?;
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
async fn run() -> Result<()> {
    let cfg = Config::from_env()?;
    let db_cfg = DatabaseConfig::from_env()?;
    let broker_cfg = BrokerConfig::from_env()?;
    let db_pool = init_database(db_cfg).await.map_err(Box::new)?;
    let channels = open_channels(broker_cfg).await.map_err(Box::new)?;
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

mod cfg;
mod dto;
mod handlers;
