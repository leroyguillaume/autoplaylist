use std::{error::Error as StdError, result::Result as StdResult, sync::Arc};

use actix_cors::Cors;
use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};
use autoplaylist_core::{
    broker::{rabbitmq::RabbitMqBroker, BaseCommand, BaseEvent, Broker, Producer},
    db::{postgres::PostgresPool, Pool as DatabasePool},
    init_tracing,
    spotify::{rspotify::RSpotifyClient, Client as SpotifyClient},
};
use cfg::JwtConfig;
use opentelemetry::global::shutdown_tracer_provider;
use tracing::{debug, error, info};
use tracing_actix_web::TracingLogger;

use crate::handlers::base::start_base_sync;

use self::{
    cfg::Config,
    handlers::{
        auth::{auth_with_spotify, spotify_redirect},
        base::list_bases,
        playlist::{create_playlist, delete_playlist, list_playlists},
    },
};

// Types

type Result<T> = StdResult<T, Box<dyn StdError + Send + Sync>>;

// Structs

#[derive(Clone)]
struct Components {
    base_cmd_prd: Arc<Box<dyn Producer<BaseCommand>>>,
    base_event_prd: Arc<Box<dyn Producer<BaseEvent>>>,
    db_pool: Arc<Box<dyn DatabasePool>>,
    jwt_cfg: JwtConfig,
    spotify_client: Arc<Box<dyn SpotifyClient>>,
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
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let spotify_client = RSpotifyClient::new(cfg.spotify);
    let cmpts = Components {
        base_cmd_prd: Arc::new(broker.base_command_producer()),
        base_event_prd: Arc::new(broker.base_event_producer()),
        db_pool: Arc::new(Box::new(db_pool)),
        jwt_cfg: cfg.jwt,
        spotify_client: Arc::new(Box::new(spotify_client)),
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
            .service(create_playlist)
            .service(delete_playlist)
            .service(health)
            .service(list_bases)
            .service(list_playlists)
            .service(spotify_redirect)
            .service(start_base_sync)
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
