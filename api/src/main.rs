use std::{io::stdout, process::exit};

use actix_cors::Cors;
use actix_web::{get, web::Data, App, HttpResponse, HttpServer, Responder};
use opentelemetry::{
    global::{set_text_map_propagator, shutdown_tracer_provider},
    runtime::TokioCurrentThread,
    sdk::propagation::TraceContextPropagator,
};
use tracing::{debug, error, info};
use tracing_actix_web::TracingLogger;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{
    filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt, EnvFilter, Registry,
};

use self::{cfg::Config, handlers::auth::spotify_redirect};

// Macros

macro_rules! eprint_and_exit_on_error {
    ($res:expr, $rc:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) => {
                eprintln!("{err}");
                exit($rc);
            }
        }
    };
}

macro_rules! log_and_exit_on_error {
    ($res:expr, $rc:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) => {
                error!("{err}");
                exit($rc);
            }
        }
    };
}

// Functions - Main

#[actix_web::main]
async fn main() {
    init_tracing();
    let cfg = log_and_exit_on_error!(Config::from_env(), exitcode::CONFIG);
    let server_addr = cfg.server_addr;
    debug!("starting server on {}", cfg.server_addr);
    let res = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&cfg.webapp_url)
            .allow_any_header()
            .allow_any_method();
        App::new()
            .app_data(Data::new(cfg.clone()))
            .wrap(TracingLogger::default())
            .wrap(cors)
            .service(health)
            .service(spotify_redirect)
    })
    .bind(server_addr);
    let server = log_and_exit_on_error!(res, exitcode::IOERR);
    let server = server.run();
    info!("server is listening connections on {}", server_addr);
    log_and_exit_on_error!(server.await, exitcode::IOERR);
    info!("server shutdown");
    shutdown_tracer_provider();
}

// Functions - Routes

#[get("/_health")]
async fn health() -> impl Responder {
    HttpResponse::NoContent()
}

// Functions - Utils

#[inline]
fn init_tracing() {
    let app_name = env!("CARGO_PKG_NAME");
    set_text_map_propagator(TraceContextPropagator::new());
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name(app_name)
        .install_batch(TokioCurrentThread)
        .expect("failed to install OpenTelemetry tracer");
    let res = EnvFilter::builder()
        .with_env_var("LOG_FILTER")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env();
    let env_filter = eprint_and_exit_on_error!(res, exitcode::CONFIG);
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    let formatting_layer = BunyanFormattingLayer::new(app_name.into(), stdout);
    let subscriber = Registry::default()
        .with(env_filter)
        .with(telemetry)
        .with(JsonStorageLayer)
        .with(formatting_layer);
    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to install `tracing` subscriber");
}

// Mods

mod cfg;
mod handlers;
