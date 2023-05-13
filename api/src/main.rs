use std::{error::Error as StdError, process::exit};

use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use tracing::{debug, error, info};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use self::cfg::Config;

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
    debug!("starting server on {}", cfg.server_addr);
    let res = HttpServer::new(|| App::new().wrap(TracingLogger::default()).service(health))
        .bind(cfg.server_addr);
    let server = log_and_exit_on_error!(res, exitcode::IOERR);
    let server = server.run();
    info!("server is listening connections on {}", cfg.server_addr);
    log_and_exit_on_error!(server.await, exitcode::IOERR);
    info!("server shutdown");
}

// Functions - Routes

#[get("/_health")]
async fn health() -> impl Responder {
    HttpResponse::NoContent()
}

// Functions - Utils

#[inline]
fn box_error<E: StdError + 'static>(err: E) -> Box<dyn StdError> {
    Box::new(err)
}

#[inline]
fn init_tracing() {
    let res = EnvFilter::builder()
        .with_env_var("LOG_FILTER")
        .with_default_directive("autoplaylist_api=info".parse().unwrap())
        .from_env();
    let env_filter = eprint_and_exit_on_error!(res, exitcode::CONFIG);
    let res = tracing_subscriber::fmt()
        .compact()
        .with_env_filter(env_filter)
        .try_init();
    eprint_and_exit_on_error!(res, exitcode::SOFTWARE);
}

// Mods

mod cfg;
