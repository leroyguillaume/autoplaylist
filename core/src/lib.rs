use std::{
    env::{var, VarError},
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    io::stdout,
    str::FromStr,
};

use opentelemetry::{
    global::set_text_map_propagator, runtime::TokioCurrentThread,
    sdk::propagation::TraceContextPropagator,
};
use opentelemetry_jaeger::new_agent_pipeline;
use tracing::{error, metadata::LevelFilter, subscriber::set_global_default, warn};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_opentelemetry::layer;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, EnvFilter, Registry};

// Enums

#[derive(Debug)]
pub enum ConfigError {
    MissingEnvVar(&'static str),
    Parsing {
        key: &'static str,
        err: Box<dyn StdError>,
    },
}

// Impl - Error

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::MissingEnvVar(key) => write!(f, "missing environment variable {key}"),
            Self::Parsing { key, err } => {
                write!(f, "parsing of environment variable {key} failed:  {err}")
            }
        }
    }
}

impl StdError for ConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::MissingEnvVar(_) => None,
            Self::Parsing { err, .. } => Some(err.as_ref()),
        }
    }
}

// Functions

pub fn init_tracing(service: &str) -> Result<(), Box<dyn StdError>> {
    let jaeger_host: String =
        env_var_or_default("JAEGER_HOST", || "127.0.0.1".into()).map_err(Box::new)?;
    let jaeger_port = env_var_or_default("JAEGER_PORT", || 6831).map_err(Box::new)?;
    let service = env_var_or_default("JAEGER_SERVICE", || service.into()).map_err(Box::new)?;
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

// Functions - Utils

#[inline]
fn env_var<E: StdError + 'static, T: FromStr<Err = E>>(
    key: &'static str,
) -> Result<T, ConfigError> {
    match env_var_opt(key) {
        Ok(Some(val)) => Ok(val),
        Ok(None) => Err(ConfigError::MissingEnvVar(key)),
        Err(err) => Err(err),
    }
}

#[inline]
fn env_var_opt<E: StdError + 'static, T: FromStr<Err = E>>(
    key: &'static str,
) -> Result<Option<T>, ConfigError> {
    match var(key) {
        Ok(val) => T::from_str(&val)
            .map(Some)
            .map_err(|err| ConfigError::Parsing {
                key,
                err: Box::new(err),
            }),
        Err(err) => {
            if matches!(err, VarError::NotUnicode(_)) {
                error!("unable to read environment variable {key}: {err}");
                warn!("environment varialbe {key} will be ignored because of previous error");
            }
            Ok(None)
        }
    }
}

#[inline]
fn env_var_or_default<E: StdError + 'static, F: Fn() -> T, T: FromStr<Err = E>>(
    key: &'static str,
    default: F,
) -> Result<T, ConfigError> {
    match env_var_opt(key) {
        Ok(Some(val)) => Ok(val),
        Ok(None) => Ok(default()),
        Err(err) => Err(err),
    }
}

// Mods

pub mod broker;
pub mod db;
pub mod domain;
