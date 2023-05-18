use std::{
    env::{var, VarError},
    error::Error as StdError,
    io::stdout,
};

use opentelemetry::{
    global::set_text_map_propagator, runtime::TokioCurrentThread,
    sdk::propagation::TraceContextPropagator,
};
use opentelemetry_jaeger::new_agent_pipeline;
use tracing::{metadata::LevelFilter, subscriber::set_global_default};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_opentelemetry::layer;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, EnvFilter, Registry};

// Functions

pub fn init_tracing(service: &str) -> Result<(), Box<dyn StdError>> {
    let jaeger_host = env_var("JAEGER_HOST", "127.0.0.1");
    let jaeger_port = env_var("JAEGER_PORT", "6831");
    let service = env_var("JAEGER_SERVICE", service);
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
fn env_var(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|err| {
        if matches!(err, VarError::NotUnicode(_)) {
            eprintln!("unable to read environment variable {key}: {err}");
            eprintln!("default value will be used because of previous error");
        }
        default.into()
    })
}
