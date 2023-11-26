use std::io::Write;

use mockable::Env;
use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{filter::Directive, layer::SubscriberExt, EnvFilter, Registry};

// Consts - Env var keys

pub const ENV_VAR_KEY_LOG_FILTER: &str = "LOG_FILTER";
pub const ENV_VAR_KEY_LOG_JSON: &str = "LOG_JSON";

// Consts - Defaults

pub const DEFAULT_LOG_FILTER: &str = "info";
pub const DEFAULT_LOG_JSON: bool = true;

// TracingConfig

pub struct TracingConfig<'a, W: Write, F: Fn() -> W + Send + Sync + 'static> {
    default_filter: &'a str,
    filter: Option<&'a str>,
    json: bool,
    pkg: &'a str,
    out: F,
}

impl<'a, W: Write, F: Fn() -> W + Send + Sync + 'static> TracingConfig<'a, W, F> {
    pub fn new(pkg: &'a str, out: F) -> Self {
        Self {
            default_filter: DEFAULT_LOG_FILTER,
            filter: None,
            json: DEFAULT_LOG_JSON,
            out,
            pkg,
        }
    }

    pub fn with_filter(mut self, filter: &'a str) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn with_json_disabled_by_default(mut self) -> Self {
        self.json = false;
        self
    }

    pub fn init(self, env: &dyn Env) {
        let dir: Directive = self
            .default_filter
            .parse()
            .expect("failed to parse default log filter");
        let json = env
            .bool(ENV_VAR_KEY_LOG_JSON)
            .unwrap_or(Ok(self.json))
            .unwrap_or(self.json);
        let filter = if let Some(filter) = self.filter {
            filter.parse().expect("failed to parse log filter")
        } else {
            EnvFilter::builder()
                .with_env_var(ENV_VAR_KEY_LOG_FILTER)
                .with_default_directive(dir)
                .from_env_lossy()
        };
        let res = if json {
            let registry = Registry::default()
                .with(filter)
                .with(JsonStorageLayer)
                .with(BunyanFormattingLayer::new(self.pkg.into(), self.out));
            set_global_default(registry)
        } else {
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(self.out)
                .compact();
            let registry = Registry::default().with(filter).with(layer);
            set_global_default(registry)
        };
        if let Err(err) = res {
            eprintln!("failed to initialize tracing: {err}");
        }
    }
}
