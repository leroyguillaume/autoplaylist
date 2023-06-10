use std::result::Result as StdResult;

use autoplaylist_core::{
    broker::rabbitmq::Config as RabbitMqConfig, db::Config as DatabaseConfig, env_var_or_default,
    ConfigError,
};
use tracing::{debug, trace};

// Result

pub type Result<T> = StdResult<T, ConfigError>;

// QueuesConfig

#[derive(Debug, Clone)]
pub struct QueuesConfig {
    pub track_cmd: String,
    pub track_event: String,
}

impl QueuesConfig {
    pub fn from_env() -> Result<Self> {
        trace!("loading queues configuration");
        let cfg = Self {
            track_cmd: env_var_or_default("TRACK_COMMAND_QUEUE", || {
                "playlist-sync_track-command".into()
            })?,
            track_event: env_var_or_default("TRACK_EVENT_QUEUE", || {
                "playlist-sync_track-event".into()
            })?,
        };
        trace!("queues configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// Config

#[derive(Debug, Clone)]
pub struct Config {
    pub rabbitmq: RabbitMqConfig,
    pub db: DatabaseConfig,
    pub queues: QueuesConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let cfg = Self {
            db: DatabaseConfig::from_env()?,
            queues: QueuesConfig::from_env()?,
            rabbitmq: RabbitMqConfig::from_env()?,
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
