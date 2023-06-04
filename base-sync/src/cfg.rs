use std::result::Result as StdResult;

use autoplaylist_core::{
    broker::rabbitmq::Config as RabbitMqConfig, db::Config as DatabaseConfig, env_var_or_default,
    spotify::rspotify::Config as SpotifyConfig, ConfigError,
};
use tracing::{debug, trace};

// Result

pub type Result<T> = StdResult<T, ConfigError>;

// QueuesConfig

#[derive(Debug, Clone)]
pub struct QueuesConfig {
    pub base_cmd: String,
    pub base_event: String,
}

impl QueuesConfig {
    pub fn from_env() -> Result<Self> {
        trace!("loading queues configuration");
        let cfg = Self {
            base_cmd: env_var_or_default("BASE_COMMAND_QUEUE", || "base-sync_base-command".into())?,
            base_event: env_var_or_default("BASE_EVENT_QUEUE", || "base-sync_base-event".into())?,
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
    pub spotify: SpotifyConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let cfg = Self {
            db: DatabaseConfig::from_env()?,
            queues: QueuesConfig::from_env()?,
            rabbitmq: RabbitMqConfig::from_env()?,
            spotify: SpotifyConfig::from_env()?,
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
