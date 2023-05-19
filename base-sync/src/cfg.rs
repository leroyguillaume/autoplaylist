use std::result::Result as StdResult;

use autoplaylist_core::{
    broker::Config as BrokerConfig, db::Config as DatabaseConfig, ConfigError,
};
use tracing::{debug, trace};

// Types

pub type Result<T> = StdResult<T, ConfigError>;

// Structs

#[derive(Debug, Clone)]
pub struct Config {
    pub broker: BrokerConfig,
    pub db: DatabaseConfig,
}

// Impl - Config

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let cfg = Config {
            broker: BrokerConfig::from_env()?,
            db: DatabaseConfig::from_env()?,
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
