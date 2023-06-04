use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    result::Result as StdResult,
};

use autoplaylist_core::{
    broker::rabbitmq::Config as RabbitMqConfig, db::Config as DatabaseConfig, env_var,
    env_var_or_default, spotify::rspotify::Config as SpotifyConfig, ConfigError,
};
use chrono::Duration;
use securefmt::Debug;
use tracing::{debug, trace};

// Result

pub type Result<T> = StdResult<T, ConfigError>;

// JwtConfig

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub issuer: String,
    #[sensitive]
    pub secret: String,
    pub validity: Duration,
}

// ServerConfig

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub allowed_origin: String,
}

// Config

#[derive(Debug, Clone)]
pub struct Config {
    pub db: DatabaseConfig,
    pub jwt: JwtConfig,
    pub rabbitmq: RabbitMqConfig,
    pub server: ServerConfig,
    pub spotify: SpotifyConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let cfg = Config {
            db: DatabaseConfig::from_env()?,
            jwt: JwtConfig {
                issuer: env_var("DOMAIN")?,
                secret: env_var("JWT_SECRET")?,
                validity: env_var_or_default("JWT_VALIDITY", || 12 * 60 * 60)
                    .map(Duration::seconds)?,
            },
            rabbitmq: RabbitMqConfig::from_env()?,
            server: ServerConfig {
                addr: env_var_or_default("SERVER_ADDRESS", || {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080))
                })?,
                allowed_origin: env_var("WEBAPP_URL")?,
            },
            spotify: SpotifyConfig::from_env()?,
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
