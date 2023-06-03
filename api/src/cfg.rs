use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    result::Result as StdResult,
};

use autoplaylist_core::{
    broker::rabbitmq::Config as RabbitMqConfig, db::Config as DatabaseConfig, env_var,
    env_var_or_default, ConfigError,
};
use chrono::Duration;
use securefmt::Debug;
use tracing::{debug, trace};

// Types

pub type Result<T> = StdResult<T, ConfigError>;

// Structs

#[derive(Debug, Clone)]
pub struct Config {
    pub db: DatabaseConfig,
    pub jwt: JwtConfig,
    pub rabbitmq: RabbitMqConfig,
    pub server: ServerConfig,
    pub spotify: SpotifyConfig,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub issuer: String,
    #[sensitive]
    pub secret: String,
    pub validity: Duration,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub allowed_origin: String,
}

#[derive(Debug, Clone)]
pub struct SpotifyConfig {
    pub id: String,
    pub redirect_url: String,
    #[sensitive]
    pub secret: String,
}

// Impl - Config

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let webapp_url: String = env_var("WEBAPP_URL")?;
        let spotify_redirect_url = format!("{webapp_url}/auth/spotify");
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
                allowed_origin: webapp_url,
            },
            spotify: SpotifyConfig {
                id: env_var("SPOTIFY_CLIENT_ID")?,
                redirect_url: spotify_redirect_url,
                secret: env_var("SPOTIFY_CLIENT_SECRET")?,
            },
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
