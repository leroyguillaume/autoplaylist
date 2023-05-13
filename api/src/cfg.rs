use std::{
    error::Error as StdError,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    result::Result as StdResult,
};

use config::{Config as ConfigConfig, Environment};
use serde::Deserialize;
use tracing::{debug, trace};

use crate::box_error;

// Consts

const DEFAULT_SERVER_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));

// Types

pub type Result<T> = StdResult<T, Box<dyn StdError>>;

// Structs

#[derive(Debug)]
pub struct Config {
    pub server_addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct EnvConfig {
    server_address: Option<SocketAddr>,
}

// Impl - Config

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration from environment");
        let env_cfg: EnvConfig = ConfigConfig::builder()
            .add_source(
                Environment::default()
                    .try_parsing(true)
                    .separator("_")
                    .list_separator(","),
            )
            .build()
            .map_err(box_error)?
            .try_deserialize()
            .map_err(box_error)?;
        trace!("configuration from environment loaded: {env_cfg:?}");
        let cfg = Config {
            server_addr: env_cfg.server_address.unwrap_or(DEFAULT_SERVER_ADDR),
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}
