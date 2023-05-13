use std::{
    env::{var, VarError},
    error::Error as StdError,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    result::Result as StdResult,
    str::FromStr,
};

use tracing::{debug, error, trace, warn};

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums

#[derive(Debug)]
pub enum Error {
    MissingEnvVar(&'static str),
    ParsingFailed {
        key: &'static str,
        err: Box<dyn StdError>,
    },
}

// Structs

#[derive(Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub spotify_client_id: String,
    pub spotify_client_secret: String,
    pub webapp_url: String,
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::MissingEnvVar(key) => write!(f, "missing environment variable {key}"),
            Self::ParsingFailed { key, err } => {
                write!(f, "unable to parse environment variable {key}:  {err}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::MissingEnvVar(_) => None,
            Self::ParsingFailed { err, .. } => Some(err.as_ref()),
        }
    }
}

// Impl - Config

impl Config {
    pub fn from_env() -> Result<Self> {
        trace!("loading configuration");
        let cfg = Config {
            server_addr: Self::env_var_or_default("SERVER_ADDRESS", || {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080))
            })?,
            spotify_client_id: Self::env_var("SPOTIFY_CLIENT_ID")?,
            spotify_client_secret: Self::env_var("SPOTIFY_CLIENT_SECRET")?,
            webapp_url: Self::env_var("WEBAPP_URL")?,
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }

    #[inline]
    fn env_var<E: StdError + 'static, T: FromStr<Err = E>>(key: &'static str) -> Result<T> {
        match var(key) {
            Ok(val) => T::from_str(&val).map_err(|err| Error::ParsingFailed {
                key,
                err: Box::new(err),
            }),
            Err(err) => {
                if matches!(err, VarError::NotUnicode(_)) {
                    error!("unable to read environment variable {key}: {err}");
                    warn!("environment varialbe {key} will be ignored because of previous error");
                }
                Err(Error::MissingEnvVar(key))
            }
        }
    }

    #[inline]
    fn env_var_or_default<E: StdError + 'static, F: Fn() -> T, T: FromStr<Err = E>>(
        key: &'static str,
        default: F,
    ) -> Result<T> {
        match Self::env_var(key) {
            Ok(val) => Ok(val),
            Err(Error::MissingEnvVar(_)) => Ok(default()),
            err => err,
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("Config")
            .field("server_address", &self.server_addr)
            .field("spotify_client_id", &self.spotify_client_id)
            .field("spotify_client_secret", &"****")
            .finish()
    }
}
