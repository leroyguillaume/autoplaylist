use std::{
    env::{var, VarError},
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    result::Result as StdResult,
    str::FromStr,
};

use deadpool_postgres::Config as DeadpoolPostgresConfig;
use securefmt::Debug;
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

#[derive(Debug, Clone)]
pub struct Config {
    pub db: DatabaseConfig,
    pub server: ServerConfig,
    pub spotify: SpotifyConfig,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub name: String,
    pub port: Option<u16>,
    #[sensitive]
    pub pwd: String,
    pub user: String,
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
        let webapp_url: String = Self::env_var("WEBAPP_URL")?;
        let spotify_redirect_url = format!("{webapp_url}/auth/spotify");
        let cfg = Config {
            db: DatabaseConfig {
                host: Self::env_var("DB_HOST")?,
                name: Self::env_var_or_default("DB_NAME", || "autoplaylist".into())?,
                port: Self::env_var_opt("DB_PORT")?,
                pwd: Self::env_var("DB_PASSWORD")?,
                user: Self::env_var_or_default("DB_USER", || "autoplaylist".into())?,
            },
            server: ServerConfig {
                addr: Self::env_var_or_default("SERVER_ADDRESS", || {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080))
                })?,
                allowed_origin: webapp_url,
            },
            spotify: SpotifyConfig {
                id: Self::env_var("SPOTIFY_CLIENT_ID")?,
                redirect_url: spotify_redirect_url,
                secret: Self::env_var("SPOTIFY_CLIENT_SECRET")?,
            },
        };
        debug!("configuration loaded: {cfg:?}");
        Ok(cfg)
    }

    #[inline]
    fn env_var<E: StdError + 'static, T: FromStr<Err = E>>(key: &'static str) -> Result<T> {
        match Self::env_var_opt(key) {
            Ok(Some(val)) => Ok(val),
            Ok(None) => Err(Error::MissingEnvVar(key)),
            Err(err) => Err(err),
        }
    }

    #[inline]
    fn env_var_opt<E: StdError + 'static, T: FromStr<Err = E>>(
        key: &'static str,
    ) -> Result<Option<T>> {
        match var(key) {
            Ok(val) => T::from_str(&val)
                .map(Some)
                .map_err(|err| Error::ParsingFailed {
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
    ) -> Result<T> {
        match Self::env_var_opt(key) {
            Ok(Some(val)) => Ok(val),
            Ok(None) => Ok(default()),
            Err(err) => Err(err),
        }
    }
}

// Impl - DeadpoolPostgresConfig

impl From<DatabaseConfig> for DeadpoolPostgresConfig {
    fn from(cfg: DatabaseConfig) -> Self {
        Self {
            dbname: Some(cfg.name),
            host: Some(cfg.host),
            password: Some(cfg.pwd),
            port: cfg.port,
            user: Some(cfg.user),
            ..Default::default()
        }
    }
}
