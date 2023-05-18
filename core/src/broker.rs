use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
};

use lapin::{
    options::{BasicPublishOptions, ExchangeDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, Error as LapinError, ExchangeKind,
};
use securefmt::Debug;
use serde::Serialize;
use serde_json::{to_string, Error as JsonError};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{env_var, ConfigError};

// Consts

const BASE_EVENT_EXCHANGE_NAME: &str = "base_event";

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums - Errors

#[derive(Debug)]
pub enum Error {
    BrokerClient(LapinError),
    Serialization(JsonError),
}

#[derive(Debug)]
pub enum InitializationError {
    Connection(LapinError),
    ExchangeDeclaration { err: LapinError, name: &'static str },
}

// Enums - Kinds

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseEventKind {
    Created,
}

// Structs

#[derive(Debug, Clone)]
pub struct Config {
    #[sensitive]
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Channels {
    pub base_event: Channel,
}

// Structs - Events

#[derive(Debug, Serialize)]
pub struct BaseEvent {
    pub id: Uuid,
    pub kind: BaseEventKind,
}

// Impl - Config

impl Config {
    pub fn from_env() -> StdResult<Self, ConfigError> {
        trace!("loading broker configuration");
        let cfg = Self {
            url: env_var("BROKER_URL")?,
        };
        debug!("broker configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BrokerClient(err) => write!(f, "broker error: {err}"),
            Self::Serialization(err) => {
                write!(f, "unable to serialize event into JSON: {err}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::BrokerClient(err) => Some(err),
            Error::Serialization(err) => Some(err),
        }
    }
}

// Impl - InitializationError

impl Display for InitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Connection(err) => write!(f, "unable to open broker connection: {err}"),
            Self::ExchangeDeclaration { err, name } => {
                write!(f, "unable to create broker exchange `{name}`: {err}")
            }
        }
    }
}

impl StdError for InitializationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::ExchangeDeclaration { err, .. } => Some(err),
        }
    }
}

// Functions - Initializers

pub async fn open_channels(cfg: Config) -> StdResult<Channels, InitializationError> {
    trace!("opening broker connection");
    let conn = Connection::connect(&cfg.url, ConnectionProperties::default())
        .await
        .map_err(InitializationError::Connection)?;
    Ok(Channels {
        base_event: declare_exchange(&conn, BASE_EVENT_EXCHANGE_NAME)
            .await
            .map_err(|err| InitializationError::ExchangeDeclaration {
                err,
                name: BASE_EVENT_EXCHANGE_NAME,
            })?,
    })
}

// Functions - Producers

pub async fn send_base_event(event: &BaseEvent, channel: &Channel) -> Result<()> {
    trace!("serializing {event:?} into JSON");
    let payload = to_string(event).map_err(Error::Serialization)?;
    debug!("sending {payload:?} to broker");
    channel
        .basic_publish(
            BASE_EVENT_EXCHANGE_NAME,
            "",
            BasicPublishOptions::default(),
            payload.as_bytes(),
            BasicProperties::default(),
        )
        .await
        .map_err(Error::BrokerClient)?;
    Ok(())
}

// Functions - Utils

#[inline]
async fn declare_exchange(conn: &Connection, exchange: &str) -> StdResult<Channel, LapinError> {
    trace!("creating broker channel");
    let channel = conn.create_channel().await?;
    debug!("declaring broker exchange `{exchange}`");
    channel
        .exchange_declare(
            exchange,
            ExchangeKind::Fanout,
            ExchangeDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    Ok(channel)
}
