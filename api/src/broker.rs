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
use serde::Serialize;
use serde_json::{to_string, Error as JsonError};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::cfg::BrokerConfig;

// Consts

const BASE_EVENT_EXCHANGE_NAME: &str = "base_event";

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums - Errors

#[derive(Debug)]
pub enum Error {
    BrokerClientFailed(LapinError),
    SerializationFailed(JsonError),
}

// Enums - Kinds

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseEventKind {
    Created,
}

// Structs

#[derive(Debug, Serialize)]
pub struct BaseEvent {
    pub id: Uuid,
    pub kind: BaseEventKind,
}

#[derive(Debug, Clone)]
pub struct Channels {
    pub base_event: Channel,
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BrokerClientFailed(err) => write!(f, "broker error: {err}"),
            Self::SerializationFailed(err) => {
                write!(f, "unable to serialize event into JSON: {err}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::BrokerClientFailed(err) => Some(err),
            Error::SerializationFailed(err) => Some(err),
        }
    }
}

// Functions - Initializers

pub async fn open_channels(cfg: BrokerConfig) -> StdResult<Channels, LapinError> {
    trace!("opening broker connection");
    let conn = Connection::connect(&cfg.url, ConnectionProperties::default()).await?;
    Ok(Channels {
        base_event: declare_exchange(&conn, BASE_EVENT_EXCHANGE_NAME).await?,
    })
}

// Functions - Producers

pub async fn send_base_event(event: &BaseEvent, channel: &Channel) -> Result<()> {
    trace!("serializing {event:?} into JSON");
    let payload = to_string(event).map_err(Error::SerializationFailed)?;
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
        .map_err(Error::BrokerClientFailed)?;
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
