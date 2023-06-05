use std::{
    error::Error as StdError,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Error as JsonError;
use tokio::sync::watch::Receiver;
use uuid::Uuid;

// ConsumerError

#[derive(Debug)]
pub struct ConsumerError {
    err: Box<dyn StdError + Send + Sync>,
    requeue: bool,
}

impl ConsumerError {
    pub fn with_requeue(err: Box<dyn StdError + Send + Sync>) -> Self {
        Self { err, requeue: true }
    }

    pub fn without_requeue(err: Box<dyn StdError + Send + Sync>) -> Self {
        Self {
            err,
            requeue: false,
        }
    }
}

impl Display for ConsumerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.err)
    }
}

impl StdError for ConsumerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.err.as_ref())
    }
}

// ProducerError

#[derive(Debug)]
pub enum ProducerError {
    BrokerClient(Box<dyn StdError + Send + Sync>),
    Serialization(JsonError),
}

impl Display for ProducerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BrokerClient(err) => write!(f, "{err}"),
            Self::Serialization(err) => write!(f, "playload JSON serialization failed: {err}"),
        }
    }
}

impl StdError for ProducerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::BrokerClient(err) => Some(err.as_ref()),
            Self::Serialization(err) => Some(err),
        }
    }
}

// BaseCommandKind

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseCommandKind {
    Sync,
}

// BaseCommand

#[derive(Debug, Deserialize, Serialize)]
pub struct BaseCommand {
    pub id: Uuid,
    pub kind: BaseCommandKind,
}

// BaseEventKind

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseEventKind {
    Created,
}

// BaseEvent

#[derive(Debug, Deserialize, Serialize)]
pub struct BaseEvent {
    pub id: Uuid,
    pub kind: BaseEventKind,
}

// ConsumerHandler

#[async_trait]
pub trait ConsumerHandler<T: Debug + Send + Sync + 'static>: Send + Sync {
    async fn handle(&self, val: T) -> Result<(), ConsumerError>;
}

// Consumer

#[async_trait]
pub trait Consumer<T: Debug + DeserializeOwned + Send + Sync>: Send + Sync {
    async fn wait_for_shutdown(self: Box<Self>);
}

// Producer

#[async_trait]
pub trait Producer<T: Serialize + Send + Sync + 'static>: Send + Sync {
    async fn produce(&self, payload: &T) -> Result<(), ProducerError>;
}

// Broker

#[async_trait]
pub trait Broker: Send + Sync {
    fn base_command_producer(&self) -> Box<dyn Producer<BaseCommand>>;

    fn base_event_producer(&self) -> Box<dyn Producer<BaseEvent>>;

    async fn start_base_command_consumer(
        &self,
        queue: String,
        stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<BaseCommand>>,
    ) -> Result<Box<dyn Consumer<BaseCommand>>, Box<dyn StdError + Send + Sync>>;

    async fn start_base_event_consumer(
        &self,
        queue: String,
        stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<BaseEvent>>,
    ) -> Result<Box<dyn Consumer<BaseEvent>>, Box<dyn StdError + Send + Sync>>;
}

// Mods

pub mod rabbitmq;
