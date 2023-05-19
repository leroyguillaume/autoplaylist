use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    result::Result as StdResult,
    sync::Arc,
};

use futures::{FutureExt, StreamExt};
use lapin::{
    message::Delivery,
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
        ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
    },
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, Consumer, Error as LapinError,
    ExchangeKind,
};
use securefmt::Debug;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{from_slice, to_string, Error as JsonError};
use tokio::{
    spawn,
    sync::watch::Receiver,
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, error, trace};
use uuid::Uuid;

use crate::{env_var, ConfigError};

// Consts

const BASE_EVENT_EXCHANGE_NAME: &str = "base-event";

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums - Errors

#[derive(Debug)]
pub enum BrokerInitializationError {
    Connection(LapinError),
    ExchangeDeclaration { err: LapinError, name: &'static str },
}

#[derive(Debug)]
pub enum Error {
    BrokerClient(LapinError),
    Serialization(JsonError),
}

// Enums - Kinds

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseEventKind {
    Created,
}

#[derive(Debug)]
pub enum ConsumerInitializationErrorKind {
    Bind(&'static str),
    Consumer,
    Queue,
}

// Enums

#[derive(Debug, Clone, Copy)]
pub enum ConsumerSignal {
    Start,
    Stop,
}

// Structs - Errors

#[derive(Debug)]
pub struct ConsumerError {
    err: Box<dyn StdError + Send + Sync>,
    requeue: bool,
}

#[derive(Debug)]
pub struct ConsumerInitializationError {
    err: LapinError,
    kind: ConsumerInitializationErrorKind,
    queue: &'static str,
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

#[derive(Debug, Deserialize, Serialize)]
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
        trace!("broker configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// Impl - BrokerInitializationError

impl Display for BrokerInitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Connection(err) => write!(f, "broker connection failed: {err}"),
            Self::ExchangeDeclaration { err, name } => {
                write!(f, "broker exchange `{name}` creation failed: {err}")
            }
        }
    }
}

impl StdError for BrokerInitializationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::ExchangeDeclaration { err, .. } => Some(err),
        }
    }
}

// Impl - ConsumerError

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

// Impl - ConsumerInitializationError

impl Display for ConsumerInitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self.kind {
            ConsumerInitializationErrorKind::Bind(exchange) => write!(
                f,
                "binding broker queue `{}` on exchange `{exchange}` failed: {}",
                self.queue, self.err
            ),
            ConsumerInitializationErrorKind::Consumer => write!(
                f,
                "broker consumer on queue `{}` creation failed: {}",
                self.queue, self.err
            ),
            ConsumerInitializationErrorKind::Queue => write!(
                f,
                "broker queue `{}` creation failed: {}",
                self.queue, self.err
            ),
        }
    }
}

impl StdError for ConsumerInitializationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.err)
    }
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BrokerClient(err) => write!(f, "broker error: {err}"),
            Self::Serialization(err) => {
                write!(f, "event serialization into JSON failed: {err}")
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

// Functions - Initializers

pub async fn open_channels(cfg: Config) -> StdResult<Channels, BrokerInitializationError> {
    trace!("opening broker connection");
    let conn = Connection::connect(&cfg.url, ConnectionProperties::default())
        .await
        .map_err(BrokerInitializationError::Connection)?;
    Ok(Channels {
        base_event: declare_exchange(&conn, BASE_EVENT_EXCHANGE_NAME)
            .await
            .map_err(|err| BrokerInitializationError::ExchangeDeclaration {
                err,
                name: BASE_EVENT_EXCHANGE_NAME,
            })?,
    })
}

// Functions - Consumers

pub async fn start_consumer<
    F: Fn(T) -> R + Send + Sync + 'static,
    R: Future<Output = StdResult<(), ConsumerError>> + Send,
    T: DeserializeOwned + Send,
>(
    queue: &'static str,
    channels: &Channels,
    sig_rcv: Receiver<ConsumerSignal>,
    handle: F,
) -> StdResult<JoinHandle<()>, ConsumerInitializationError> {
    create_and_start_consumer(
        queue,
        &channels.base_event,
        BASE_EVENT_EXCHANGE_NAME,
        sig_rcv,
        handle,
    )
    .await
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
async fn create_consumer(
    queue: &'static str,
    exchange: &'static str,
    channel: &Channel,
) -> StdResult<Consumer, ConsumerInitializationError> {
    debug!("declaring broker queue `{queue}`");
    channel
        .queue_declare(queue, QueueDeclareOptions::default(), FieldTable::default())
        .await
        .map_err(|err| ConsumerInitializationError {
            err,
            kind: ConsumerInitializationErrorKind::Queue,
            queue,
        })?;
    trace!("binding broker queue `{queue}` on exchange `{exchange}`");
    channel
        .queue_bind(
            queue,
            exchange,
            "",
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|err| ConsumerInitializationError {
            err,
            kind: ConsumerInitializationErrorKind::Bind(exchange),
            queue,
        })?;
    trace!("creating consumer of queue `{queue}`");
    channel
        .basic_consume(
            queue,
            "",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|err| ConsumerInitializationError {
            err,
            kind: ConsumerInitializationErrorKind::Consumer,
            queue,
        })
}

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

#[inline]
async fn handle_delivery<
    F: Fn(T) -> R + Send + Sync + 'static,
    R: Future<Output = StdResult<(), ConsumerError>> + Send,
    T: DeserializeOwned,
>(
    delivery: Delivery,
    handle: &F,
) {
    match from_slice(&delivery.data) {
        Ok(payload) => match handle(payload).await {
            Ok(()) => {
                debug!("sending acknowledgement to broker");
                if let Err(err) = delivery.ack(BasicAckOptions::default()).await {
                    error!("sending acknowledgement to borker failed: {err}");
                }
            }
            Err(err) => {
                error!("{err}");
                send_nack(err.requeue, delivery).await;
            }
        },
        Err(err) => {
            error!("deserialization failed: {err}");
            send_nack(true, delivery).await;
        }
    }
}

#[inline]
async fn send_nack(requeue: bool, delivery: Delivery) {
    let opts = BasicNackOptions {
        requeue,
        ..Default::default()
    };
    if requeue {
        debug!("sending non-acknowledgement to broker because of previous error (delivery will be requeued)");
    } else {
        debug!("sending non-acknowledgement to broker because of previous error");
    }
    if let Err(err) = delivery.nack(opts).await {
        error!("sending non-acknowledgement to broker failed: {err}");
    }
}

#[inline]
async fn create_and_start_consumer<
    F: Fn(T) -> R + Send + Sync + 'static,
    R: Future<Output = StdResult<(), ConsumerError>> + Send,
    T: DeserializeOwned + Send,
>(
    queue: &'static str,
    channel: &Channel,
    exchange: &'static str,
    mut sig_rcv: Receiver<ConsumerSignal>,
    handle: F,
) -> StdResult<JoinHandle<()>, ConsumerInitializationError> {
    let mut csm = create_consumer(queue, exchange, channel).await?;
    let handle = Arc::new(handle);
    trace!("spawning consumer of queue `{queue}`");
    Ok(spawn({
        async move {
            debug!("consumer of queue `{queue}` started");
            let mut handles = JoinSet::new();
            loop {
                match sig_rcv.changed().now_or_never() {
                    Some(Ok(())) => {
                        let sig = *sig_rcv.borrow();
                        trace!("consumer of queue `{queue}` received {sig:?}");
                        if let ConsumerSignal::Stop = sig {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        error!(
                            "consumer of queue `{queue}` failed to listen consumer signal: {err}"
                        );
                    }
                    None => (),
                }
                if let Some(Some(delivery)) = csm.next().now_or_never() {
                    match delivery {
                        Ok(delivery) => {
                            trace!("spawning worker to handle {delivery:?}");
                            handles.spawn({
                                let handle = handle.clone();
                                async move {
                                    handle_delivery(delivery, handle.as_ref()).await;
                                }
                            });
                        }
                        Err(err) => {
                            error!("consumer of queue `{queue}` failed: {err}");
                        }
                    }
                }
            }
            debug!("waiting for workers stop");
            while let Some(res) = handles.join_next().await {
                if let Err(err) = res {
                    error!("waiting for worker stop failed: {err}");
                }
            }
            debug!("consumer of queue `{queue}` stopped");
        }
    }))
}
