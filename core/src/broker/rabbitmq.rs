use std::{
    error::Error as StdError,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    sync::Arc,
};

use async_trait::async_trait;
use futures::StreamExt;
use lapin::{
    message::Delivery,
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
        ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
    },
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, Consumer as LapinConsumer,
    Error as LapinError, ExchangeKind,
};
use securefmt::Debug as SecureDebug;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_slice, to_string};
use tokio::{
    select, spawn,
    sync::watch::Receiver,
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, error, trace};

use crate::{env_var, env_var_or_default, ConfigError};

use super::{BaseCommand, BaseEvent, Broker, Consumer, ConsumerHandler, Producer, ProducerError};

// InitializationErrorKind

#[derive(Debug)]
pub enum BrokerInitializationErrorKind {
    ChannelCreation,
    Connection,
    ExchangeDeclaration(String),
}

// BrokerInitializationError

#[derive(Debug)]
pub struct BrokerInitializationError {
    err: LapinError,
    kind: BrokerInitializationErrorKind,
}

impl BrokerInitializationError {
    fn channel_creation(err: LapinError) -> Self {
        Self {
            err,
            kind: BrokerInitializationErrorKind::ChannelCreation,
        }
    }

    fn connection(err: LapinError) -> Self {
        Self {
            err,
            kind: BrokerInitializationErrorKind::Connection,
        }
    }

    fn exchange_declaration(err: LapinError, exchange: String) -> Self {
        Self {
            err,
            kind: BrokerInitializationErrorKind::ExchangeDeclaration(exchange),
        }
    }
}

impl Display for BrokerInitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.kind {
            BrokerInitializationErrorKind::ChannelCreation => {
                write!(f, "RabbitMQ channel creation failed: {}", self.err)
            }
            BrokerInitializationErrorKind::Connection => {
                write!(f, "RabbitMQ connection failed: {}", self.err)
            }
            BrokerInitializationErrorKind::ExchangeDeclaration(exchange) => write!(
                f,
                "RabbitMQ exchange `{exchange}` declaration failed: {}",
                self.err
            ),
        }
    }
}

impl StdError for BrokerInitializationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.err)
    }
}

// ConsumerInitializationErrorKind

#[derive(Debug)]
pub enum ConsumerInitializationErrorKind {
    ConsumerCreation,
    QueueBinding(String),
    QueueDeclaration,
}

// ConsumerInitializationError

#[derive(Debug)]
pub struct ConsumerInitializationError {
    err: LapinError,
    kind: ConsumerInitializationErrorKind,
    queue: String,
}

impl ConsumerInitializationError {
    fn consumer_creation_boxed(err: LapinError, queue: String) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self {
            err,
            kind: ConsumerInitializationErrorKind::ConsumerCreation,
            queue,
        })
    }

    fn queue_binding_boxed(
        err: LapinError,
        queue: String,
        exchange: String,
    ) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self {
            err,
            kind: ConsumerInitializationErrorKind::QueueBinding(exchange),
            queue,
        })
    }

    fn queue_declaration_boxed(err: LapinError, queue: String) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self {
            err,
            kind: ConsumerInitializationErrorKind::QueueDeclaration,
            queue,
        })
    }
}

impl Display for ConsumerInitializationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.kind {
            ConsumerInitializationErrorKind::ConsumerCreation => write!(
                f,
                "consumer of queue `{}` creation failed: {}",
                self.queue, self.err
            ),
            ConsumerInitializationErrorKind::QueueBinding(exchange) => write!(
                f,
                "binding queue `{}` on exchange `{exchange}` failed: {}",
                self.queue, self.err
            ),
            ConsumerInitializationErrorKind::QueueDeclaration => write!(
                f,
                "RabbitMQ queue `{}` declaration failed: {}",
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

// ProducerError

impl ProducerError {
    fn broker_client_boxed(err: LapinError) -> Self {
        Self::BrokerClient(Box::new(err))
    }
}

// RabbitMqConsumer

pub struct RabbitMqConsumer<T: Debug + DeserializeOwned + Send + Sync + 'static> {
    join_handle: JoinHandle<()>,
    _phantom: PhantomData<T>,
}

impl<T: Debug + DeserializeOwned + Send + Sync + 'static> RabbitMqConsumer<T> {
    fn start(
        queue: String,
        mut consumer: LapinConsumer,
        mut stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<T>>,
    ) -> Self {
        let csm_join_handle = spawn(async move {
            let mut handler_join_set = JoinSet::new();
            let handler = Arc::new(handler);
            loop {
                select! {
                    res = consumer.next() => match res {
                        Some(Ok(delivery)) => {
                            let handler = handler.clone();
                            handler_join_set.spawn(async move { Self::handle(delivery, handler).await });
                        }
                        Some(Err(err)) => {
                            error!("consumer of queue `{queue}` failed: {err}");
                        }
                        None => {
                            debug!("stream on queue `{queue}` closed");
                            break;
                        }
                    },
                    _ = stop_rx.changed() => {
                        debug!("consumer of queue `{queue}` received stop signal");
                        break;
                    },
                }
            }
            debug!("waiting for handlers abort");
            while let Some(res) = handler_join_set.join_next().await {
                if let Err(err) = res {
                    error!("waiting for handler abort failed: {err}");
                }
            }
        });
        Self {
            join_handle: csm_join_handle,
            _phantom: PhantomData::default(),
        }
    }

    #[inline]
    async fn handle(delivery: Delivery, handler: Arc<Box<dyn ConsumerHandler<T>>>) {
        trace!("handling {delivery:?}");
        match from_slice::<T>(&delivery.data) {
            Ok(val) => {
                debug!("handling {val:?}");
                match handler.handle(val).await {
                    Ok(()) => Self::send_ack(delivery).await,
                    Err(err) => Self::send_nack(err.requeue, delivery).await,
                }
            }
            Err(err) => {
                error!("deserialization of delivery payload failed: {err}");
                Self::send_nack(false, delivery).await;
            }
        }
    }

    #[inline]
    async fn send_ack(delivery: Delivery) {
        debug!("sending acknowledgement to RabbitMQ");
        let res = delivery.ack(BasicAckOptions::default()).await;
        if let Err(err) = res {
            error!("sending acknowledgement to RabbitMQ failed: {err}");
        }
    }

    #[inline]
    async fn send_nack(requeue: bool, delivery: Delivery) {
        let opts = BasicNackOptions {
            requeue,
            ..Default::default()
        };
        if requeue {
            debug!("sending non-acknowledgement to RabbitMQ because of previous error (delivery will be requeued)");
        } else {
            debug!("sending non-acknowledgement to RabbitMQ because of previous error");
        }
        if let Err(err) = delivery.nack(opts).await {
            error!("sending non-acknowledgement to RabbitMQ failed: {err}");
        }
    }
}

#[async_trait]
impl<T: Debug + DeserializeOwned + Send + Sync + 'static> Consumer<T> for RabbitMqConsumer<T> {
    async fn wait_for_shutdown(self: Box<Self>) {
        if let Err(err) = self.join_handle.await {
            error!("waiting for consumer shutdown failed: {err}");
        }
    }
}

// RabbitMqProducer

pub struct RabbitMqProducer<T: Serialize + Send + Sync + 'static> {
    channel: Channel,
    exchange: String,
    _phantom: PhantomData<T>,
}

impl<T: Debug + Serialize + Send + Sync + 'static> RabbitMqProducer<T> {
    fn new(channel: Channel, exchange: String) -> Self {
        Self {
            channel,
            exchange,
            _phantom: PhantomData::default(),
        }
    }
}

#[async_trait]
impl<T: Debug + Serialize + Send + Sync + 'static> Producer<T> for RabbitMqProducer<T> {
    async fn produce(&self, payload: &T) -> Result<(), ProducerError> {
        trace!("serializing {payload:?} into JSON");
        let payload = to_string(payload).map_err(ProducerError::Serialization)?;
        debug!("sending {payload:?} to RabbitMQ");
        self.channel
            .basic_publish(
                &self.exchange,
                "",
                BasicPublishOptions::default(),
                payload.as_bytes(),
                BasicProperties::default(),
            )
            .await
            .map_err(ProducerError::broker_client_boxed)?;
        Ok(())
    }
}

// Config

#[derive(SecureDebug, Clone)]
pub struct Config {
    pub base_cmd_exchange: String,
    pub base_event_exchange: String,
    #[sensitive]
    pub url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        trace!("loading RabbitMQ configuration");
        let cfg = Self {
            base_cmd_exchange: env_var_or_default("BASE_COMMAND_EXCHANGE", || {
                "base-command".into()
            })?,
            base_event_exchange: env_var_or_default("BASE_EVENT_EXCHANGE", || "base-event".into())?,
            url: env_var("BROKER_URL")?,
        };
        trace!("RabbitMQ configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// RabbitMqBroker

pub struct RabbitMqBroker {
    cfg: Config,
    channel: Channel,
}

impl RabbitMqBroker {
    pub async fn init(cfg: Config) -> Result<Self, BrokerInitializationError> {
        debug!("opening RabbitMQ connection");
        let conn = Connection::connect(&cfg.url, ConnectionProperties::default())
            .await
            .map_err(BrokerInitializationError::connection)?;
        debug!("opening RabbitMQ channel");
        let channel = conn
            .create_channel()
            .await
            .map_err(BrokerInitializationError::channel_creation)?;
        Self::declare_exchange(&channel, &cfg.base_cmd_exchange).await?;
        Self::declare_exchange(&channel, &cfg.base_event_exchange).await?;
        Ok(Self { cfg, channel })
    }

    #[inline]
    async fn declare_exchange(
        channel: &Channel,
        exchange: &str,
    ) -> Result<(), BrokerInitializationError> {
        debug!("declaring RabbitMQ exchange `{exchange}`");
        channel
            .exchange_declare(
                exchange,
                ExchangeKind::Fanout,
                ExchangeDeclareOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|err| BrokerInitializationError::exchange_declaration(err, exchange.into()))?;
        Ok(())
    }

    #[inline]
    async fn start_consumer<T: Debug + DeserializeOwned + Send + Sync + 'static>(
        queue: String,
        exchange: &str,
        channel: &Channel,
        stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<T>>,
    ) -> Result<Box<dyn Consumer<T>>, Box<dyn StdError + Send + Sync>> {
        debug!("declaring RabbitMQ queue `{queue}`");
        channel
            .queue_declare(
                &queue,
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|err| {
                ConsumerInitializationError::queue_declaration_boxed(err, queue.clone())
            })?;
        trace!("binding RabbitMQ queue `{queue}` on exchange `{exchange}`");
        channel
            .queue_bind(
                &queue,
                exchange,
                "",
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|err| {
                ConsumerInitializationError::queue_binding_boxed(
                    err,
                    queue.clone(),
                    exchange.into(),
                )
            })?;
        trace!("creating consumer of queue `{queue}`");
        let consumer = channel
            .basic_consume(
                &queue,
                "",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|err| {
                ConsumerInitializationError::consumer_creation_boxed(err, queue.clone())
            })?;
        Ok(Box::new(RabbitMqConsumer::start(
            queue, consumer, stop_rx, handler,
        )))
    }
}

#[async_trait]
impl Broker for RabbitMqBroker {
    fn base_command_producer(&self) -> Box<dyn Producer<BaseCommand>> {
        Box::new(RabbitMqProducer::new(
            self.channel.clone(),
            self.cfg.base_cmd_exchange.clone(),
        ))
    }

    fn base_event_producer(&self) -> Box<dyn Producer<BaseEvent>> {
        Box::new(RabbitMqProducer::new(
            self.channel.clone(),
            self.cfg.base_event_exchange.clone(),
        ))
    }

    async fn start_base_command_consumer(
        &self,
        queue: String,
        stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<BaseCommand>>,
    ) -> Result<Box<dyn Consumer<BaseCommand>>, Box<dyn StdError + Send + Sync>> {
        Self::start_consumer(
            queue,
            &self.cfg.base_cmd_exchange,
            &self.channel,
            stop_rx,
            handler,
        )
        .await
    }

    async fn start_base_event_consumer(
        &self,
        queue: String,
        stop_rx: Receiver<()>,
        handler: Box<dyn ConsumerHandler<BaseEvent>>,
    ) -> Result<Box<dyn Consumer<BaseEvent>>, Box<dyn StdError + Send + Sync>> {
        Self::start_consumer(
            queue,
            &self.cfg.base_event_exchange,
            &self.channel,
            stop_rx,
            handler,
        )
        .await
    }
}
