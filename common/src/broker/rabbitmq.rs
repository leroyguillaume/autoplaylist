use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use lapin::{message::Delivery, options::BasicNackOptions, Channel, Connection, ExchangeKind};
use mockable::Env;
use thiserror::Error;
use tokio::{
    select, spawn,
    sync::watch::{self, Receiver, Sender},
    task::{JoinError, JoinHandle, JoinSet},
};
use tracing::{debug, debug_span, error, info, info_span, trace, warn, Instrument, Span};

use super::{
    BrokerClient, BrokerError, BrokerResult, Consumer, Message, MessageHandler, PlaylistMessage,
    Publisher, SourceMessage,
};

// Consts - Env var keys

pub const ENV_VAR_KEY_BROKER_URL: &str = "BROKER_URL";
pub const ENV_VAR_KEY_PLAYLIST_MSG_EXCH: &str = "BROKER_EXCHANGE_PLAYLIST_MESSAGE";
pub const ENV_VAR_KEY_SRC_MSG_EXCH: &str = "BROKER_EXCHANGE_SOURCE_MESSAGE";

// Consts - Defaults

pub const DEFAULT_BROKER_URL: &str = "amqp://localhost:5672/%2f";
pub const DEFAULT_PLAYLIST_MSG_EXCH: &str = "playlist";
pub const DEFAULT_SRC_MSG_EXCH: &str = "source";

// Types

pub type RabbitMqResult<T> = Result<T, RabbitMqError>;

// RabbitMqError

#[derive(Debug, Error)]
pub enum RabbitMqError {
    #[error("{0}")]
    Client(
        #[from]
        #[source]
        lapin::Error,
    ),
    #[error("JSON error: {0}")]
    Json(
        #[from]
        #[source]
        serde_json::Error,
    ),
}

// RabbitMqInitError

#[derive(Debug, Error)]
#[error("failed to initialize broker client: {0}")]
pub struct RabbitMqInitError(
    #[from]
    #[source]
    lapin::Error,
);

// RabbitMqConfig

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RabbitMqConfig {
    pub playlist_msg_exch: String,
    pub src_msg_exch: String,
    pub url: String,
}

impl RabbitMqConfig {
    pub fn from_env(env: &dyn Env) -> Self {
        debug!("loading RabbitMQ configuration");
        Self {
            playlist_msg_exch: env
                .string(ENV_VAR_KEY_PLAYLIST_MSG_EXCH)
                .unwrap_or_else(|| DEFAULT_PLAYLIST_MSG_EXCH.into()),
            src_msg_exch: env
                .string(ENV_VAR_KEY_SRC_MSG_EXCH)
                .unwrap_or_else(|| DEFAULT_SRC_MSG_EXCH.into()),
            url: env
                .string(ENV_VAR_KEY_BROKER_URL)
                .unwrap_or_else(|| DEFAULT_BROKER_URL.into()),
        }
    }
}

// RabbitMqClient

pub struct RabbitMqClient {
    conn: Connection,
    publisher: RabbitMqPublisher,
}

impl RabbitMqClient {
    pub async fn init(cfg: RabbitMqConfig) -> Result<Self, RabbitMqInitError> {
        debug!("opening connection");
        let conn = Connection::connect(&cfg.url, Default::default()).await?;
        trace!("opening channel");
        let channel = conn.create_channel().await?;
        Ok(Self {
            conn,
            publisher: RabbitMqPublisher { channel, cfg },
        })
    }

    #[inline]
    async fn consume<M: Message + 'static, H: MessageHandler<M> + 'static>(
        queue: String,
        exch: String,
        mut csm: lapin::Consumer,
        mut stop_rx: Receiver<()>,
        handler: H,
    ) {
        let span = info_span!("consume", csm.exch = exch, csm.queue = queue);
        let root_span = span.clone();
        async {
            let mut tasks = JoinSet::new();
            let handler = Arc::new(handler);
            loop {
                select! {
                    dly = csm.next() => {
                        match dly {
                            Some(Ok(dly)) => {
                                Self::handle_delivery(
                                    dly,
                                    &mut tasks,
                                    stop_rx.clone(),
                                    handler.clone(),
                                    root_span.clone(),
                                ).await;
                            }
                            Some(Err(err)) => {
                                error!(
                                    details = %err,
                                    "failed to receive delivery"
                                );
                            }
                            None => {
                                warn!("channel closed");
                                break;
                            }
                        }
                    }
                    _ = stop_rx.changed() => {
                        break;
                    }
                }
            }
            trace!("waiting for jobs to finish");
            while let Some(res) = tasks.join_next().await {
                if let Err(err) = res {
                    error!(
                        csm.exch = exch,
                        csm.queue = queue,
                        details = %err,
                        "failed to wait for job to finish"
                    );
                }
            }
            info!("consumer stopped");
        }
        .instrument(span)
        .await
    }

    #[inline]
    async fn handle_delivery<M: Message + 'static, H: MessageHandler<M> + 'static>(
        dly: Delivery,
        tasks: &mut JoinSet<()>,
        stop_rx: Receiver<()>,
        handler: Arc<H>,
        root_span: Span,
    ) {
        match serde_json::from_slice::<M>(&dly.data) {
            Ok(msg) => {
                tasks.spawn(async move {
                    let span =
                        info_span!(parent: root_span, "handle_message", msg.id = %msg.id(), msg.kind = %msg.kind());
                    async {
                        match handler.handle(msg, stop_rx).await {
                            Ok(()) => {
                                debug!("acknowledging message");
                                if let Err(err) = dly.ack(Default::default()).await {
                                    error!(
                                        details = %err,
                                        "failed to acknowledge message"
                                    );
                                }
                            }
                            Err(err) => {
                                error!(
                                    details = %err,
                                    "failed to handle message",
                                );
                                Self::nack_delivery(dly).await;
                            }
                        }
                    }
                    .instrument(span)
                    .await
                });
            }
            Err(err) => {
                error!(
                    details = %err,
                    "failed to deserialize message"
                );
                Self::nack_delivery(dly).await;
            }
        }
    }

    #[inline]
    async fn nack_delivery(dly: Delivery) {
        debug!("non-acknowledging message");
        let opts = BasicNackOptions {
            requeue: true,
            ..Default::default()
        };
        if let Err(err) = dly.nack(opts).await {
            error!(
                details = %err,
                "failed to non-acknowledge message"
            );
        }
    }

    #[inline]
    async fn start_consumer<M: Message + 'static, H: MessageHandler<M> + 'static>(
        &self,
        queue: &str,
        exch: &str,
        handler: H,
    ) -> RabbitMqResult<RabbitMqConsumer> {
        let span = debug_span!("start_consumer", csm.exch = exch, csm.queue = queue);
        async {
            debug!("opening channel");
            let channel = self.conn.create_channel().await?;
            debug!("declaring queue");
            channel
                .queue_declare(queue, Default::default(), Default::default())
                .await?;
            debug!("declaring exchange");
            channel
                .exchange_declare(
                    exch,
                    ExchangeKind::Fanout,
                    Default::default(),
                    Default::default(),
                )
                .await?;
            debug!("binding queue to exchange");
            channel
                .queue_bind(queue, exch, "", Default::default(), Default::default())
                .await?;
            debug!("creating consumer");
            let csm = channel
                .basic_consume(queue, "", Default::default(), Default::default())
                .await?;
            let (stop_tx, stop_rx) = watch::channel(());
            let task = spawn(Self::consume(
                queue.into(),
                exch.into(),
                csm,
                stop_rx,
                handler,
            ));
            info!("consumer started");
            Ok(RabbitMqConsumer { stop_tx, task })
        }
        .instrument(span)
        .await
    }
}

#[async_trait]
impl BrokerClient<RabbitMqConsumer> for RabbitMqClient {
    fn publisher(&self) -> &dyn Publisher {
        &self.publisher
    }

    async fn start_playlist_message_consumer(
        &self,
        queue: &str,
        handle: impl MessageHandler<PlaylistMessage> + 'static,
    ) -> BrokerResult<RabbitMqConsumer> {
        let csm = self
            .start_consumer(queue, &self.publisher.cfg.playlist_msg_exch, handle)
            .await?;
        Ok(csm)
    }

    async fn start_source_message_consumer(
        &self,
        queue: &str,
        handle: impl MessageHandler<SourceMessage> + 'static,
    ) -> BrokerResult<RabbitMqConsumer> {
        let csm = self
            .start_consumer(queue, &self.publisher.cfg.src_msg_exch, handle)
            .await?;
        Ok(csm)
    }
}

// RabbitMqConsumer

pub struct RabbitMqConsumer {
    stop_tx: Sender<()>,
    task: JoinHandle<()>,
}

#[async_trait]
impl Consumer for RabbitMqConsumer {
    async fn stop(self) -> Result<(), JoinError> {
        debug!("stopping consumer");
        self.stop_tx.send(()).ok();
        trace!("waiting for consumer to stop");
        self.task.await
    }
}

// RabbitMqPublisher

pub struct RabbitMqPublisher {
    channel: Channel,
    cfg: RabbitMqConfig,
}

impl RabbitMqPublisher {
    #[inline]
    async fn publish_message<M: Message>(&self, msg: &M, exch: &str) -> RabbitMqResult<()> {
        let span = debug_span!("publish_message", csm.exch = exch);
        async {
            trace!("serializing message");
            let payload = serde_json::to_vec(msg)?;
            debug!("publishing message");
            self.channel
                .basic_publish(exch, "", Default::default(), &payload, Default::default())
                .await?;
            Ok(())
        }
        .instrument(span)
        .await
    }
}

#[async_trait]
impl Publisher for RabbitMqPublisher {
    async fn publish_playlist_message(&self, msg: &PlaylistMessage) -> BrokerResult<()> {
        self.publish_message(msg, &self.cfg.playlist_msg_exch)
            .await?;
        Ok(())
    }

    async fn publish_source_message(&self, msg: &SourceMessage) -> BrokerResult<()> {
        self.publish_message(msg, &self.cfg.src_msg_exch).await?;
        Ok(())
    }
}

// BrokerError

impl From<RabbitMqError> for BrokerError {
    fn from(err: RabbitMqError) -> Self {
        Self(Box::new(err))
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::{
        io::stderr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use anyhow::anyhow;
    use mockable::{DefaultEnv, MockEnv};
    use mockall::predicate::eq;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    use crate::{
        broker::{PlaylistMessageKind, SourceMessageKind},
        test_env_var, TracingConfig,
    };

    use super::*;

    // TestHandler

    struct TestHandler<MSG: Message> {
        msg_tx: mpsc::Sender<MSG>,
        times: AtomicUsize,
    }

    impl<MSG: Message> TestHandler<MSG> {
        fn new(msg_tx: mpsc::Sender<MSG>) -> Self {
            Self {
                msg_tx,
                times: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl<MSG: Message> MessageHandler<MSG> for TestHandler<MSG> {
        async fn handle(&self, msg: MSG, _: Receiver<()>) -> anyhow::Result<()> {
            let times = self.times.fetch_add(1, Ordering::Relaxed);
            if times == 0 {
                Err(anyhow!("error"))
            } else {
                self.msg_tx.send(msg).await.ok();
                Ok(())
            }
        }
    }

    // Mods

    mod rabbitmq_config {
        use super::*;

        mod from_env {
            use super::*;

            // Params

            #[derive(Default)]
            struct Params {
                playlist_msg_exch: Option<String>,
                src_msg_exch: Option<String>,
                url: Option<String>,
            }

            // mock_optional_string

            fn mock_optional_string(key: &'static str, val: Option<String>, mock: &mut MockEnv) {
                mock.expect_string()
                    .with(eq(key))
                    .times(1)
                    .return_const(val);
            }

            // run

            fn run(params: Params, expected: RabbitMqConfig) {
                let mut env = MockEnv::new();
                mock_optional_string(
                    ENV_VAR_KEY_PLAYLIST_MSG_EXCH,
                    params.playlist_msg_exch,
                    &mut env,
                );
                mock_optional_string(ENV_VAR_KEY_SRC_MSG_EXCH, params.src_msg_exch, &mut env);
                mock_optional_string(ENV_VAR_KEY_BROKER_URL, params.url, &mut env);
                let cfg = RabbitMqConfig::from_env(&env);
                assert_eq!(cfg, expected);
            }

            // Tests

            #[test]
            fn default() {
                let expected = RabbitMqConfig {
                    playlist_msg_exch: DEFAULT_PLAYLIST_MSG_EXCH.into(),
                    src_msg_exch: DEFAULT_SRC_MSG_EXCH.into(),
                    url: DEFAULT_BROKER_URL.into(),
                };
                let params = Params::default();
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = RabbitMqConfig {
                    playlist_msg_exch: "playlist_msg_exch".into(),
                    src_msg_exch: "src_msg_exch".into(),
                    url: "url".into(),
                };
                let params = Params {
                    playlist_msg_exch: Some(expected.playlist_msg_exch.clone()),
                    src_msg_exch: Some(expected.src_msg_exch.clone()),
                    url: Some(expected.url.clone()),
                };
                run(params, expected);
            }
        }
    }

    mod rabbitmq_client {
        use super::*;

        // Mods

        mod playlist_message {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                TracingConfig::new("autoplaylist-common", stderr).init(&DefaultEnv);
                let expected = PlaylistMessage {
                    id: Uuid::new_v4(),
                    kind: PlaylistMessageKind::Created,
                };
                let suffix = format!("_{}", Uuid::new_v4());
                let queue = format!("test{suffix}");
                let cfg = RabbitMqConfig {
                    playlist_msg_exch: format!("{DEFAULT_PLAYLIST_MSG_EXCH}{suffix}"),
                    src_msg_exch: format!("{DEFAULT_SRC_MSG_EXCH}{suffix}"),
                    url: test_env_var(ENV_VAR_KEY_BROKER_URL, DEFAULT_BROKER_URL),
                };
                let client = RabbitMqClient::init(cfg)
                    .await
                    .expect("failed to initialize RabbitMQ client");
                let (msg_tx, mut msg_rx) = mpsc::channel(1);
                let handler = TestHandler::new(msg_tx);
                let csm = client
                    .start_playlist_message_consumer(&queue, handler)
                    .await
                    .expect("failed to start consumer");
                client
                    .publisher()
                    .publish_playlist_message(&expected)
                    .await
                    .expect("failed to publish message");
                let msg = msg_rx.recv().await.expect("failed to receive message");
                csm.stop().await.expect("failed to stop consumer");
                assert_eq!(msg, expected);
            }
        }

        mod source_message {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                TracingConfig::new("autoplaylist-common", stderr).init(&DefaultEnv);
                let expected = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Created,
                };
                let suffix = format!("_{}", Uuid::new_v4());
                let queue = format!("test{suffix}");
                let cfg = RabbitMqConfig {
                    playlist_msg_exch: format!("{DEFAULT_PLAYLIST_MSG_EXCH}{suffix}"),
                    src_msg_exch: format!("{DEFAULT_SRC_MSG_EXCH}{suffix}"),
                    url: test_env_var(ENV_VAR_KEY_BROKER_URL, DEFAULT_BROKER_URL),
                };
                let client = RabbitMqClient::init(cfg)
                    .await
                    .expect("failed to initialize RabbitMQ client");
                let (msg_tx, mut msg_rx) = mpsc::channel(1);
                let handler = TestHandler::new(msg_tx);
                let csm = client
                    .start_source_message_consumer(&queue, handler)
                    .await
                    .expect("failed to start consumer");
                client
                    .publisher()
                    .publish_source_message(&expected)
                    .await
                    .expect("failed to publish message");
                let msg = msg_rx.recv().await.expect("failed to receive message");
                csm.stop().await.expect("failed to stop consumer");
                assert_eq!(msg, expected);
            }
        }
    }
}
