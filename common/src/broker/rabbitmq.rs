use std::{num::ParseIntError, sync::Arc};

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
    SourceMessage,
};

// Consts - Env var keys

pub const ENV_VAR_KEY_BROKER_HOST: &str = "BROKER_HOST";
pub const ENV_VAR_KEY_BROKER_PASSWORD: &str = "BROKER_PASSWORD";
pub const ENV_VAR_KEY_BROKER_PORT: &str = "BROKER_PORT";
pub const ENV_VAR_KEY_BROKER_USER: &str = "BROKER_USER";
pub const ENV_VAR_KEY_BROKER_VHOST: &str = "BROKER_VHOST";
pub const ENV_VAR_KEY_PLAYLIST_MSG_EXCH: &str = "BROKER_EXCHANGE_PLAYLIST_MESSAGE";
pub const ENV_VAR_KEY_SRC_MSG_EXCH: &str = "BROKER_EXCHANGE_SOURCE_MESSAGE";

// Consts - Defaults

pub const DEFAULT_BROKER_HOST: &str = "localhost";
pub const DEFAULT_BROKER_PASSWORD: &str = "guest";
pub const DEFAULT_BROKER_PORT: u16 = 5672;
pub const DEFAULT_BROKER_USER: &str = "guest";
pub const DEFAULT_BROKER_VHOST: &str = "%2f";
pub const DEFAULT_PLAYLIST_MSG_EXCH: &str = "playlist";
pub const DEFAULT_SRC_MSG_EXCH: &str = "source";

// Types

pub type RabbitMqResult<T> = Result<T, RabbitMqError>;

// RabbitMqConfigError

#[derive(Debug, Error)]
#[error("invalid broker port: {0}")]
pub struct RabbitMqConfigError(
    #[from]
    #[source]
    ParseIntError,
);

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
    pub host: String,
    pub password: String,
    pub playlist_msg_exch: String,
    pub port: u16,
    pub src_msg_exch: String,
    pub user: String,
    pub vhost: String,
}

impl RabbitMqConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, RabbitMqConfigError> {
        debug!("loading RabbitMQ configuration");
        let cfg = Self {
            host: env
                .string(ENV_VAR_KEY_BROKER_HOST)
                .unwrap_or_else(|| DEFAULT_BROKER_HOST.into()),
            password: env
                .string(ENV_VAR_KEY_BROKER_PASSWORD)
                .unwrap_or_else(|| DEFAULT_BROKER_PASSWORD.into()),
            playlist_msg_exch: env
                .string(ENV_VAR_KEY_PLAYLIST_MSG_EXCH)
                .unwrap_or_else(|| DEFAULT_PLAYLIST_MSG_EXCH.into()),
            port: env
                .u16(ENV_VAR_KEY_BROKER_PORT)
                .unwrap_or(Ok(DEFAULT_BROKER_PORT))?,
            src_msg_exch: env
                .string(ENV_VAR_KEY_SRC_MSG_EXCH)
                .unwrap_or_else(|| DEFAULT_SRC_MSG_EXCH.into()),
            user: env
                .string(ENV_VAR_KEY_BROKER_USER)
                .unwrap_or_else(|| DEFAULT_BROKER_USER.into()),
            vhost: env
                .string(ENV_VAR_KEY_BROKER_VHOST)
                .unwrap_or_else(|| DEFAULT_BROKER_VHOST.into()),
        };
        debug!(
            rabbitmq.cfg.host = cfg.host,
            rabbitmq.cfg.port = cfg.port,
            rabbitmq.cfg.playlist_msg_exch = cfg.playlist_msg_exch,
            rabbitmq.cfg.src_msg_exch = cfg.src_msg_exch,
            rabbitmq.cfg.user = cfg.user,
            rabbitmq.cfg.vhost = cfg.vhost,
            "RabbitMQ configuration loaded"
        );
        Ok(cfg)
    }
}

// RabbitMqClient

pub struct RabbitMqClient {
    cfg: RabbitMqConfig,
    channel: Channel,
    conn: Connection,
}

impl RabbitMqClient {
    pub async fn init(cfg: RabbitMqConfig) -> Result<Self, RabbitMqInitError> {
        debug!("opening connection");
        let url = format!(
            "amqp://{}:{}@{}:{}/{}",
            cfg.user, cfg.password, cfg.host, cfg.port, cfg.vhost,
        );
        let conn = Connection::connect(&url, Default::default()).await?;
        trace!("opening channel");
        let channel = conn.create_channel().await?;
        let exchs = [&cfg.playlist_msg_exch, &cfg.src_msg_exch];
        for exch in &exchs {
            debug!(exch, "declaring exchange");
            channel
                .exchange_declare(
                    exch,
                    ExchangeKind::Fanout,
                    Default::default(),
                    Default::default(),
                )
                .await?;
        }
        Ok(Self { cfg, channel, conn })
    }

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
impl BrokerClient for RabbitMqClient {
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

// RabbitMqConsumer

pub struct RabbitMqConsumer {
    stop_tx: Sender<()>,
    task: JoinHandle<()>,
}

impl RabbitMqConsumer {
    pub async fn start_playlist_message_consumer<H: MessageHandler<PlaylistMessage> + 'static>(
        queue: &str,
        client: &RabbitMqClient,
        handler: H,
    ) -> RabbitMqResult<Self> {
        Self::start(queue, &client.cfg.playlist_msg_exch, client, handler).await
    }

    pub async fn start_source_message_consumer<H: MessageHandler<SourceMessage> + 'static>(
        queue: &str,
        client: &RabbitMqClient,
        handler: H,
    ) -> RabbitMqResult<Self> {
        Self::start(queue, &client.cfg.src_msg_exch, client, handler).await
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
    async fn start<MSG: Message + 'static, HANDLER: MessageHandler<MSG> + 'static>(
        queue: &str,
        exch: &str,
        client: &RabbitMqClient,
        handler: HANDLER,
    ) -> RabbitMqResult<Self> {
        let span = info_span!("start", csm.exch = exch, csm.queue = queue);
        async {
            debug!("opening channel");
            let channel = client.conn.create_channel().await?;
            debug!("declaring queue");
            channel
                .queue_declare(queue, Default::default(), Default::default())
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
impl Consumer for RabbitMqConsumer {
    async fn stop(self) -> Result<(), JoinError> {
        debug!("stopping consumer");
        self.stop_tx.send(()).ok();
        trace!("waiting for consumer to stop");
        self.task.await
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

    // test_broker_config

    fn test_broker_config() -> RabbitMqConfig {
        RabbitMqConfig {
            host: test_env_var(ENV_VAR_KEY_BROKER_HOST, || DEFAULT_BROKER_HOST.into()),
            password: test_env_var(ENV_VAR_KEY_BROKER_PASSWORD, || {
                DEFAULT_BROKER_PASSWORD.into()
            }),
            playlist_msg_exch: "playlist".into(),
            port: test_env_var(ENV_VAR_KEY_BROKER_PORT, || DEFAULT_BROKER_PORT),
            src_msg_exch: "source".into(),
            user: test_env_var(ENV_VAR_KEY_BROKER_USER, || DEFAULT_BROKER_USER.into()),
            vhost: test_env_var(ENV_VAR_KEY_BROKER_VHOST, || DEFAULT_BROKER_VHOST.into()),
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
                host: Option<String>,
                password: Option<String>,
                playlist_msg_exch: Option<String>,
                port: Option<u16>,
                src_msg_exch: Option<String>,
                user: Option<String>,
                vhost: Option<String>,
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
                mock_optional_string(ENV_VAR_KEY_BROKER_HOST, params.host, &mut env);
                mock_optional_string(ENV_VAR_KEY_BROKER_PASSWORD, params.password, &mut env);
                mock_optional_string(ENV_VAR_KEY_BROKER_USER, params.user, &mut env);
                mock_optional_string(ENV_VAR_KEY_BROKER_VHOST, params.vhost, &mut env);
                env.expect_u16()
                    .with(eq(ENV_VAR_KEY_BROKER_PORT))
                    .times(1)
                    .returning(move |_| params.port.map(Ok));
                mock_optional_string(
                    ENV_VAR_KEY_PLAYLIST_MSG_EXCH,
                    params.playlist_msg_exch,
                    &mut env,
                );
                mock_optional_string(ENV_VAR_KEY_SRC_MSG_EXCH, params.src_msg_exch, &mut env);
                let cfg = RabbitMqConfig::from_env(&env).expect("failed to load configuration");
                assert_eq!(cfg, expected);
            }

            // Tests

            #[test]
            fn default() {
                let expected = RabbitMqConfig {
                    host: DEFAULT_BROKER_HOST.into(),
                    password: DEFAULT_BROKER_PASSWORD.into(),
                    playlist_msg_exch: DEFAULT_PLAYLIST_MSG_EXCH.into(),
                    port: DEFAULT_BROKER_PORT,
                    src_msg_exch: DEFAULT_SRC_MSG_EXCH.into(),
                    user: DEFAULT_BROKER_USER.into(),
                    vhost: DEFAULT_BROKER_VHOST.into(),
                };
                let params = Params::default();
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = RabbitMqConfig {
                    host: "host".into(),
                    password: "password".into(),
                    playlist_msg_exch: "playlist_msg_exch".into(),
                    port: 1234,
                    src_msg_exch: "src_msg_exch".into(),
                    user: "user".into(),
                    vhost: "vhost".into(),
                };
                let params = Params {
                    host: Some(expected.host.clone()),
                    password: Some(expected.password.clone()),
                    playlist_msg_exch: Some(expected.playlist_msg_exch.clone()),
                    port: Some(expected.port),
                    src_msg_exch: Some(expected.src_msg_exch.clone()),
                    user: Some(expected.user.clone()),
                    vhost: Some(expected.vhost.clone()),
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
                let client = RabbitMqClient::init(test_broker_config())
                    .await
                    .expect("failed to initialize RabbitMQ client");
                let (msg_tx, mut msg_rx) = mpsc::channel(1);
                let handler = TestHandler::new(msg_tx);
                let csm =
                    RabbitMqConsumer::start_playlist_message_consumer(&queue, &client, handler)
                        .await
                        .expect("failed to start consumer");
                client
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
                let client = RabbitMqClient::init(test_broker_config())
                    .await
                    .expect("failed to initialize RabbitMQ client");
                let (msg_tx, mut msg_rx) = mpsc::channel(1);
                let handler = TestHandler::new(msg_tx);
                let csm = RabbitMqConsumer::start_source_message_consumer(&queue, &client, handler)
                    .await
                    .expect("failed to start consumer");
                client
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
