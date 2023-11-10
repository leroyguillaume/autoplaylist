use std::fmt::Display;

use async_trait::async_trait;
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{sync::watch::Receiver, task::JoinError};
use uuid::Uuid;

// Types

pub type BrokerResult<T> = Result<T, BrokerError>;

// BrokerError

#[derive(Debug, Error)]
#[error("{0}")]
pub struct BrokerError(Box<dyn std::error::Error + Send + Sync>);

// Message

pub trait Message: for<'a> Deserialize<'a> + Send + Serialize + Sync {
    fn id(&self) -> Uuid;

    fn kind(&self) -> &dyn Display;
}

// PlaylistMessage

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistMessage {
    pub id: Uuid,
    pub kind: PlaylistMessageKind,
}

impl Message for PlaylistMessage {
    fn id(&self) -> Uuid {
        self.id
    }

    fn kind(&self) -> &dyn Display {
        &self.kind
    }
}

// PlaylistMessageKind

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
pub enum PlaylistMessageKind {
    Created,
    Sync,
}

// SourceMessage

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceMessage {
    pub id: Uuid,
    pub kind: SourceMessageKind,
}

impl Message for SourceMessage {
    fn id(&self) -> Uuid {
        self.id
    }

    fn kind(&self) -> &dyn Display {
        &self.kind
    }
}

// SourceMessageKind

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
pub enum SourceMessageKind {
    Created,
    Sync,
}

// BrokerClient

#[async_trait]
pub trait BrokerClient<CSM: Consumer>: Send + Sync {
    fn publisher(&self) -> &dyn Publisher;

    async fn start_playlist_message_consumer(
        &self,
        queue: &str,
        handler: impl MessageHandler<PlaylistMessage> + 'static,
    ) -> BrokerResult<CSM>;

    async fn start_source_message_consumer(
        &self,
        queue: &str,
        handler: impl MessageHandler<SourceMessage> + 'static,
    ) -> BrokerResult<CSM>;
}

// Consumer

#[cfg_attr(any(test, feature = "test"), mockall::automock)]
#[async_trait]
pub trait Consumer: Send + Sync {
    async fn stop(self) -> Result<(), JoinError>;
}

// MessageHandler

#[async_trait]
pub trait MessageHandler<MSG: Message>: Send + Sync {
    async fn handle(&self, msg: MSG, stop_rx: Receiver<()>) -> anyhow::Result<()>;
}

// Publisher

#[cfg_attr(any(test, feature = "test"), mockall::automock)]
#[async_trait]
pub trait Publisher: Send + Sync {
    async fn publish_playlist_message(&self, msg: &PlaylistMessage) -> BrokerResult<()>;

    async fn publish_source_message(&self, msg: &SourceMessage) -> BrokerResult<()>;
}

// MockBrokerClient

#[cfg(any(test, feature = "test"))]
#[derive(Default)]
pub struct MockBrokerClient {
    pub publisher: MockPublisher,
    pub start_playlist_message_consumer: mockable::Mock<MockConsumer, String>,
    pub start_src_message_consumer: mockable::Mock<MockConsumer, String>,
}

#[async_trait]
#[cfg(any(test, feature = "test"))]
impl BrokerClient<MockConsumer> for MockBrokerClient {
    fn publisher(&self) -> &dyn Publisher {
        &self.publisher
    }

    async fn start_playlist_message_consumer(
        &self,
        queue: &str,
        _handler: impl MessageHandler<PlaylistMessage> + 'static,
    ) -> BrokerResult<MockConsumer> {
        let csm = self
            .start_playlist_message_consumer
            .call_with_args(queue.into());
        Ok(csm)
    }

    async fn start_source_message_consumer(
        &self,
        queue: &str,
        _handler: impl MessageHandler<SourceMessage> + 'static,
    ) -> BrokerResult<MockConsumer> {
        let csm = self.start_src_message_consumer.call_with_args(queue.into());
        Ok(csm)
    }
}

// Mods

pub mod rabbitmq;
