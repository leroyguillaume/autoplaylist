use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::broker::{
    rabbitmq::{RabbitMqClient, RabbitMqConsumer},
    BrokerClient, Consumer, SourceMessage, SourceMessageKind,
};
use uuid::Uuid;

use crate::ServiceResult;

// SourceService

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SourceService: Send + Sync {
    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()>;
}

// DefaultSourceService

pub struct DefaultSourceService<CSM: Consumer, BROKER: BrokerClient<CSM>> {
    broker: Arc<BROKER>,
    _csm: PhantomData<CSM>,
}

impl DefaultSourceService<RabbitMqConsumer, RabbitMqClient> {
    pub fn new(broker: Arc<RabbitMqClient>) -> Self {
        Self {
            broker,
            _csm: PhantomData,
        }
    }
}

#[async_trait]
impl<CSM: Consumer, BROKER: BrokerClient<CSM>> SourceService for DefaultSourceService<CSM, BROKER> {
    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()> {
        let msg = SourceMessage {
            id,
            kind: SourceMessageKind::Sync,
        };
        self.broker.publisher().publish_source_message(&msg).await?;
        Ok(())
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::broker::{MockBrokerClient, MockPublisher};
    use mockall::predicate::eq;
    use uuid::Uuid;

    use super::*;

    mod default_source_message {
        use super::*;

        mod start_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let msg = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Sync,
                };
                let mut publisher = MockPublisher::new();
                publisher
                    .expect_publish_source_message()
                    .with(eq(msg.clone()))
                    .times(1)
                    .returning(|_| Ok(()));
                let broker = MockBrokerClient {
                    publisher,
                    ..Default::default()
                };
                let src_svc = DefaultSourceService {
                    broker: Arc::new(broker),
                    _csm: PhantomData,
                };
                src_svc
                    .start_synchronization(msg.id)
                    .await
                    .expect("failed to start synchronization");
            }
        }
    }
}
