use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::{
    api::PageRequestQueryParams,
    broker::{rabbitmq::RabbitMqClient, BrokerClient, SourceMessage, SourceMessageKind},
    db::{
        pg::{PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseConnection, DatabasePool, DatabaseTransaction,
    },
    model::{Page, Source},
};
use uuid::Uuid;

use crate::ServiceResult;

// SourceService

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SourceService: Send + Sync {
    async fn authenticated_user_sources(
        &self,
        user_id: Uuid,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Source>>;

    async fn sources(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<Source>>;

    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()>;
}

// DefaultSourceService

pub struct DefaultSourceService<
    BROKER: BrokerClient,
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
> {
    broker: Arc<BROKER>,
    db: Arc<DB>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
}

impl
    DefaultSourceService<RabbitMqClient, PostgresConnection, PostgresTransaction<'_>, PostgresPool>
{
    pub fn new(broker: Arc<RabbitMqClient>, db: Arc<PostgresPool>) -> Self {
        Self {
            broker,
            db,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
        }
    }
}

#[async_trait]
impl<
        BROKER: BrokerClient,
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
    > SourceService for DefaultSourceService<BROKER, DBCONN, DBTX, DB>
{
    async fn authenticated_user_sources(
        &self,
        user_id: Uuid,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<Source>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.user_sources(user_id, req.into()).await?;
        Ok(page)
    }

    async fn sources(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<Source>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.sources(req.into()).await?;
        Ok(page)
    }

    async fn start_synchronization(&self, id: Uuid) -> ServiceResult<()> {
        let msg = SourceMessage {
            id,
            kind: SourceMessageKind::Sync,
        };
        self.broker.publish_source_message(&msg).await?;
        Ok(())
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::{
        broker::MockBrokerClient,
        db::{MockDatabaseConnection, MockDatabasePool},
    };
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use super::*;

    mod default_source_message {
        use super::*;

        mod authenticated_user_sources {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let id = Uuid::new_v4();
                let req = PageRequestQueryParams::<25>::default();
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_user_sources()
                                .with(eq(id), eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_, _| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let src_svc = DefaultSourceService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = src_svc
                    .authenticated_user_sources(id, req)
                    .await
                    .expect("failed to get sources");
                assert_eq!(page, expected);
            }
        }

        mod sources {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let req = PageRequestQueryParams::<25>::default();
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: req.into(),
                    total: 0,
                };
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let expected = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_sources()
                                .with(eq(expected.req))
                                .times(1)
                                .returning({
                                    let expected = expected.clone();
                                    move |_| Ok(expected.clone())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let src_svc = DefaultSourceService {
                    broker: Arc::new(MockBrokerClient::default()),
                    db: Arc::new(db),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = src_svc.sources(req).await.expect("failed to get sources");
                assert_eq!(page, expected);
            }
        }

        mod start_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let msg = SourceMessage {
                    id: Uuid::new_v4(),
                    kind: SourceMessageKind::Sync,
                };
                let mut broker = MockBrokerClient::new();
                broker
                    .expect_publish_source_message()
                    .with(eq(msg.clone()))
                    .times(1)
                    .returning(|_| Ok(()));
                let src_svc = DefaultSourceService {
                    broker: Arc::new(broker),
                    db: Arc::new(MockDatabasePool::default()),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                src_svc
                    .start_synchronization(msg.id)
                    .await
                    .expect("failed to start synchronization");
            }
        }
    }
}
