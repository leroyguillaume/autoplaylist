use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::{
    api::{PageRequestQueryParams, SearchQueryParam},
    db::{
        pg::{PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseConnection, DatabasePool, DatabaseTransaction,
    },
    model::{Page, User},
};
use uuid::Uuid;

use crate::{ServiceError, ServiceResult};

// UserService

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UserService: Send + Sync {
    async fn delete(&self, id: Uuid) -> ServiceResult<()>;

    async fn search_users_by_email(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<User>>;

    async fn users(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<User>>;
}

// DefaultUserService

pub struct DefaultUserService<
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
> {
    db: Arc<DB>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
}

impl DefaultUserService<PostgresConnection, PostgresTransaction<'_>, PostgresPool> {
    pub fn new(db: Arc<PostgresPool>) -> Self {
        Self {
            db,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
        }
    }
}

#[async_trait]
impl<DBCONN: DatabaseConnection, DBTX: DatabaseTransaction, DB: DatabasePool<DBCONN, DBTX>>
    UserService for DefaultUserService<DBCONN, DBTX, DB>
{
    async fn delete(&self, id: Uuid) -> ServiceResult<()> {
        let mut db_conn = self.db.acquire().await?;
        if db_conn.delete_user(id).await? {
            Ok(())
        } else {
            Err(ServiceError::NotFound(id))
        }
    }

    async fn search_users_by_email(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
    ) -> ServiceResult<Page<User>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.search_users_by_email(&params.q, req.into()).await?;
        Ok(page)
    }

    async fn users(&self, req: PageRequestQueryParams<25>) -> ServiceResult<Page<User>> {
        let mut db_conn = self.db.acquire().await?;
        let page = db_conn.users(req.into()).await?;
        Ok(page)
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::db::{MockDatabaseConnection, MockDatabasePool};
    use mockable::Mock;
    use mockall::predicate::eq;

    use super::*;

    // Mods

    mod default_user_message {
        use super::*;

        // Mods

        mod delete {
            use super::*;

            // run

            async fn run(id: Uuid, mock: Mock<bool>) -> ServiceResult<()> {
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let mock = mock.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_delete_user()
                                .with(eq(id))
                                .times(1)
                                .returning({
                                    let mock = mock.clone();
                                    move |_| Ok(mock.call())
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let usr_svc = DefaultUserService {
                    db: Arc::new(db),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                usr_svc.delete(id).await
            }

            // Tests

            #[tokio::test]
            async fn not_found() {
                let expected = Uuid::new_v4();
                let err = run(expected, Mock::once(|| false))
                    .await
                    .expect_err("deleting user should failed");
                match err {
                    ServiceError::NotFound(id) => {
                        assert_eq!(id, expected);
                    }
                    _ => panic!("unexpected error: {err:?}"),
                }
            }

            #[tokio::test]
            async fn unit() {
                let id = Uuid::new_v4();
                run(id, Mock::once(|| true))
                    .await
                    .expect("failed to delete user");
            }
        }

        mod search_users {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let req = PageRequestQueryParams::<25>::default();
                let params = SearchQueryParam { q: "query".into() };
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
                        let params = params.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_search_users_by_email()
                                .with(eq(params.q.clone()), eq(expected.req))
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
                let usr_svc = DefaultUserService {
                    db: Arc::new(db),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = usr_svc
                    .search_users_by_email(&params, req)
                    .await
                    .expect("failed to get users");
                assert_eq!(page, expected);
            }
        }

        mod users {
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
                                .expect_users()
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
                let usr_svc = DefaultUserService {
                    db: Arc::new(db),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let page = usr_svc.users(req).await.expect("failed to get users");
                assert_eq!(page, expected);
            }
        }
    }
}
