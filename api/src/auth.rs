use std::{future::Future, pin::Pin};

use async_trait::async_trait;
use autoplaylist_common::{db::DatabaseClient, model::User};
use axum::http::{header, HeaderMap};
use mockable::DefaultClock;
use regex::Regex;
use tracing::trace;

use crate::{
    jwt::{DefaultJwtProvider, JwtProvider},
    ApiError, ApiResult,
};

// Authenticator

#[cfg_attr(test, mockall::automock)]
pub trait Authenticator: Send + Sync {
    fn authenticate<'a, 'b, 'c, 'd>(
        &'a self,
        headers: &'b HeaderMap,
        db_conn: &'c mut dyn DatabaseClient,
    ) -> Pin<Box<dyn Future<Output = ApiResult<User>> + Send + 'd>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd;
}

// DefaultAuthenticator

pub struct DefaultAuthenticator<JWT: JwtProvider>(pub JWT);

impl DefaultAuthenticator<DefaultJwtProvider<DefaultClock>> {
    pub fn new(jwt: DefaultJwtProvider<DefaultClock>) -> Self {
        Self(jwt)
    }
}

#[async_trait]
impl<JWT: JwtProvider> Authenticator for DefaultAuthenticator<JWT> {
    fn authenticate<'a, 'b, 'c, 'd>(
        &'a self,
        headers: &'b HeaderMap,
        db_conn: &'c mut dyn DatabaseClient,
    ) -> Pin<Box<dyn Future<Output = ApiResult<User>> + Send + 'd>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        Box::pin(async move {
            trace!("reading header `{}`", header::AUTHORIZATION);
            let header = headers
                .get(header::AUTHORIZATION)
                .ok_or(ApiError::Unauthorized)?;
            trace!("decoding header `{}`", header::AUTHORIZATION);
            let authz = header.to_str().map_err(|_| ApiError::Unauthorized)?;
            let bearer_re = Regex::new(r"^(?i)bearer (.+)$")?;
            trace!("extracting JWT from header `{}`", header::AUTHORIZATION);
            let jwt = bearer_re
                .captures(authz)
                .and_then(|captures| captures.get(1))
                .ok_or(ApiError::Unauthorized)?
                .as_str();
            let id = self.0.verify(jwt)?;
            db_conn.user_by_id(id).await?.ok_or(ApiError::Unauthorized)
        })
    }
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    use autoplaylist_common::{
        db::MockDatabaseConnection,
        model::{Role, User},
    };
    use chrono::Utc;
    use mockable::Mock;
    use mockall::predicate::eq;
    use uuid::Uuid;

    use crate::jwt::MockJwtProvider;

    mod default_authenticator {
        use super::*;

        // Data

        struct Data {
            headers: HeaderMap,
            jwt: &'static str,
        }

        // Mocks

        #[derive(Clone, Default)]
        struct Mocks {
            usr_by_id: Mock<Option<User>, User>,
            verify: Mock<()>,
        }

        // run

        async fn run(data: Data, mocks: Mocks) -> ApiResult<(User, User)> {
            let expected = User {
                creation: Utc::now(),
                creds: Default::default(),
                id: Uuid::new_v4(),
                role: Role::User,
            };
            let mut jwt_prov = MockJwtProvider::new();
            jwt_prov
                .expect_verify()
                .with(eq(data.jwt))
                .times(mocks.verify.times())
                .returning(move |_| Ok(expected.id));
            let mut db_conn = MockDatabaseConnection::new();
            let mocks = mocks.clone();
            db_conn
                .0
                .expect_user_by_id()
                .with(eq(expected.id))
                .times(mocks.usr_by_id.times())
                .returning({
                    let usr = expected.clone();
                    let mock = mocks.usr_by_id.clone();
                    move |_| Ok(mock.call_with_args(usr.clone()))
                });
            let auth = DefaultAuthenticator(jwt_prov);
            auth.authenticate(&data.headers, &mut db_conn)
                .await
                .map(|usr| (usr, expected))
        }

        // Tests

        #[tokio::test]
        async fn unauthorized_when_no_header() {
            let data = Data {
                headers: HeaderMap::new(),
                jwt: "jwt",
            };
            let mocks = Mocks::default();
            let err = run(data, mocks)
                .await
                .expect_err("getting authenticated user should fail");
            assert!(matches!(err, ApiError::Unauthorized));
        }

        #[tokio::test]
        async fn unauthorized_when_invalid_bearer() {
            let data = Data {
                headers: HeaderMap::from_iter([(
                    header::AUTHORIZATION,
                    "".parse().expect("failed to parse header value"),
                )]),
                jwt: "jwt",
            };
            let mocks = Mocks::default();
            let err = run(data, mocks)
                .await
                .expect_err("getting authenticated user should fail");
            assert!(matches!(err, ApiError::Unauthorized));
        }

        #[tokio::test]
        async fn unauthorized_when_user_doesnt_exist() {
            let jwt = "jwt";
            let data = Data {
                headers: HeaderMap::from_iter([(
                    header::AUTHORIZATION,
                    format!("bEaReR {jwt}")
                        .parse()
                        .expect("failed to parse header value"),
                )]),
                jwt,
            };
            let mocks = Mocks {
                usr_by_id: Mock::once_with_args(|_| None),
                verify: Mock::once(|| ()),
            };
            let err = run(data, mocks)
                .await
                .expect_err("getting authenticated user should fail");
            assert!(matches!(err, ApiError::Unauthorized));
        }

        #[tokio::test]
        async fn user() {
            let jwt = "jwt";
            let data = Data {
                headers: HeaderMap::from_iter([(
                    header::AUTHORIZATION,
                    format!("bEaReR {jwt}")
                        .parse()
                        .expect("failed to parse header value"),
                )]),
                jwt,
            };
            let mocks = Mocks {
                usr_by_id: Mock::once_with_args(Some),
                verify: Mock::once(|| ()),
            };
            let (usr, expected) = run(data, mocks)
                .await
                .expect("failed to get authenticated user");
            assert_eq!(usr, expected);
        }
    }
}
