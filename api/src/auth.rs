use std::{marker::PhantomData, num::ParseIntError, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::{
    api::{AuthenticateViaSpotifyQueryParams, RedirectUriQueryParam},
    db::{
        pg::{PostgresConnection, PostgresPool, PostgresTransaction},
        DatabaseConnection, DatabasePool, DatabaseTransaction, UserCreation,
    },
    model::{Credentials, SpotifyCredentials, User},
    spotify::{rspotify::RSpotifyClient, SpotifyClient},
};
use axum::http::{header, HeaderMap};
use hmac::{digest::InvalidLength, Hmac, Mac};
use jwt::{RegisteredClaims, SignWithKey, VerifyWithKey};
use mockable::{Clock, DefaultClock, Env};
use regex::Regex;
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::{ServiceError, ServiceResult};

// Consts - Env var keys

pub const ENV_VAR_KEY_JWT_ISSUER: &str = "JWT_ISSUER";
pub const ENV_VAR_KEY_JWT_SECRET: &str = "JWT_SECRET";
pub const ENV_VAR_KEY_JWT_VALIDITY: &str = "JWT_VALIDITY";

// Consts - Defaults

pub const DEFAULT_JWT_ISSUER: &str = "localhost:8000";
pub const DEFAULT_JWT_VALIDITY: u64 = 60 * 60 * 24 * 7;

// JwtConfigError

#[derive(Debug, Error)]
pub enum JwtConfigError {
    #[error("invalid JWT validity: {0}")]
    InvalidValidity(
        #[from]
        #[source]
        ParseIntError,
    ),
    #[error("missing environment variable: {0}")]
    MissingEnvVar(&'static str),
}

// JwtConfig

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtConfig {
    pub issuer: String,
    pub secret: String,
    pub validity: u64,
}

impl JwtConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, JwtConfigError> {
        debug!("loading JWT configuration");
        Ok(Self {
            issuer: env
                .string(ENV_VAR_KEY_JWT_ISSUER)
                .unwrap_or_else(|| DEFAULT_JWT_ISSUER.into()),
            secret: env
                .string(ENV_VAR_KEY_JWT_SECRET)
                .ok_or(JwtConfigError::MissingEnvVar(ENV_VAR_KEY_JWT_SECRET))?,
            validity: env
                .u64(ENV_VAR_KEY_JWT_VALIDITY)
                .unwrap_or(Ok(DEFAULT_JWT_VALIDITY))?,
        })
    }
}

// AuthService

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AuthService: Send + Sync {
    async fn authenticate_via_spotify(
        &self,
        params: &AuthenticateViaSpotifyQueryParams,
    ) -> ServiceResult<String>;

    async fn authenticated_user(&self, headers: &HeaderMap) -> ServiceResult<User>;

    fn spotify_authorize_url(&self, params: &RedirectUriQueryParam) -> ServiceResult<String>;
}

// JwtProvider

#[cfg_attr(test, mockall::automock)]
pub trait JwtProvider: Send + Sync {
    fn generate(&self, sub: Uuid) -> ServiceResult<String>;

    fn verify(&self, jwt: &str) -> ServiceResult<Uuid>;
}

// DefaultAuthService

pub struct DefaultAuthService<
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    JWT: JwtProvider,
    SPOTIFY: SpotifyClient,
> {
    db: Arc<DB>,
    jwt: JWT,
    spotify: Arc<SPOTIFY>,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
}

impl
    DefaultAuthService<
        PostgresConnection,
        PostgresTransaction<'_>,
        PostgresPool,
        DefaultJwtProvider<DefaultClock>,
        RSpotifyClient,
    >
{
    pub fn init(
        jwt_cfg: JwtConfig,
        db: Arc<PostgresPool>,
        spotify: Arc<RSpotifyClient>,
    ) -> Result<Self, InvalidLength> {
        Ok(Self {
            db,
            jwt: DefaultJwtProvider::init(jwt_cfg)?,
            spotify,
            _dbconn: PhantomData,
            _dbtx: PhantomData,
        })
    }
}

#[async_trait]
impl<
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        JWT: JwtProvider,
        SPOTIFY: SpotifyClient,
    > AuthService for DefaultAuthService<DBCONN, DBTX, DB, JWT, SPOTIFY>
{
    async fn authenticate_via_spotify(
        &self,
        params: &AuthenticateViaSpotifyQueryParams,
    ) -> ServiceResult<String> {
        let mut db_conn = self.db.acquire().await?;
        let mut token = self
            .spotify
            .authenticate(&params.code, &params.redirect_uri)
            .await?;
        let spotify_usr = self.spotify.authenticated_user(&mut token).await?;
        let creds = SpotifyCredentials {
            id: spotify_usr.id,
            token,
        };
        let usr = db_conn.user_by_email(&spotify_usr.email).await?;
        let usr = match usr {
            Some(mut user) => {
                user.creds.spotify = Some(creds);
                db_conn.update_user(&user).await?;
                user
            }
            None => {
                let creation = UserCreation {
                    creds: Credentials {
                        spotify: Some(creds),
                    },
                    email: spotify_usr.email,
                };
                let usr = db_conn.create_user(&creation).await?;
                info!(usr.email, %usr.id, "user created");
                usr
            }
        };
        self.jwt.generate(usr.id)
    }

    async fn authenticated_user(&self, headers: &HeaderMap) -> ServiceResult<User> {
        trace!("reading header `{}`", header::AUTHORIZATION);
        let header = headers
            .get(header::AUTHORIZATION)
            .ok_or(ServiceError::Unauthorized)?;
        trace!("decoding header `{}`", header::AUTHORIZATION);
        let authz = header.to_str().map_err(|_| ServiceError::Unauthorized)?;
        let bearer_re = Regex::new(r"^(?i)bearer (.+)$")?;
        trace!("extracting JWT from header `{}`", header::AUTHORIZATION);
        let jwt = bearer_re
            .captures(authz)
            .and_then(|captures| captures.get(1))
            .ok_or(ServiceError::Unauthorized)?
            .as_str();
        let id = self.jwt.verify(jwt)?;
        let mut db_conn = self.db.acquire().await?;
        match db_conn.user_by_id(id).await? {
            Some(usr) => Ok(usr),
            None => {
                debug!(usr.id = %id, "user doesn't exist");
                Err(ServiceError::Unauthorized)
            }
        }
    }

    fn spotify_authorize_url(&self, params: &RedirectUriQueryParam) -> ServiceResult<String> {
        let url = self.spotify.authorize_url(&params.redirect_uri)?;
        Ok(url)
    }
}

// DefaultJwtProvider

pub struct DefaultJwtProvider<CLOCK: Clock> {
    cfg: JwtConfig,
    clock: CLOCK,
    key: Hmac<Sha256>,
}

impl DefaultJwtProvider<DefaultClock> {
    fn init(cfg: JwtConfig) -> Result<Self, InvalidLength> {
        let key = Hmac::new_from_slice(cfg.secret.as_bytes())?;
        Ok(Self {
            cfg,
            clock: DefaultClock,
            key,
        })
    }
}

impl<CLOCK: Clock> JwtProvider for DefaultJwtProvider<CLOCK> {
    fn generate(&self, sub: Uuid) -> ServiceResult<String> {
        let ts: u64 = self.clock.utc().timestamp().try_into()?;
        let claims = RegisteredClaims {
            expiration: Some(ts + self.cfg.validity),
            issued_at: Some(ts),
            issuer: Some(self.cfg.issuer.clone()),
            subject: Some(sub.to_string()),
            ..Default::default()
        };
        trace!("generating JWT");
        let jwt = claims.sign_with_key(&self.key)?;
        Ok(jwt)
    }

    fn verify(&self, jwt: &str) -> ServiceResult<Uuid> {
        debug!("verifying JWT");
        let claims: RegisteredClaims = jwt
            .verify_with_key(&self.key)
            .map_err(|_| ServiceError::Unauthorized)?;
        trace!("extracting subject from JWT");
        let sub = claims.subject.ok_or(ServiceError::Unauthorized)?;
        trace!("extracting expiration from JWT");
        let exp = claims.expiration.ok_or(ServiceError::Unauthorized)?;
        let ts: u64 = self.clock.utc().timestamp().try_into()?;
        if exp < ts {
            debug!("JWT is expired");
            return Err(ServiceError::Unauthorized);
        }
        trace!("parsing subject as UUID");
        let sub = Uuid::parse_str(&sub).map_err(|_| ServiceError::Unauthorized)?;
        Ok(sub)
    }
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    use autoplaylist_common::{
        db::{MockDatabaseConnection, MockDatabasePool},
        model::{Role, SpotifyToken, User},
        spotify::{MockSpotifyClient, SpotifyUser},
    };
    use chrono::Utc;
    use jwt::VerifyWithKey;
    use mockable::{Mock, MockClock, MockEnv};
    use mockall::predicate::eq;

    mod jwt_config {
        use super::*;

        // Mods

        mod from_env {
            use super::*;

            // Params

            struct Params {
                issuer: Option<String>,
                secret: String,
                validity: Option<u64>,
            }

            // run

            fn run(params: Params, expected: JwtConfig) {
                let mut env = MockEnv::new();
                env.expect_string()
                    .with(eq(ENV_VAR_KEY_JWT_ISSUER))
                    .times(1)
                    .return_const(params.issuer.clone());
                env.expect_string()
                    .with(eq(ENV_VAR_KEY_JWT_SECRET))
                    .times(1)
                    .returning(move |_| Some(params.secret.clone()));
                env.expect_u64()
                    .with(eq(ENV_VAR_KEY_JWT_VALIDITY))
                    .times(1)
                    .returning(move |_| params.validity.map(Ok));
                let cfg = JwtConfig::from_env(&env).expect("failed to load JWT configuration");
                assert_eq!(cfg, expected);
            }

            // Tests

            #[test]
            fn default() {
                let expected = JwtConfig {
                    issuer: DEFAULT_JWT_ISSUER.into(),
                    secret: "changeit".into(),
                    validity: DEFAULT_JWT_VALIDITY,
                };
                let params = Params {
                    issuer: None,
                    secret: expected.secret.clone(),
                    validity: None,
                };
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = JwtConfig {
                    issuer: "autoplaylist".into(),
                    secret: "changeit".into(),
                    validity: 10,
                };
                let params = Params {
                    issuer: Some(expected.issuer.clone()),
                    secret: expected.secret.clone(),
                    validity: Some(expected.validity),
                };
                run(params, expected);
            }
        }
    }

    mod default_auth_service {
        use super::*;

        mod authenticate_via_spotify {
            use super::*;

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                create_usr: Mock<()>,
                update_usr: Mock<()>,
                usr_by_email: Mock<Option<User>, User>,
            }

            // run

            async fn run(mocks: Mocks) {
                let params = AuthenticateViaSpotifyQueryParams {
                    code: "code".into(),
                    redirect_uri: "redirect_uri".into(),
                };
                let token = SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                };
                let spotify_usr = SpotifyUser {
                    id: "id".into(),
                    email: "user@test".into(),
                };
                let usr = User {
                    creation: Utc::now(),
                    creds: Credentials {
                        spotify: Some(SpotifyCredentials {
                            id: spotify_usr.id.clone(),
                            token: token.clone(),
                        }),
                    },
                    email: spotify_usr.email.clone(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let expected = "jwt";
                let db_pool = MockDatabasePool {
                    acquire: Mock::once({
                        let usr = usr.clone();
                        let mocks = mocks.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            conn.0
                                .expect_user_by_email()
                                .with(eq(usr.email.clone()))
                                .times(mocks.usr_by_email.times())
                                .returning({
                                    let usr = usr.clone();
                                    let mock = mocks.usr_by_email.clone();
                                    move |_| Ok(mock.call_with_args(usr.clone()))
                                });
                            conn.0
                                .expect_update_user()
                                .with(eq(usr.clone()))
                                .times(mocks.update_usr.times())
                                .returning({
                                    let mock = mocks.update_usr.clone();
                                    move |_| {
                                        mock.call();
                                        Ok(())
                                    }
                                });
                            let creation: UserCreation = usr.clone().into();
                            conn.0
                                .expect_create_user()
                                .with(eq(creation))
                                .times(mocks.create_usr.times())
                                .returning({
                                    let mock = mocks.create_usr.clone();
                                    let usr = usr.clone();
                                    move |_| {
                                        mock.call();
                                        Ok(usr.clone())
                                    }
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let mut spotify = MockSpotifyClient::new();
                spotify
                    .expect_authenticate()
                    .with(eq(params.code.clone()), eq(params.redirect_uri.clone()))
                    .times(1)
                    .returning({
                        let token = token.clone();
                        move |_, _| Ok(token.clone())
                    });

                spotify
                    .expect_authenticated_user()
                    .with(eq(token.clone()))
                    .times(1)
                    .returning({
                        let usr = spotify_usr.clone();
                        move |_| Ok(usr.clone())
                    });
                let mut jwt = MockJwtProvider::new();
                jwt.expect_generate()
                    .with(eq(usr.id))
                    .times(1)
                    .returning(|_| Ok(expected.into()));
                let auth = DefaultAuthService {
                    db: Arc::new(db_pool),
                    jwt,
                    spotify: Arc::new(spotify),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let jwt = auth
                    .authenticate_via_spotify(&params)
                    .await
                    .expect("failed to authenticate via Spotify");
                assert_eq!(jwt, expected);
            }

            // Tests

            #[tokio::test]
            async fn jwt_when_user_didnt_exist() {
                let mocks = Mocks {
                    create_usr: Mock::once(|| ()),
                    usr_by_email: Mock::once_with_args(|_| None),
                    ..Default::default()
                };
                run(mocks).await;
            }

            #[tokio::test]
            async fn jwt_when_user_already_existed() {
                let mocks = Mocks {
                    update_usr: Mock::once(|| ()),
                    usr_by_email: Mock::once_with_args(|usr| {
                        Some(User {
                            creds: Default::default(),
                            ..usr
                        })
                    }),
                    ..Default::default()
                };
                run(mocks).await;
            }
        }

        mod authenticated_user {
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

            async fn run(data: Data, mocks: Mocks) -> ServiceResult<(User, User)> {
                let expected = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    email: "user@test".into(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let mut provider = MockJwtProvider::new();
                provider
                    .expect_verify()
                    .with(eq(data.jwt))
                    .times(mocks.verify.times())
                    .returning(move |_| Ok(expected.id));
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let usr = expected.clone();
                        move || {
                            let mut conn = MockDatabaseConnection::new();
                            let mocks = mocks.clone();
                            conn.0
                                .expect_user_by_id()
                                .with(eq(usr.id))
                                .times(mocks.usr_by_id.times())
                                .returning({
                                    let usr = usr.clone();
                                    let mock = mocks.usr_by_id.clone();
                                    move |_| Ok(mock.call_with_args(usr.clone()))
                                });
                            conn
                        }
                    }),
                    ..Default::default()
                };
                let auth = DefaultAuthService {
                    db: Arc::new(db),
                    jwt: provider,
                    spotify: Arc::new(MockSpotifyClient::new()),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                auth.authenticated_user(&data.headers)
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
                assert!(matches!(err, ServiceError::Unauthorized));
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
                assert!(matches!(err, ServiceError::Unauthorized));
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
                assert!(matches!(err, ServiceError::Unauthorized));
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

        mod spotify_authorize_url {
            use super::*;

            // Tests

            #[tokio::test]
            async fn url() {
                let expected = "url";
                let params = RedirectUriQueryParam::from(String::from("redirect_uri"));
                let mut spotify = MockSpotifyClient::new();
                spotify
                    .expect_authorize_url()
                    .with(eq(params.redirect_uri.clone()))
                    .times(1)
                    .returning(move |_| Ok(expected.into()));
                let auth = DefaultAuthService {
                    db: Arc::new(MockDatabasePool::default()),
                    jwt: MockJwtProvider::new(),
                    spotify: Arc::new(spotify),
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                };
                let url = auth
                    .spotify_authorize_url(&params)
                    .expect("failed to get Spotify authorize URL");
                assert_eq!(url, expected);
            }
        }
    }

    mod default_jwt_provider {
        use super::*;

        // Mods

        mod generate {
            use super::*;

            #[test]
            fn jwt() {
                let cfg = JwtConfig {
                    issuer: "issuer".into(),
                    secret: "changeit".into(),
                    validity: 10,
                };
                let key =
                    Hmac::new_from_slice(cfg.secret.as_bytes()).expect("failed to create key");
                let mut clock = MockClock::new();
                let now = Utc::now();
                let ts: u64 = now
                    .timestamp()
                    .try_into()
                    .expect("failed to cast timestamp");
                clock.expect_utc().times(1).return_const(now);
                let provider = DefaultJwtProvider { cfg, clock, key };
                let sub = Uuid::new_v4();
                let jwt = provider.generate(sub).expect("failed to generate JWT");
                let claims: RegisteredClaims = jwt
                    .verify_with_key(&provider.key)
                    .expect("failed to verify JWT");
                assert_eq!(claims.subject, Some(sub.to_string()));
                assert_eq!(claims.issuer, Some(provider.cfg.issuer));
                assert_eq!(claims.issued_at, Some(ts));
                assert_eq!(claims.expiration, Some(ts + provider.cfg.validity));
            }
        }

        mod verify {
            use super::*;

            // run

            fn run(exp: u64) -> ServiceResult<(Uuid, Uuid)> {
                let expected = Uuid::new_v4();
                let cfg = JwtConfig {
                    issuer: "issuer".into(),
                    secret: "changeit".into(),
                    validity: 10,
                };
                let key =
                    Hmac::new_from_slice(cfg.secret.as_bytes()).expect("failed to create key");
                let claims = RegisteredClaims {
                    expiration: Some(exp),
                    subject: Some(expected.to_string()),
                    ..Default::default()
                };
                let jwt = claims.sign_with_key(&key).expect("failed to sign JWT");
                let provider = DefaultJwtProvider {
                    cfg,
                    clock: DefaultClock,
                    key,
                };
                provider.verify(&jwt).map(|id| (id, expected))
            }

            // Tests

            #[test]
            fn expired() {
                let err = run(0).expect_err("verifying JWT should fail");
                assert!(matches!(err, ServiceError::Unauthorized));
            }

            #[test]
            fn jwt() {
                let ts: u64 = Utc::now()
                    .timestamp()
                    .try_into()
                    .expect("failed to cast timestamp");
                let (id, expected) = run(ts + 1000).expect("failed to verify JWT");
                assert_eq!(id, expected);
            }
        }
    }
}
