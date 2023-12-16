use std::{collections::BTreeMap, num::ParseIntError};

use autoplaylist_common::model::User;
use hmac::{digest::InvalidLength, Hmac, Mac};
use jwt::{Claims, RegisteredClaims, SignWithKey, VerifyWithKey};
use mockable::{Clock, DefaultClock, Env};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{ApiError, ApiResult};

// Consts - Env var keys

pub const ENV_VAR_KEY_JWT_ISSUER: &str = "JWT_ISSUER";
pub const ENV_VAR_KEY_JWT_SECRET: &str = "JWT_SECRET";
pub const ENV_VAR_KEY_JWT_VALIDITY: &str = "JWT_VALIDITY";

// Consts - Claim keys

pub const CLAIM_KEY_ROLE: &str = "role";

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

// JwtProvider

#[cfg_attr(test, mockall::automock)]
pub trait JwtProvider: Send + Sync {
    fn generate(&self, usr: &User) -> ApiResult<String>;

    fn verify(&self, jwt: &str) -> ApiResult<Uuid>;
}

// DefaultJwtProvider

pub struct DefaultJwtProvider<CLOCK: Clock> {
    cfg: JwtConfig,
    clock: CLOCK,
    key: Hmac<Sha256>,
}

impl DefaultJwtProvider<DefaultClock> {
    pub fn init(cfg: JwtConfig) -> Result<Self, InvalidLength> {
        let key = Hmac::new_from_slice(cfg.secret.as_bytes())?;
        Ok(Self {
            cfg,
            clock: DefaultClock,
            key,
        })
    }
}

impl<CLOCK: Clock> JwtProvider for DefaultJwtProvider<CLOCK> {
    fn generate(&self, usr: &User) -> ApiResult<String> {
        trace!("getting current timestamp");
        let ts: u64 = self.clock.utc().timestamp().try_into()?;
        trace!("serializing role into JSON");
        let role = serde_json::to_value(usr.role)?;
        let claims = Claims {
            private: BTreeMap::from_iter([(CLAIM_KEY_ROLE.into(), role)]),
            registered: RegisteredClaims {
                expiration: Some(ts + self.cfg.validity),
                issued_at: Some(ts),
                issuer: Some(self.cfg.issuer.clone()),
                subject: Some(usr.id.to_string()),
                ..Default::default()
            },
        };
        trace!("generating JWT");
        let jwt = claims.sign_with_key(&self.key)?;
        Ok(jwt)
    }

    fn verify(&self, jwt: &str) -> ApiResult<Uuid> {
        debug!("verifying JWT");
        let claims: RegisteredClaims = jwt
            .verify_with_key(&self.key)
            .map_err(|_| ApiError::Unauthorized)?;
        trace!("extracting subject from JWT");
        let sub = claims.subject.ok_or(ApiError::Unauthorized)?;
        trace!("extracting expiration from JWT");
        let exp = claims.expiration.ok_or(ApiError::Unauthorized)?;
        let ts: u64 = self.clock.utc().timestamp().try_into()?;
        if exp < ts {
            debug!("JWT is expired");
            return Err(ApiError::Unauthorized);
        }
        trace!("parsing subject as UUID");
        let sub = Uuid::parse_str(&sub).map_err(|_| ApiError::Unauthorized)?;
        Ok(sub)
    }
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    use autoplaylist_common::model::Role;
    use chrono::Utc;
    use jwt::VerifyWithKey;
    use mockable::{MockClock, MockEnv};
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
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                };
                let jwt = provider.generate(&usr).expect("failed to generate JWT");
                let claims: Claims = jwt
                    .verify_with_key(&provider.key)
                    .expect("failed to verify JWT");
                assert_eq!(claims.registered.subject, Some(usr.id.to_string()));
                assert_eq!(claims.registered.issuer, Some(provider.cfg.issuer));
                assert_eq!(claims.registered.issued_at, Some(ts));
                assert_eq!(
                    claims.registered.expiration,
                    Some(ts + provider.cfg.validity)
                );
                let role = claims
                    .private
                    .get(CLAIM_KEY_ROLE)
                    .expect("missing role")
                    .clone();
                let role: Role = serde_json::from_value(role).expect("failed to deserialize role");
                assert_eq!(role, usr.role);
            }
        }

        mod verify {
            use super::*;

            // run

            fn run(exp: u64) -> ApiResult<(Uuid, Uuid)> {
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
                assert!(matches!(err, ApiError::Unauthorized));
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
