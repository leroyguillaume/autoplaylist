use std::num::ParseIntError;

use autoplaylist_common::{api::JwtClaims, model::User};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use mockable::{Clock, DefaultClock, Env};
use thiserror::Error;
use tracing::debug;
use uuid::Uuid;

use crate::{ApiError, ApiResult};

// Consts - Env var keys

pub const ENV_VAR_KEY_JWT_SECRET: &str = "JWT_SECRET";
pub const ENV_VAR_KEY_JWT_VALIDITY: &str = "JWT_VALIDITY";

// Consts - Defaults

pub const DEFAULT_JWT_VALIDITY: i64 = 60 * 60 * 24 * 7;

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
    pub secret: String,
    pub validity: i64,
}

impl JwtConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, JwtConfigError> {
        debug!("loading JWT configuration");
        let cfg = Self {
            secret: env
                .string(ENV_VAR_KEY_JWT_SECRET)
                .ok_or(JwtConfigError::MissingEnvVar(ENV_VAR_KEY_JWT_SECRET))?,
            validity: env
                .i64(ENV_VAR_KEY_JWT_VALIDITY)
                .unwrap_or(Ok(DEFAULT_JWT_VALIDITY))?,
        };
        debug!(jwt.cfg.validity = cfg.validity, "JWT configuration loaded");
        Ok(cfg)
    }
}

// JwtProvider

#[cfg_attr(test, mockall::automock)]
pub trait JwtProvider: Send + Sync {
    fn decode(&self, jwt: &str) -> ApiResult<Uuid>;

    fn encode(&self, usr: &User) -> ApiResult<String>;
}

// DefaultJwtProvider

pub struct DefaultJwtProvider<CLOCK: Clock> {
    cfg: JwtConfig,
    clock: CLOCK,
    decoding_key: DecodingKey,
    encoding_key: EncodingKey,
}

impl DefaultJwtProvider<DefaultClock> {
    pub fn new(cfg: JwtConfig) -> Self {
        let secret = cfg.secret.as_bytes();
        let decoding_key = DecodingKey::from_secret(secret);
        let encoding_key = EncodingKey::from_secret(secret);
        Self {
            cfg,
            clock: DefaultClock,
            decoding_key,
            encoding_key,
        }
    }
}

impl<CLOCK: Clock> JwtProvider for DefaultJwtProvider<CLOCK> {
    fn decode(&self, jwt: &str) -> ApiResult<Uuid> {
        debug!("decoding JWT");
        let data =
            jsonwebtoken::decode::<JwtClaims>(jwt, &self.decoding_key, &Validation::default())
                .map_err(|err| {
                    debug!("failed to decode JWT: {err}");
                    ApiError::Unauthorized
                })?;
        Ok(data.claims.sub)
    }

    fn encode(&self, usr: &User) -> ApiResult<String> {
        let claims = JwtClaims {
            exp: self.clock.utc().timestamp() + self.cfg.validity,
            role: usr.role,
            sub: usr.id,
        };
        debug!("encoding JWT");
        let jwt = jsonwebtoken::encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(jwt)
    }
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    use autoplaylist_common::model::Role;
    use chrono::Utc;
    use mockable::{MockClock, MockEnv};
    use mockall::predicate::eq;

    mod jwt_config {
        use super::*;

        // Mods

        mod from_env {
            use super::*;

            // Params

            struct Params {
                secret: String,
                validity: Option<i64>,
            }

            // run

            fn run(params: Params, expected: JwtConfig) {
                let mut env = MockEnv::new();
                env.expect_string()
                    .with(eq(ENV_VAR_KEY_JWT_SECRET))
                    .times(1)
                    .returning(move |_| Some(params.secret.clone()));
                env.expect_i64()
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
                    secret: "changeit".into(),
                    validity: DEFAULT_JWT_VALIDITY,
                };
                let params = Params {
                    secret: expected.secret.clone(),
                    validity: None,
                };
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = JwtConfig {
                    secret: "changeit".into(),
                    validity: 10,
                };
                let params = Params {
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
                    secret: "changeit".into(),
                    validity: 10,
                };
                let secret = cfg.secret.as_bytes();
                let encoding_key = EncodingKey::from_secret(secret);
                let decoding_key = DecodingKey::from_secret(secret);
                let mut clock = MockClock::new();
                let now = Utc::now();
                let ts = now.timestamp();
                clock.expect_utc().times(1).return_const(now);
                let provider = DefaultJwtProvider {
                    cfg,
                    clock,
                    encoding_key,
                    decoding_key,
                };
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                };
                let jwt = provider.encode(&usr).expect("failed to generate JWT");
                let data = jsonwebtoken::decode::<JwtClaims>(
                    &jwt,
                    &provider.decoding_key,
                    &Validation::default(),
                )
                .expect("failed to decode JWT");
                let expected = JwtClaims {
                    exp: ts + provider.cfg.validity,
                    role: usr.role,
                    sub: usr.id,
                };
                assert_eq!(data.claims, expected);
            }
        }

        mod verify {
            use super::*;

            // run

            fn run(exp: i64) -> ApiResult<(Uuid, Uuid)> {
                let expected = Uuid::new_v4();
                let cfg = JwtConfig {
                    secret: "changeit".into(),
                    validity: 10,
                };
                let secret = cfg.secret.as_bytes();
                let encoding_key = EncodingKey::from_secret(secret);
                let decoding_key = DecodingKey::from_secret(secret);
                let claims = JwtClaims {
                    exp,
                    role: Role::Admin,
                    sub: expected,
                };
                let jwt = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
                    .expect("failed to encode JWT");
                let provider = DefaultJwtProvider {
                    cfg,
                    clock: DefaultClock,
                    decoding_key,
                    encoding_key,
                };
                provider.decode(&jwt).map(|id| (id, expected))
            }

            // Tests

            #[test]
            fn expired() {
                let err = run(0).expect_err("verifying JWT should fail");
                assert!(matches!(err, ApiError::Unauthorized));
            }

            #[test]
            fn jwt() {
                let ts = Utc::now().timestamp();
                let (id, expected) = run(ts + 1000).expect("failed to verify JWT");
                assert_eq!(id, expected);
            }
        }
    }
}
