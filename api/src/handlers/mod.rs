use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    num::TryFromIntError,
    result::Result as StdResult,
};

use actix_web::{
    body::BoxBody,
    http::{header, StatusCode},
    HttpRequest, HttpResponse, ResponseError,
};
use chrono::Utc;
use deadpool_postgres::{
    tokio_postgres::Client as TokioPostgresClient, tokio_postgres::Error as TokioPostgresError,
    PoolError as DeadpoolPostgresPoolError,
};
use hmac::{digest::InvalidLength as HmacInvalidLength, Hmac, Mac};
use jwt::{Claims, Error as JwtError, VerifyWithKey};
use regex::Regex;
use rspotify::ClientError;
use sha2::Sha512;
use tracing::{debug, error, trace};
use uuid::Uuid;

use crate::{
    cfg::JwtConfig,
    db::user_by_id,
    domain::User,
    dto::{ConflictResponse, PreconditionFailedResponse},
};

// Macros

macro_rules! handle {
    ($block:expr) => {
        match $block.await {
            Ok(resp) => resp,
            Err(err) => {
                err.log();
                use actix_web::ResponseError;
                err.error_response()
            }
        }
    };
}

macro_rules! transactional {
    ($tx:expr, $block:expr) => {
        match $block.await {
            Ok(val) => {
                tracing::debug!("committing database transaction");
                $tx.commit()
                    .await
                    .map_err(crate::handlers::Error::DatabaseClientFailed)?;
                Ok(val)
            }
            Err(err) => {
                tracing::debug!("rollbacking database transaction");
                if let Err(err) = $tx.rollback().await {
                    let err = Error::DatabaseClientFailed(err);
                    tracing::error!("{err}");
                }
                Err(err)
            }
        }
    };
}

// Consts

const ROLE_JWT_CLAIM_KEY: &str = "role";

// Types

type Result<T> = StdResult<T, Error>;

// Enums

#[derive(Debug)]
enum Error {
    AuthenticatedUserNotFound(Uuid),
    DatabaseClientFailed(TokioPostgresError),
    DatabasePoolFailed(DeadpoolPostgresPoolError),
    EmptyQuery,
    ExpiredJwt,
    InvalidAuthorizationHeader(String),
    InvalidJwtSubject(Option<String>),
    JwtGenerationFailed(JwtError),
    JwtKeyGenerationFailed(HmacInvalidLength),
    JwtSignatureVerificationFailed(JwtError),
    MissingAuthorizationHeader,
    NoSpotifyToken,
    NoSpotifyUserEmail,
    QueryAlreadyExists(Uuid),
    QueryNotFound(Uuid),
    QueryNotOwnedByAuthenticatedUser(Uuid),
    SpotifyClientFailed(ClientError),
    SpotifyClientTokenLockFailed,
    TimestampConversionFailed(TryFromIntError),
}

// Impl - Error

impl Error {
    pub fn log(&self) {
        match self {
            Self::AuthenticatedUserNotFound(_) => debug!("{self}"),
            Self::EmptyQuery => debug!("{self}"),
            Self::ExpiredJwt => debug!("{self}"),
            Self::InvalidAuthorizationHeader(_) => debug!("{self}"),
            Self::InvalidJwtSubject(_) => debug!("{self}"),
            Self::JwtSignatureVerificationFailed(_) => debug!("{self}"),
            Self::MissingAuthorizationHeader => debug!("{self}"),
            Self::QueryAlreadyExists(_) => debug!("{self}"),
            Self::QueryNotFound(_) => debug!("{self}"),
            Self::QueryNotOwnedByAuthenticatedUser(_) => debug!("{self}"),
            _ => error!("{self}"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AuthenticatedUserNotFound(id) => write!(f, "user {id} doesn't exist anymore"),
            Self::DatabaseClientFailed(err) => write!(f, "database client error: {err}"),
            Self::DatabasePoolFailed(err) => write!(f, "database client pool error: {err}"),
            Self::EmptyQuery => write!(f, "query should contain at least one filter or grouping"),
            Self::ExpiredJwt => write!(f, "JWT is expired"),
            Self::InvalidAuthorizationHeader(val) => {
                write!(f, "invalid {} header value: `{val}`", header::AUTHORIZATION)
            }
            Self::InvalidJwtSubject(subj) => match subj {
                Some(subj) => write!(f, "`{subj}` is not a valid JWT subject"),
                None => write!(f, "no subject in JWT"),
            },
            Self::JwtGenerationFailed(err) => write!(f, "JWT generation failed: {err}"),
            Self::JwtKeyGenerationFailed(err) => write!(f, "JWT key generation failed: {err}"),
            Self::JwtSignatureVerificationFailed(err) => {
                write!(f, "JWT signature verification failed: {err}")
            }
            Self::MissingAuthorizationHeader => write!(
                f,
                "request doesn't contain {} header",
                header::AUTHORIZATION
            ),
            Self::NoSpotifyToken => write!(f, "Spotify client doesn't have token"),
            Self::NoSpotifyUserEmail => write!(f, "Spotify user doesn't have email"),
            Self::QueryAlreadyExists(id) => write!(f, "similar query already exists with ID {id}"),
            Self::QueryNotFound(id) => write!(f, "query {id} doesn't exist"),
            Self::QueryNotOwnedByAuthenticatedUser(id) => {
                write!(f, "query {id} is not owned by authenticated user")
            }
            Self::SpotifyClientFailed(err) => write!(f, "Spotify error: {err}"),
            Self::SpotifyClientTokenLockFailed => {
                write!(f, "unable to acquire lock on Spotify client token")
            }
            Self::TimestampConversionFailed(err) => write!(f, "timestamp conversion failed: {err}"),
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::AuthenticatedUserNotFound(_) => HttpResponse::Unauthorized().into(),
            Self::EmptyQuery => {
                HttpResponse::PreconditionFailed().json(PreconditionFailedResponse {
                    detail: self.to_string(),
                })
            }
            Self::ExpiredJwt => HttpResponse::Unauthorized().into(),
            Self::InvalidAuthorizationHeader(_) => HttpResponse::Unauthorized().into(),
            Self::InvalidJwtSubject(_) => HttpResponse::Unauthorized().into(),
            Self::JwtSignatureVerificationFailed(_) => HttpResponse::Unauthorized().into(),
            Self::MissingAuthorizationHeader => HttpResponse::Unauthorized().into(),
            Self::QueryAlreadyExists(id) => {
                HttpResponse::Conflict().json(ConflictResponse { id: *id })
            }
            Self::QueryNotFound(_) => HttpResponse::NotFound().into(),
            Self::QueryNotOwnedByAuthenticatedUser(_) => HttpResponse::Forbidden().into(),
            _ => HttpResponse::InternalServerError().into(),
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuthenticatedUserNotFound(_) => StatusCode::UNAUTHORIZED,
            Self::EmptyQuery => StatusCode::PRECONDITION_FAILED,
            Self::ExpiredJwt => StatusCode::UNAUTHORIZED,
            Self::InvalidAuthorizationHeader(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidJwtSubject(_) => StatusCode::UNAUTHORIZED,
            Self::JwtSignatureVerificationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::MissingAuthorizationHeader => StatusCode::UNAUTHORIZED,
            Self::QueryAlreadyExists(_) => StatusCode::CONFLICT,
            Self::QueryNotFound(_) => StatusCode::NOT_FOUND,
            Self::QueryNotOwnedByAuthenticatedUser(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AuthenticatedUserNotFound(_) => None,
            Self::DatabaseClientFailed(err) => Some(err),
            Self::DatabasePoolFailed(err) => Some(err),
            Self::EmptyQuery => None,
            Self::ExpiredJwt => None,
            Self::InvalidAuthorizationHeader(_) => None,
            Self::InvalidJwtSubject(_) => None,
            Self::JwtGenerationFailed(err) => Some(err),
            Self::JwtKeyGenerationFailed(err) => Some(err),
            Self::JwtSignatureVerificationFailed(err) => Some(err),
            Self::MissingAuthorizationHeader => None,
            Self::NoSpotifyToken => None,
            Self::NoSpotifyUserEmail => None,
            Self::QueryAlreadyExists(_) => None,
            Self::QueryNotFound(_) => None,
            Self::QueryNotOwnedByAuthenticatedUser(_) => None,
            Self::SpotifyClientFailed(err) => Some(err),
            Self::SpotifyClientTokenLockFailed => None,
            Self::TimestampConversionFailed(err) => Some(err),
        }
    }
}

// Functions - Utils

#[inline]
async fn current_user(
    req: &HttpRequest,
    cfg: &JwtConfig,
    db_client: &TokioPostgresClient,
) -> Result<User> {
    trace!("parsing {} header", header::AUTHORIZATION);
    let val = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(Error::MissingAuthorizationHeader)?;
    let val = String::from_utf8_lossy(val.as_bytes());
    let re = Regex::new(r"^\s*(?i)(bearer)\s+(.+)$").unwrap();
    let caps = re
        .captures(&val)
        .ok_or_else(|| Error::InvalidAuthorizationHeader(val.to_string()))?;
    let jwt = caps
        .get(2)
        .ok_or_else(|| Error::InvalidAuthorizationHeader(val.to_string()))?;
    let key = generate_jwt_key(cfg)?;
    debug!("verifying JWT signature");
    let claims: Claims = jwt
        .as_str()
        .verify_with_key(&key)
        .map_err(Error::JwtSignatureVerificationFailed)?;
    let now_ts: u64 = Utc::now()
        .timestamp()
        .try_into()
        .map_err(Error::TimestampConversionFailed)?;
    if let Some(exp_ts) = claims.registered.expiration {
        if exp_ts < now_ts {
            return Err(Error::ExpiredJwt);
        }
    } else {
        debug!("JWT doesn't contain `exp` claim entry");
        return Err(Error::ExpiredJwt);
    }
    let subj = claims
        .registered
        .subject
        .ok_or_else(|| Error::InvalidJwtSubject(None))?;
    let id: Uuid = subj
        .parse()
        .map_err(|_| Error::InvalidJwtSubject(Some(subj)))?;
    user_by_id(&id, db_client)
        .await
        .map_err(Error::DatabaseClientFailed)?
        .ok_or_else(|| Error::AuthenticatedUserNotFound(id))
}

#[inline]
fn generate_jwt_key(cfg: &JwtConfig) -> Result<Hmac<Sha512>> {
    trace!("generating JWT signature key from secret");
    Hmac::new_from_slice(cfg.secret.as_bytes()).map_err(Error::JwtKeyGenerationFailed)
}

// Mods

pub mod auth;
pub mod query;
