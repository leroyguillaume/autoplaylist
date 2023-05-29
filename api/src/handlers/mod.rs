use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    num::TryFromIntError,
    result::Result as StdResult,
};

use actix_web::{
    body::BoxBody,
    http::{header, StatusCode},
    HttpRequest, HttpResponse, HttpResponseBuilder, ResponseError,
};
use autoplaylist_core::{
    broker::Error as BrokerError,
    db::{InTransactionError, UserRepository},
    domain::User,
};
use chrono::Utc;
use hmac::{digest::InvalidLength as HmacInvalidLength, Hmac, Mac};
use jwt::{Claims, Error as JwtError, VerifyWithKey};
use regex::Regex;
use rspotify::ClientError;
use sha2::Sha512;
use tracing::{debug, trace};
use uuid::Uuid;
use validator::ValidationErrors;

use crate::{cfg::JwtConfig, dto::ConflictResponse};

// Consts

const ROLE_JWT_CLAIM_KEY: &str = "role";

// Types

type Result<T> = StdResult<T, Error>;

// Enums

#[derive(Debug)]
enum Error {
    AuthenticatedUserIsNotAdmin(Uuid),
    AuthenticatedUserNotFound(Uuid),
    BrokerClient(BrokerError),
    DatabaseClient(Box<dyn StdError + Send + Sync>),
    DatabasePool(Box<dyn StdError + Send + Sync>),
    ExpiredJwt,
    InvalidAuthorizationHeader(String),
    InvalidJwtSubject(Option<String>),
    JwtGeneration(JwtError),
    JwtKeyGeneration(HmacInvalidLength),
    JwtSignatureVerification(JwtError),
    MissingAuthorizationHeader,
    NoSpotifyToken,
    NoSpotifyUserEmail,
    PlaylistAlreadyExists(Uuid),
    PlaylistNotFound(Uuid),
    PlaylistNotOwnedByAuthenticatedUser(Uuid),
    RequestValidation(ValidationErrors),
    SpotifyClient(ClientError),
    SpotifyClientTokenLock,
    TimestampConversion(TryFromIntError),
}

// Impl - Error

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AuthenticatedUserIsNotAdmin(id) => write!(f, "user {id} is not admin"),
            Self::AuthenticatedUserNotFound(id) => write!(f, "user {id} doesn't exist anymore"),
            Self::BrokerClient(err) => write!(f, "{err}"),
            Self::DatabaseClient(err) => write!(f, "{err}"),
            Self::DatabasePool(err) => write!(f, "database connection pool error: {err}"),
            Self::ExpiredJwt => write!(f, "JWT is expired"),
            Self::InvalidAuthorizationHeader(val) => {
                write!(f, "invalid {} header value: `{val}`", header::AUTHORIZATION)
            }
            Self::InvalidJwtSubject(subj) => match subj {
                Some(subj) => write!(f, "`{subj}` is not a valid JWT subject"),
                None => write!(f, "no subject in JWT"),
            },
            Self::JwtGeneration(err) => write!(f, "JWT generation failed: {err}"),
            Self::JwtKeyGeneration(err) => write!(f, "JWT key generation failed: {err}"),
            Self::JwtSignatureVerification(err) => {
                write!(f, "JWT signature verification failed: {err}")
            }
            Self::MissingAuthorizationHeader => write!(
                f,
                "request doesn't contain {} header",
                header::AUTHORIZATION
            ),
            Self::NoSpotifyToken => write!(f, "Spotify client doesn't have token"),
            Self::NoSpotifyUserEmail => write!(f, "Spotify user doesn't have email"),
            Self::PlaylistAlreadyExists(id) => {
                write!(f, "similar playlist already exists with ID {id}")
            }
            Self::PlaylistNotFound(id) => write!(f, "playlist {id} doesn't exist"),
            Self::PlaylistNotOwnedByAuthenticatedUser(id) => {
                write!(f, "playlist {id} is not owned by authenticated user")
            }
            Self::RequestValidation(_) => write!(f, "request validation failed"),
            Self::SpotifyClient(err) => write!(f, "Spotify error: {err}"),
            Self::SpotifyClientTokenLock => {
                write!(f, "acquiring lock on Spotify client token failed")
            }
            Self::TimestampConversion(err) => write!(f, "timestamp conversion failed: {err}"),
        }
    }
}

impl From<InTransactionError<Error>> for Error {
    fn from(err: InTransactionError<Error>) -> Self {
        match err {
            InTransactionError::Client(err) => Error::DatabaseClient(err),
            InTransactionError::Execution(err) => err,
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        let status = self.status_code();
        match self {
            Self::PlaylistAlreadyExists(id) => {
                HttpResponseBuilder::new(status).json(ConflictResponse { id: *id })
            }
            Self::RequestValidation(errs) => HttpResponseBuilder::new(status).json(errs),
            _ => HttpResponse::new(status),
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuthenticatedUserIsNotAdmin(_) => StatusCode::FORBIDDEN,
            Self::AuthenticatedUserNotFound(_) => StatusCode::UNAUTHORIZED,
            Self::ExpiredJwt => StatusCode::UNAUTHORIZED,
            Self::InvalidAuthorizationHeader(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidJwtSubject(_) => StatusCode::UNAUTHORIZED,
            Self::JwtSignatureVerification(_) => StatusCode::UNAUTHORIZED,
            Self::MissingAuthorizationHeader => StatusCode::UNAUTHORIZED,
            Self::PlaylistAlreadyExists(_) => StatusCode::CONFLICT,
            Self::PlaylistNotFound(_) => StatusCode::NOT_FOUND,
            Self::PlaylistNotOwnedByAuthenticatedUser(_) => StatusCode::FORBIDDEN,
            Self::RequestValidation(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AuthenticatedUserIsNotAdmin(_) => None,
            Self::AuthenticatedUserNotFound(_) => None,
            Self::BrokerClient(err) => Some(err),
            Self::DatabaseClient(err) => Some(err.as_ref()),
            Self::DatabasePool(err) => Some(err.as_ref()),
            Self::ExpiredJwt => None,
            Self::InvalidAuthorizationHeader(_) => None,
            Self::InvalidJwtSubject(_) => None,
            Self::JwtGeneration(err) => Some(err),
            Self::JwtKeyGeneration(err) => Some(err),
            Self::JwtSignatureVerification(err) => Some(err),
            Self::MissingAuthorizationHeader => None,
            Self::NoSpotifyToken => None,
            Self::NoSpotifyUserEmail => None,
            Self::PlaylistAlreadyExists(_) => None,
            Self::PlaylistNotFound(_) => None,
            Self::PlaylistNotOwnedByAuthenticatedUser(_) => None,
            Self::RequestValidation(errs) => Some(errs),
            Self::SpotifyClient(err) => Some(err),
            Self::SpotifyClientTokenLock => None,
            Self::TimestampConversion(err) => Some(err),
        }
    }
}

// Functions - Utils

#[inline]
async fn current_user(
    req: &HttpRequest,
    cfg: &JwtConfig,
    user_repo: &dyn UserRepository,
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
        .map_err(Error::JwtSignatureVerification)?;
    let now_ts: u64 = Utc::now()
        .timestamp()
        .try_into()
        .map_err(Error::TimestampConversion)?;
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
    user_repo
        .get_by_id(&id)
        .await
        .map_err(Error::DatabaseClient)?
        .ok_or_else(|| Error::AuthenticatedUserNotFound(id))
}

#[inline]
fn generate_jwt_key(cfg: &JwtConfig) -> Result<Hmac<Sha512>> {
    trace!("generating JWT signature key from secret");
    Hmac::new_from_slice(cfg.secret.as_bytes()).map_err(Error::JwtKeyGeneration)
}

// Mods

pub mod auth;
pub mod base;
pub mod playlist;
