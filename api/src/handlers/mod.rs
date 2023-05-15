use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    num::TryFromIntError,
    result::Result as StdResult,
};

use actix_web::{body::BoxBody, http::StatusCode, HttpResponse, ResponseError};
use deadpool_postgres::{
    tokio_postgres::Error as TokioPostgresError, PoolError as DeadpoolPostgresPoolError,
};
use hmac::digest::InvalidLength as HmacInvalidLength;
use jwt::Error as JwtError;
use rspotify::ClientError;
use tracing::error;

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

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums

#[derive(Debug)]
pub enum Error {
    DatabaseClientFailed(TokioPostgresError),
    DatabasePoolFailed(DeadpoolPostgresPoolError),
    JwtGenerationFailed(JwtError),
    JwtKeyGenerationFailed(HmacInvalidLength),
    NoSpotifyToken,
    NoSpotifyUserEmail,
    SpotifyClientFailed(ClientError),
    SpotifyClientTokenLockFailed,
    TimestampConversionFailed(TryFromIntError),
}

// Impl - Error

impl Error {
    pub fn log(&self) {
        error!("{self}");
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::DatabaseClientFailed(err) => write!(f, "database client error: {err}"),
            Self::DatabasePoolFailed(err) => write!(f, "database client pool error: {err}"),
            Self::JwtGenerationFailed(err) => write!(f, "JWT generation failed: {err}"),
            Self::JwtKeyGenerationFailed(err) => write!(f, "JWT key generation failed: {err}"),
            Self::NoSpotifyToken => write!(f, "Spotify client doesn't have token"),
            Self::NoSpotifyUserEmail => write!(f, "Spotify user doesn't have email"),
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
        HttpResponse::InternalServerError().into()
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::DatabaseClientFailed(err) => Some(err),
            Self::DatabasePoolFailed(err) => Some(err),
            Self::JwtGenerationFailed(err) => Some(err),
            Self::JwtKeyGenerationFailed(err) => Some(err),
            Self::NoSpotifyToken => None,
            Self::NoSpotifyUserEmail => None,
            Self::SpotifyClientFailed(err) => Some(err),
            Self::SpotifyClientTokenLockFailed => None,
            Self::TimestampConversionFailed(err) => Some(err),
        }
    }
}

// Mods

pub mod auth;
