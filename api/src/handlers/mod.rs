use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
};

use actix_web::{body::BoxBody, http::StatusCode, HttpResponse, Responder, ResponseError};
use rspotify::ClientError;
use tracing::error;

// Types

pub type Result<T> = StdResult<T, Error>;

// Enums

#[derive(Debug)]
pub enum Error {
    SpotifyClientFailed(ClientError),
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
            Self::SpotifyClientFailed(err) => write!(f, "Spotify error: {err}"),
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
            Self::SpotifyClientFailed(err) => Some(err),
        }
    }
}

// Functions

#[inline]
fn handle<F: Fn() -> Result<HttpResponse<BoxBody>>>(f: F) -> impl Responder {
    match f() {
        Ok(resp) => resp,
        Err(err) => {
            err.log();
            err.error_response()
        }
    }
}

// Mods

pub mod auth;
