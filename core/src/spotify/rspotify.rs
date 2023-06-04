use std::{
    collections::HashSet,
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
};

use async_trait::async_trait;
use chrono::Utc;
use rspotify::{prelude::OAuthClient, AuthCodeSpotify, ClientError, Credentials, OAuth, Token};
use securefmt::Debug;
use tracing::{debug, trace};

use crate::{domain::SpotifyToken, env_var, ConfigError};

use super::{Client, Result};

// Consts

const SCOPES: [&str; 14] = [
    "playlist-modify-private",
    "playlist-modify-public",
    "playlist-read-collaborative",
    "playlist-read-private",
    "user-follow-read",
    "user-library-read",
    "user-modify-playback-state",
    "user-read-currently-playing",
    "user-read-playback-position",
    "user-read-playback-state",
    "user-read-recently-played",
    "user-read-email",
    "user-read-private",
    "user-top-read",
];

// Error

#[derive(Debug)]
pub enum Error {
    Client(ClientError),
    NoEmail,
    NoToken,
    TokenLock,
}

impl Error {
    fn client_boxed(err: ClientError) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::Client(err))
    }

    fn no_email_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::NoEmail)
    }

    fn no_token_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::NoToken)
    }

    fn token_lock_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::TokenLock)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Client(err) => write!(f, "Spotify client failed: {err}"),
            Self::NoEmail => write!(f, "Spotify user doesn't have email"),
            Self::NoToken => write!(f, "no Spotify token"),
            Self::TokenLock => write!(f, "locking mutex of Spotify token failed"),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match self {
            Self::Client(err) => Some(err),
            Self::NoEmail => None,
            Self::NoToken => None,
            Self::TokenLock => None,
        }
    }
}

// Config

#[derive(Debug, Clone)]
pub struct Config {
    pub id: String,
    pub redirect_uri: String,
    #[sensitive]
    pub secret: String,
}

impl Config {
    pub fn from_env() -> StdResult<Self, ConfigError> {
        trace!("loading Spotify configuration");
        let webapp_url: String = env_var("WEBAPP_URL")?;
        let cfg = Self {
            id: env_var("SPOTIFY_CLIENT_ID")?,
            redirect_uri: format!("{webapp_url}/auth/spotify"),
            secret: env_var("SPOTIFY_CLIENT_SECRET")?,
        };
        trace!("Spotify configuration loaded: {cfg:?}");
        Ok(cfg)
    }
}

// Token

impl From<SpotifyToken> for Token {
    fn from(token: SpotifyToken) -> Self {
        Self {
            access_token: token.access_token,
            expires_in: Utc::now() - token.expiration_date,
            expires_at: Some(token.expiration_date),
            refresh_token: token.refresh_token,
            scopes: HashSet::from_iter(SCOPES.map(|scope| scope.into())),
        }
    }
}

// SpotifyToken

impl From<Token> for SpotifyToken {
    fn from(token: Token) -> Self {
        Self {
            access_token: token.access_token,
            expiration_date: token
                .expires_at
                .unwrap_or_else(|| Utc::now() + token.expires_in),
            refresh_token: token.refresh_token,
        }
    }
}

// RSpotifyClient

pub struct RSpotifyClient {
    creds: Credentials,
    oauth: OAuth,
}

impl RSpotifyClient {
    pub fn new(cfg: Config) -> Self {
        Self {
            creds: Credentials {
                id: cfg.id,
                secret: Some(cfg.secret),
            },
            oauth: OAuth {
                redirect_uri: cfg.redirect_uri,
                scopes: HashSet::from_iter(SCOPES.map(|scope| scope.into())),
                ..Default::default()
            },
        }
    }

    #[inline]
    async fn oauth_client(&self, token: Option<&SpotifyToken>) -> Result<AuthCodeSpotify> {
        let client = AuthCodeSpotify::new(self.creds.clone(), self.oauth.clone());
        if let Some(token) = token {
            let mut client_token = client
                .token
                .lock()
                .await
                .map_err(|_| Error::token_lock_boxed())?;
            *client_token = Some(token.clone().into());
        }
        Ok(client)
    }
}

#[async_trait]
impl Client for RSpotifyClient {
    async fn auth_url(&self) -> Result<String> {
        let client = self.oauth_client(None).await?;
        trace!("computing Spoitfy authentication URL");
        client.get_authorize_url(false).map_err(Error::client_boxed)
    }

    async fn request_token(&self, code: &str) -> Result<SpotifyToken> {
        let client = self.oauth_client(None).await?;
        debug!("requesting Spotify token from code {code}");
        client
            .request_token(code)
            .await
            .map_err(Error::client_boxed)?;
        let token = client
            .token
            .lock()
            .await
            .map_err(|_| Error::token_lock_boxed())?
            .as_ref()
            .ok_or_else(Error::no_token_boxed)?
            .clone();
        Ok(token.into())
    }

    async fn user_email(&self, token: &SpotifyToken) -> Result<String> {
        let client = self.oauth_client(Some(token)).await?;
        debug!("fetching Spotify user");
        let user = client.current_user().await.map_err(Error::client_boxed)?;
        user.email.ok_or_else(Error::no_email_boxed)
    }
}
