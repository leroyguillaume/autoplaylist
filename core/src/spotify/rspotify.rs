use std::{
    collections::HashSet,
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result as StdResult,
};

use async_trait::async_trait;
use chrono::Utc;
use rspotify::{
    model::{
        FullTrack, IdError, PlayableItem, PlaylistId, PlaylistItem, SavedTrack, SimplifiedArtist,
    },
    prelude::{BaseClient, OAuthClient},
    AuthCodeSpotify, ClientError, Credentials, OAuth, Token,
};
use securefmt::Debug;
use tracing::{debug, trace};

use crate::{
    domain::{Page, SpotifyArtist, SpotifyToken, SpotifyTrack},
    env_var, ConfigError,
};

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
    Id(IdError),
    NoEmail,
    NotATrack(String),
    MissingField(&'static str),
    NoToken,
    TokenLock,
}

impl Error {
    fn client_boxed(err: ClientError) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::Client(err))
    }

    fn id_boxed(err: IdError) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::Id(err))
    }

    fn missing_field_boxed(field: &'static str) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::MissingField(field))
    }

    fn no_email_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::NoEmail)
    }

    fn no_token_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::NoToken)
    }

    fn not_a_track_boxed(id: String) -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::NotATrack(id))
    }

    fn token_lock_boxed() -> Box<dyn StdError + Send + Sync> {
        Box::new(Self::TokenLock)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Client(err) => write!(f, "Spotify client failed: {err}"),
            Self::Id(err) => write!(f, "invalid Spotify ID: {err}"),
            Self::MissingField(field) => {
                write!(f, "playlist item doesn't contain required fied `{field}`")
            }
            Self::NoEmail => write!(f, "Spotify user doesn't have email"),
            Self::NoToken => write!(f, "no Spotify token"),
            Self::NotATrack(id) => write!(f, "Spotify resource {id} is not a track"),
            Self::TokenLock => write!(f, "locking mutex of Spotify token failed"),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match self {
            Self::Client(err) => Some(err),
            Self::Id(err) => Some(err),
            Self::MissingField(_) => None,
            Self::NoEmail => None,
            Self::NoToken => None,
            Self::NotATrack(_) => None,
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

// SpotifyArtist

impl From<SimplifiedArtist> for SpotifyArtist {
    fn from(artist: SimplifiedArtist) -> Self {
        Self {
            id: artist.id.map(|id| id.to_string()),
            name: artist.name,
        }
    }
}

// SpotifyTrack

impl TryFrom<PlaylistItem> for SpotifyTrack {
    type Error = Box<dyn StdError + Send + Sync>;

    fn try_from(item: PlaylistItem) -> Result<Self> {
        match item.track {
            Some(PlayableItem::Episode(episode)) => {
                Err(Error::not_a_track_boxed(episode.id.to_string()))
            }
            Some(PlayableItem::Track(track)) => Ok(track.into()),
            None => Err(Error::missing_field_boxed("track")),
        }
    }
}

impl From<FullTrack> for SpotifyTrack {
    fn from(track: FullTrack) -> Self {
        Self {
            artists: track.artists.into_iter().map(SpotifyArtist::from).collect(),
            id: track.id.map(|id| id.to_string()),
            name: track.name,
            release_date: track.album.release_date,
        }
    }
}

impl From<SavedTrack> for SpotifyTrack {
    fn from(track: SavedTrack) -> Self {
        track.track.into()
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
        let mut client = AuthCodeSpotify::new(self.creds.clone(), self.oauth.clone());
        client.config.token_refreshing = true;
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

    async fn playlist_tacks(
        &self,
        id: &str,
        limit: u32,
        offset: u32,
        token: &SpotifyToken,
    ) -> Result<Page<SpotifyTrack>> {
        let client = self.oauth_client(Some(token)).await?;
        debug!(
            "fetching Spotify playlist {id} tracks from offset {offset} limiting to {limit} results"
        );
        let playlist_id = PlaylistId::from_id(id).map_err(Error::id_boxed)?;
        let page = client
            .playlist_items_manual(playlist_id, None, None, Some(limit), Some(offset))
            .await
            .map_err(Error::client_boxed)?;
        debug!("page fetched: {page:?}");
        let items = page
            .items
            .into_iter()
            .map(SpotifyTrack::try_from)
            .collect::<Result<Vec<SpotifyTrack>>>()?;
        Ok(Page {
            is_last: page.next.is_none(),
            items,
            total: page.total,
        })
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

    async fn user_liked_tacks(
        &self,
        limit: u32,
        offset: u32,
        token: &SpotifyToken,
    ) -> Result<Page<SpotifyTrack>> {
        let client = self.oauth_client(Some(token)).await?;
        debug!(
            "fetching Spotify user liked tracks from offset {offset} limiting to {limit} results"
        );
        let page = client
            .current_user_saved_tracks_manual(None, Some(limit), Some(offset))
            .await
            .map_err(Error::client_boxed)?;
        debug!("page fetched: {page:?}");
        let items = page.items.into_iter().map(SpotifyTrack::from).collect();
        Ok(Page {
            is_last: page.next.is_none(),
            items,
            total: page.total,
        })
    }
}
