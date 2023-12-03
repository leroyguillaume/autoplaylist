use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::Utc;
use mockable::Env;
use rspotify::{
    model::{
        FullTrack, IdError, PlayableId, PlayableItem, PlaylistId, PlaylistItem, PrivateUser,
        SavedTrack, TrackId, UserId,
    },
    prelude::{BaseClient, Id, OAuthClient},
    scopes, AuthCodeSpotify, ClientError, Config, Credentials, OAuth, Token, DEFAULT_API_BASE_URL,
    DEFAULT_AUTH_BASE_URL,
};
use thiserror::Error;
use tracing::{debug, debug_span, trace, Instrument};

use crate::model::{Album, Page, PageRequest, SpotifyCredentials, SpotifyToken};

use super::{SpotifyClient, SpotifyError, SpotifyResult, SpotifyTrack, SpotifyUser};

// Consts - Env var keys

pub const ENV_VAR_KEY_SPOTIFY_API_BASE_URL: &str = "SPOTIFY_API_BASE_URL";
pub const ENV_VAR_KEY_SPOTIFY_AUTH_BASE_URL: &str = "SPOTIFY_AUTH_BASE_URL";
pub const ENV_VAR_KEY_SPOTIFY_CLIENT_ID: &str = "SPOTIFY_CLIENT_ID";
pub const ENV_VAR_KEY_SPOTIFY_CLIENT_SECRET: &str = "SPOTIFY_CLIENT_SECRET";

// Types

pub type RSpotifyMapResult<T> = Result<T, RSpotifyMapError>;
pub type RSpotifyResult<T> = Result<T, RSpotifyError>;

// RSpotifyConfigError

#[derive(Debug, Error)]
#[error("missing environment variable `{0}`")]
pub struct RSpotifyConfigError(&'static str);

// RSpotifyError

#[derive(Debug, Error)]
pub enum RSpotifyError {
    #[error("{0}")]
    Client(
        #[from]
        #[source]
        ClientError,
    ),
    #[error("failed to parse ID: {0}")]
    InvalidId(
        #[from]
        #[source]
        IdError,
    ),
    #[error("{0}")]
    Mapping(
        #[from]
        #[source]
        RSpotifyMapError,
    ),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("client doesn't contain token")]
    NoToken,
    #[error("failed to acquire lock on client token")]
    TokenLock,
}

// RSpotifyMapError

#[derive(Debug, Error)]
pub enum RSpotifyMapError {
    #[error("failed to parse date `{0}`")]
    DateParsing(String),
    #[error("playlist item is an episode")]
    Episode,
    #[error("missing field `{0}`")]
    MissingField(&'static str),
}

// RSpotifyConfig

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RSpotifyConfig {
    pub api_base_url: String,
    pub auth_base_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl RSpotifyConfig {
    pub fn from_env(env: &dyn Env) -> Result<Self, RSpotifyConfigError> {
        debug!("loading Spotify configuration");
        let api_base_url = env
            .string(ENV_VAR_KEY_SPOTIFY_API_BASE_URL)
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.into());
        let auth_base_url = env
            .string(ENV_VAR_KEY_SPOTIFY_AUTH_BASE_URL)
            .unwrap_or_else(|| DEFAULT_AUTH_BASE_URL.into());
        let client_id = env
            .string(ENV_VAR_KEY_SPOTIFY_CLIENT_ID)
            .ok_or(RSpotifyConfigError(ENV_VAR_KEY_SPOTIFY_CLIENT_ID))?;
        let client_secret = env
            .string(ENV_VAR_KEY_SPOTIFY_CLIENT_SECRET)
            .ok_or(RSpotifyConfigError(ENV_VAR_KEY_SPOTIFY_CLIENT_SECRET))?;
        Ok(Self {
            api_base_url,
            auth_base_url,
            client_id,
            client_secret,
        })
    }
}

// RSpotifyClient

pub struct RSpotifyClient {
    cfg: Config,
    creds: Credentials,
}

impl RSpotifyClient {
    pub fn new(cfg: RSpotifyConfig) -> Self {
        Self {
            cfg: Config {
                api_base_url: cfg.api_base_url,
                auth_base_url: cfg.auth_base_url,
                token_refreshing: true,
                ..Default::default()
            },
            creds: Credentials {
                id: cfg.client_id,
                secret: Some(cfg.client_secret),
            },
        }
    }

    #[inline]
    fn map_track_page<T: TryInto<SpotifyTrack, Error = RSpotifyMapError>>(
        page: rspotify::model::Page<T>,
        req: PageRequest,
    ) -> Page<SpotifyTrack> {
        let items = page
            .items
            .into_iter()
            .filter_map(|track| match track.try_into() {
                Ok(track) => Some(track),
                Err(err) => {
                    debug!(details = %err, "failed to parse track");
                    None
                }
            })
            .collect();
        Page {
            first: page.previous.is_none(),
            items,
            last: page.next.is_none(),
            req,
            total: page.total,
        }
    }

    #[inline]
    async fn api_client(&self, token: &SpotifyToken) -> RSpotifyResult<AuthCodeSpotify> {
        let mut client = AuthCodeSpotify::new(self.creds.clone(), OAuth::default());
        client.config = self.cfg.clone();
        trace!("acquiring lock on client token");
        let mut client_token = client
            .token
            .lock()
            .await
            .map_err(|_| RSpotifyError::TokenLock)?;
        *client_token = Some(token.clone().into());
        drop(client_token);
        Ok(client)
    }

    #[inline]
    fn auth_client(&self, redirect_uri: &str) -> AuthCodeSpotify {
        let oauth = OAuth {
            redirect_uri: redirect_uri.into(),
            scopes: scopes!(
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
                "user-top-read"
            ),
            ..Default::default()
        };
        AuthCodeSpotify::with_config(self.creds.clone(), oauth, self.cfg.clone())
    }

    #[inline]
    async fn token(&self, client: &AuthCodeSpotify) -> RSpotifyResult<SpotifyToken> {
        trace!("acquiring lock on client token");
        let token = client
            .token
            .lock()
            .await
            .map_err(|_| RSpotifyError::TokenLock)?;
        let token = token.as_ref().ok_or(RSpotifyError::NoToken)?;
        token.clone().try_into()
    }
}

#[async_trait]
impl SpotifyClient for RSpotifyClient {
    async fn add_tracks_to_playlist(
        &self,
        id: &str,
        tracks: &[String],
        token: &mut SpotifyToken,
    ) -> SpotifyResult<()> {
        let span = debug_span!("add_tracks_to_playlist", playlist.spotify_id = id,);
        async {
            let id = PlaylistId::from_id(id)?;
            let tracks = tracks
                .iter()
                .map(|id| TrackId::from_id(id).map(PlayableId::Track))
                .collect::<Result<Vec<_>, _>>()?;
            let client = self.api_client(token).await?;
            debug!("adding tracks to playlist");
            client.playlist_add_items(id, tracks, None).await?;
            *token = self.token(&client).await?;
            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn authenticate(&self, code: &str, redirect_uri: &str) -> SpotifyResult<SpotifyToken> {
        let span = debug_span!("authenticate", params.code = code,);
        async {
            let client = self.auth_client(redirect_uri);
            debug!("getting token");
            client.request_token(code).await?;
            let token = self.token(&client).await?;
            Ok(token)
        }
        .instrument(span)
        .await
    }

    async fn authenticated_user(&self, token: &mut SpotifyToken) -> SpotifyResult<SpotifyUser> {
        let span = debug_span!("authenticated_user",);
        async {
            let client = self.api_client(token).await?;
            debug!("getting authenticated user");
            let user = client.current_user().await?;
            *token = self.token(&client).await?;
            let user = user.try_into()?;
            Ok(user)
        }
        .instrument(span)
        .await
    }

    fn authorize_url(&self, redirect_uri: &str) -> SpotifyResult<String> {
        let client = self.auth_client(redirect_uri);
        let url = client.get_authorize_url(false)?;
        Ok(url)
    }

    async fn create_playlist(
        &self,
        name: &str,
        creds: &mut SpotifyCredentials,
    ) -> SpotifyResult<String> {
        let span = debug_span!(
            "create_playlist",
            playlist.name = name,
            playlist.spotify_owner = creds.id
        );
        async {
            let id = UserId::from_id(&creds.id)?;
            let client = self.api_client(&creds.token).await?;
            debug!("creating playlist");
            let playlist = client
                .user_playlist_create(id, name, None, None, None)
                .await?;
            creds.token = self.token(&client).await?;
            Ok(playlist.id.id().into())
        }
        .instrument(span)
        .await
    }

    async fn playlist_tracks(
        &self,
        id: &str,
        req: PageRequest,
        token: &mut SpotifyToken,
    ) -> SpotifyResult<Page<SpotifyTrack>> {
        let span = debug_span!(
            "playlist_tracks",
            params.limit = req.limit,
            params.offset = req.offset
        );
        async {
            let id = PlaylistId::from_id(id)?;
            let client = self.api_client(token).await?;
            debug!("getting playlist tracks");
            let page = client
                .playlist_items_manual(id, None, None, Some(req.limit), Some(req.offset))
                .await?;
            *token = self.token(&client).await?;
            let page = Self::map_track_page(page, req);
            Ok(page)
        }
        .instrument(span)
        .await
    }

    async fn remove_tracks_from_playlist(
        &self,
        id: &str,
        tracks: &[String],
        token: &mut SpotifyToken,
    ) -> SpotifyResult<()> {
        let span = debug_span!("remove_tracks_from_playlist", playlist.spotify_id = id,);
        async {
            let id = PlaylistId::from_id(id)?;
            let tracks = tracks
                .iter()
                .map(|id| TrackId::from_id(id).map(PlayableId::Track))
                .collect::<Result<Vec<_>, _>>()?;
            let client = self.api_client(token).await?;
            debug!("adding tracks to playlist");
            client
                .playlist_remove_all_occurrences_of_items(id, tracks, None)
                .await?;
            *token = self.token(&client).await?;
            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn saved_tracks(
        &self,
        req: PageRequest,
        token: &mut SpotifyToken,
    ) -> SpotifyResult<Page<SpotifyTrack>> {
        let span = debug_span!(
            "saved_tracks",
            params.limit = req.limit,
            params.offset = req.offset
        );
        async {
            let client = self.api_client(token).await?;
            debug!("getting current user saved tracks");
            let page = client
                .current_user_saved_tracks_manual(None, Some(req.limit), Some(req.offset))
                .await?;
            *token = self.token(&client).await?;
            let page = Self::map_track_page(page, req);
            Ok(page)
        }
        .instrument(span)
        .await
    }
}

// SpotifyError

impl From<ClientError> for SpotifyError {
    fn from(err: ClientError) -> Self {
        Self(Box::new(RSpotifyError::Client(err)))
    }
}

impl From<IdError> for SpotifyError {
    fn from(err: IdError) -> Self {
        Self(Box::new(RSpotifyError::InvalidId(err)))
    }
}

impl From<RSpotifyError> for SpotifyError {
    fn from(err: RSpotifyError) -> Self {
        Self(Box::new(err))
    }
}

impl From<RSpotifyMapError> for SpotifyError {
    fn from(err: RSpotifyMapError) -> Self {
        Self(Box::new(RSpotifyError::Mapping(err)))
    }
}

// SpotifyToken

impl TryFrom<Token> for SpotifyToken {
    type Error = RSpotifyError;

    fn try_from(token: Token) -> Result<Self, Self::Error> {
        Ok(Self {
            access: token.access_token,
            expiration: token
                .expires_at
                .ok_or(RSpotifyError::MissingField("expires_at"))?,
            refresh: token
                .refresh_token
                .ok_or(RSpotifyError::MissingField("refresh_token"))?,
        })
    }
}

// SpotifyTrack

impl TryFrom<FullTrack> for SpotifyTrack {
    type Error = RSpotifyMapError;

    fn try_from(track: FullTrack) -> RSpotifyMapResult<Self> {
        let album_type = track
            .album
            .album_type
            .ok_or(RSpotifyMapError::MissingField("album.album_type"))?;
        let artists: BTreeSet<String> = track
            .artists
            .into_iter()
            .map(|artist| artist.name)
            .collect();
        let id: String = track
            .id
            .ok_or(RSpotifyMapError::MissingField("id"))?
            .id()
            .into();
        let date = track
            .album
            .release_date
            .ok_or(RSpotifyMapError::MissingField("album.release_date"))?;
        let year = date
            .split('-')
            .next()
            .ok_or_else(|| RSpotifyMapError::DateParsing(date.clone()))?;
        let year: i32 = year
            .parse()
            .map_err(|_| RSpotifyMapError::DateParsing(date))?;
        Ok(Self {
            album: Album {
                compil: album_type == "compilation",
                name: track.album.name,
            },
            artists,
            id,
            title: track.name,
            year,
        })
    }
}

impl TryFrom<PlaylistItem> for SpotifyTrack {
    type Error = RSpotifyMapError;

    fn try_from(item: PlaylistItem) -> RSpotifyMapResult<Self> {
        match item.track {
            Some(PlayableItem::Episode(_)) => Err(RSpotifyMapError::Episode),
            Some(PlayableItem::Track(track)) => track.try_into(),
            None => Err(RSpotifyMapError::MissingField("track")),
        }
    }
}

impl TryFrom<SavedTrack> for SpotifyTrack {
    type Error = RSpotifyMapError;

    fn try_from(track: SavedTrack) -> RSpotifyMapResult<Self> {
        track.track.try_into()
    }
}

// SpotifyUser

impl TryFrom<PrivateUser> for SpotifyUser {
    type Error = RSpotifyMapError;

    fn try_from(user: PrivateUser) -> RSpotifyMapResult<Self> {
        Ok(Self {
            id: user.id.id().into(),
            email: user.email.ok_or(RSpotifyMapError::MissingField("email"))?,
        })
    }
}

// Token

impl From<SpotifyToken> for Token {
    fn from(token: SpotifyToken) -> Self {
        Self {
            access_token: token.access,
            expires_at: Some(token.expiration),
            expires_in: token.expiration - Utc::now(),
            refresh_token: Some(token.refresh),
            ..Default::default()
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::io::stderr;

    use mockable::{DefaultEnv, MockEnv};
    use mockall::predicate::eq;

    use crate::{test_env_var, TracingConfig};

    use super::*;

    // Consts - Data

    const REFRESH_TOKEN: &str = "refresh";
    const PLAYLIST_ID: &str = "7sTVJNSq4b3FmlTl79fAae";

    // assert_token_updated

    fn assert_token_updated(token: &SpotifyToken) {
        assert_eq!(token.access, "access_2");
        assert_eq!(token.refresh, REFRESH_TOKEN);
    }

    // init

    fn init() -> RSpotifyClient {
        TracingConfig::new("autoplaylist-common", stderr).init(&DefaultEnv);
        let cfg = RSpotifyConfig {
            api_base_url: test_env_var(
                ENV_VAR_KEY_SPOTIFY_API_BASE_URL,
                "http://localhost:8081/spotify/api",
            ),
            auth_base_url: test_env_var(
                ENV_VAR_KEY_SPOTIFY_API_BASE_URL,
                "http://localhost:8081/spotify/auth",
            ),
            client_id: "client_id".into(),
            client_secret: "client_secret".into(),
        };
        RSpotifyClient::new(cfg)
    }

    // token

    fn token() -> SpotifyToken {
        SpotifyToken {
            access: "access_1".into(),
            expiration: Utc::now(),
            refresh: REFRESH_TOKEN.into(),
        }
    }

    // tracks

    fn tracks() -> Vec<SpotifyTrack> {
        vec![
            SpotifyTrack {
                album: Album {
                    compil: false,
                    name: "Sparks".into(),
                },
                artists: BTreeSet::from_iter(["Roberta Loki".into()]),
                id: "5OKWAL4qNRUz28CBWEU411".into(),
                title: "Sparks".into(),
                year: 2023,
            },
            SpotifyTrack {
                album: Album {
                    compil: true,
                    name: "Singulier 81 - 89".into(),
                },
                artists: BTreeSet::from_iter([
                    "Jean-Jacques Goldman".into(),
                    "Michael Jones".into(),
                ]),
                id: "09ik0oFw7qwq88qY0AvsOy".into(),
                title: "Je te donne".into(),
                year: 1996,
            },
        ]
    }

    // Mods

    mod rspotify_config {
        use super::*;

        // Mods

        mod from_env {
            use super::*;

            // Params

            struct Params {
                api_base_url: Option<String>,
                auth_base_url: Option<String>,
                client_id: String,
                client_secret: String,
            }

            // mock_optional_string

            fn mock_optional_string(key: &'static str, val: Option<String>, mock: &mut MockEnv) {
                mock.expect_string()
                    .with(eq(key))
                    .times(1)
                    .return_const(val);
            }

            // mock_string

            fn mock_string(key: &'static str, val: String, mock: &mut MockEnv) {
                mock.expect_string()
                    .with(eq(key))
                    .times(1)
                    .returning(move |_| Some(val.clone()));
            }

            // run

            fn run(params: Params, expected: RSpotifyConfig) {
                let mut env = MockEnv::new();
                mock_optional_string(
                    ENV_VAR_KEY_SPOTIFY_API_BASE_URL,
                    params.api_base_url,
                    &mut env,
                );
                mock_optional_string(
                    ENV_VAR_KEY_SPOTIFY_AUTH_BASE_URL,
                    params.auth_base_url,
                    &mut env,
                );
                mock_string(ENV_VAR_KEY_SPOTIFY_CLIENT_ID, params.client_id, &mut env);
                mock_string(
                    ENV_VAR_KEY_SPOTIFY_CLIENT_SECRET,
                    params.client_secret,
                    &mut env,
                );
                let cfg =
                    RSpotifyConfig::from_env(&env).expect("failed to load Spotify configuration");
                assert_eq!(cfg, expected);
            }

            // Tests

            #[test]
            fn default() {
                let expected = RSpotifyConfig {
                    api_base_url: DEFAULT_API_BASE_URL.into(),
                    auth_base_url: DEFAULT_AUTH_BASE_URL.into(),
                    client_id: "client_id".into(),
                    client_secret: "client_secret".into(),
                };
                let params = Params {
                    api_base_url: None,
                    auth_base_url: None,
                    client_id: expected.client_id.clone(),
                    client_secret: expected.client_secret.clone(),
                };
                run(params, expected);
            }

            #[test]
            fn overriden() {
                let expected = RSpotifyConfig {
                    api_base_url: "api_base_url".into(),
                    auth_base_url: "auth_base_url".into(),
                    client_id: "client_id".into(),
                    client_secret: "client_secret".into(),
                };
                let params = Params {
                    api_base_url: Some(expected.api_base_url.clone()),
                    auth_base_url: Some(expected.auth_base_url.clone()),
                    client_id: expected.client_id.clone(),
                    client_secret: expected.client_secret.clone(),
                };
                run(params, expected);
            }
        }
    }

    mod rspotify_client {
        use super::*;

        // Mods

        mod add_tracks_to_playlist {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let mut token = token();
                let spotify = init();
                spotify
                    .add_tracks_to_playlist(
                        PLAYLIST_ID,
                        &[
                            "5OKWAL4qNRUz28CBWEU411".into(),
                            "09ik0oFw7qwq88qY0AvsOy".into(),
                        ],
                        &mut token,
                    )
                    .await
                    .expect("failed to add tracks to playlist");
                assert_token_updated(&token);
            }
        }

        mod authenticate {
            use super::*;

            // Tests

            #[tokio::test]
            async fn token() {
                let spotify = init();
                let token = spotify
                    .authenticate("code", "redirect_uri")
                    .await
                    .expect("failed to authenticate");
                assert_eq!(token.access, "access_1");
                assert_eq!(token.refresh, REFRESH_TOKEN);
            }
        }

        mod authenticated_user {
            use super::*;

            // Tests

            #[tokio::test]
            async fn user() {
                let mut token = token();
                let spotify = init();
                let user = spotify
                    .authenticated_user(&mut token)
                    .await
                    .expect("failed to fetch authenticated user");
                let expected = SpotifyUser {
                    id: "216m62jtruqgd6iaqx224jiqi".into(),
                    email: "user@test".into(),
                };
                assert_eq!(user, expected);
                assert_token_updated(&token);
            }
        }

        mod create_spotify_playlist {
            use super::*;

            // Tests

            #[tokio::test]
            async fn id() {
                let mut creds = SpotifyCredentials {
                    id: "216m62jtruqgd6iaqx224jiqi".into(),
                    token: token(),
                };
                let spotify = init();
                let id = spotify
                    .create_playlist("New Playlist", &mut creds)
                    .await
                    .expect("failed to create playlist");
                assert_eq!(id, "2jxT1I5apKDVKwz6sYuI3A");
                assert_token_updated(&creds.token);
            }
        }

        mod playlist_tracks {
            use super::*;

            // run

            async fn run(expected: Page<SpotifyTrack>) {
                let mut token = token();
                let spotify = init();
                let page = spotify
                    .playlist_tracks(PLAYLIST_ID, expected.req, &mut token)
                    .await
                    .expect("failed to fetch playlist tracks");
                assert_eq!(page, expected);
                assert_token_updated(&token);
            }

            // Tests

            #[tokio::test]
            async fn first_last() {
                let expected = Page {
                    first: true,
                    items: tracks(),
                    last: true,
                    req: PageRequest::new(50, 0),
                    total: 3,
                };
                run(expected).await;
            }

            #[tokio::test]
            async fn middle() {
                let expected = Page {
                    first: false,
                    items: tracks(),
                    last: false,
                    req: PageRequest::new(50, 50),
                    total: 100,
                };
                run(expected).await;
            }
        }

        mod remove_tracks_from_playlist {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let mut token = token();
                let spotify = init();
                spotify
                    .remove_tracks_from_playlist(
                        PLAYLIST_ID,
                        &[
                            "5OKWAL4qNRUz28CBWEU411".into(),
                            "09ik0oFw7qwq88qY0AvsOy".into(),
                        ],
                        &mut token,
                    )
                    .await
                    .expect("failed to remove tracks from playlist");
                assert_token_updated(&token);
            }
        }

        mod saved_tracks {
            use super::*;

            // run

            async fn run(expected: Page<SpotifyTrack>) {
                let mut token = token();
                let spotify = init();
                let page = spotify
                    .saved_tracks(expected.req, &mut token)
                    .await
                    .expect("failed to fetch saved tracks");
                assert_eq!(page, expected);
                assert_token_updated(&token);
            }

            // Tests

            #[tokio::test]
            async fn first_last() {
                let expected = Page {
                    first: true,
                    items: tracks(),
                    last: true,
                    req: PageRequest::new(50, 0),
                    total: 3,
                };
                run(expected).await;
            }

            #[tokio::test]
            async fn middle() {
                let expected = Page {
                    first: false,
                    items: tracks(),
                    last: false,
                    req: PageRequest::new(50, 50),
                    total: 100,
                };
                run(expected).await;
            }
        }
    }
}
