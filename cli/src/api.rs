use async_trait::async_trait;
use autoplaylist_common::{
    api::{
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, JwtResponse,
        PageRequestQueryParams, PlaylistResponse, RedirectUriQueryParam, SourceResponse,
        PATH_ADMIN, PATH_AUTH_SPOTIFY, PATH_AUTH_SPOTIFY_TOKEN, PATH_PLAYLIST, PATH_SRC, PATH_SYNC,
    },
    model::Page,
};
use reqwest::{
    header::{self, HeaderName, ToStrError},
    redirect::Policy,
    Client, ClientBuilder, StatusCode,
};
use thiserror::Error;
use tracing::{debug, debug_span, Instrument};
use uuid::Uuid;

// Types

pub type ApiResult<T> = Result<T, ApiError>;

// ApiError

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("API error ({0})")]
    Api(StatusCode),
    #[error("failed to decode header: {0}")]
    HeaderDecoding(
        #[from]
        #[source]
        ToStrError,
    ),
    #[error("HTTP error: {0}")]
    Http(
        #[from]
        #[source]
        reqwest::Error,
    ),
    #[error("missing expected header `{0}`")]
    NoHeader(HeaderName),
}

// ApiClient

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ApiClient: Send + Sync {
    async fn authenticate_via_spotify(
        &self,
        params: &AuthenticateViaSpotifyQueryParams,
    ) -> ApiResult<JwtResponse>;

    async fn authenticated_user_playlists(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn authenticated_user_sources(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>>;

    async fn create_playlist(
        &self,
        req: &CreatePlaylistRequest,
        token: &str,
    ) -> ApiResult<PlaylistResponse>;

    async fn playlists(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn sources(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>>;

    async fn spotify_authorize_url(&self, param: &RedirectUriQueryParam) -> ApiResult<String>;

    async fn start_playlist_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()>;

    async fn start_source_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()>;
}

// DefautApiClient

pub struct DefaultApiClient {
    base_url: String,
}

impl DefaultApiClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

#[async_trait]
impl ApiClient for DefaultApiClient {
    async fn authenticate_via_spotify(
        &self,
        params: &AuthenticateViaSpotifyQueryParams,
    ) -> ApiResult<JwtResponse> {
        let span = debug_span!("authenticate_via_spotify", params.code, params.redirect_uri);
        async {
            let url = format!("{}{PATH_AUTH_SPOTIFY_TOKEN}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new().get(&url).query(params).send().await?;
            let status = resp.status();
            if status.is_success() {
                let resp: JwtResponse = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn authenticated_user_playlists(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!("authenticated_user_playlists", params.limit, params.offset);
        async {
            let url = format!("{}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                let resp: Page<PlaylistResponse> = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn authenticated_user_sources(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>> {
        let span = debug_span!("authenticated_user_sources", params.limit, params.offset);
        async {
            let url = format!("{}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                let resp: Page<SourceResponse> = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn create_playlist(
        &self,
        req: &CreatePlaylistRequest,
        token: &str,
    ) -> ApiResult<PlaylistResponse> {
        let span = debug_span!(
            "create_playlist",
            playlist.name = req.name,
            playlist.platform = %req.platform
        );
        async {
            let url = format!("{}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing POST");
            let resp = Client::new()
                .post(&url)
                .bearer_auth(token)
                .json(req)
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                let resp: PlaylistResponse = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn playlists(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!("playlists", params.limit, params.offset);
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                let resp: Page<PlaylistResponse> = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn sources(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>> {
        let span = debug_span!("sources", params.limit, params.offset);
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_SRC}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .send()
                .await?;
            let status = resp.status();
            if status.is_success() {
                let resp: Page<SourceResponse> = resp.json().await?;
                Ok(resp)
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn spotify_authorize_url(&self, params: &RedirectUriQueryParam) -> ApiResult<String> {
        let span = debug_span!("spotify_authorize_url", params.redirect_uri);
        async {
            let client = ClientBuilder::new().redirect(Policy::none()).build()?;
            let url = format!("{}{PATH_AUTH_SPOTIFY}", self.base_url);
            debug!(url, "doing GET");
            let resp = client.get(&url).query(params).send().await?;
            let status = resp.status();
            if status.is_redirection() {
                let headers = resp.headers();
                let loc = headers
                    .get(header::LOCATION)
                    .ok_or(ApiError::NoHeader(header::LOCATION))?;
                let url = loc.to_str()?;
                Ok(url.into())
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn start_playlist_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()> {
        let span = debug_span!("start_playlist_synchronization", playlist.id = %id);
        async {
            let url = format!("{}{PATH_PLAYLIST}/{id}{PATH_SYNC}", self.base_url);
            debug!(url, "doing PUT");
            let resp = Client::new().put(&url).bearer_auth(token).send().await?;
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }

    async fn start_source_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()> {
        let span = debug_span!("start_source_synchronization", src.id = %id);
        async {
            let url = format!("{}{PATH_SRC}/{id}{PATH_SYNC}", self.base_url);
            debug!(url, "doing PUT");
            let resp = Client::new().put(&url).bearer_auth(token).send().await?;
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(ApiError::Api(status))
            }
        }
        .instrument(span)
        .await
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::io::stderr;

    use autoplaylist_common::{
        api::Platform,
        api::SourceResponse,
        model::{PageRequest, Predicate, SourceKind, SpotifyResourceKind, Synchronization, Target},
        test_env_var, TracingConfig,
    };
    use chrono::DateTime;
    use mockable::DefaultEnv;
    use uuid::Uuid;

    use super::*;

    // init

    fn init() -> DefaultApiClient {
        TracingConfig::new("autoplaylist-api-client", stderr).init(&DefaultEnv);
        let base_url = test_env_var(
            "AUTOPLAYLIST_API_BASE_URL",
            "http://localhost:8081/autoplaylist",
        );
        DefaultApiClient::new(base_url)
    }

    // Mods

    mod default_api_client {
        use super::*;

        // Mods

        mod authenticate_via_spotify {
            use super::*;

            // Tests

            #[tokio::test]
            async fn jwt() {
                let params = AuthenticateViaSpotifyQueryParams {
                    code: "code".into(),
                    redirect_uri: "http://localhost:8080/".into(),
                };
                let client = init();
                let resp = client
                    .authenticate_via_spotify(&params)
                    .await
                    .expect("failed to get JWT");
                assert_eq!(resp.jwt, "jwt");
            }
        }

        mod authenticated_user_playlists {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(10, 0),
                    total: 0,
                };
                let params = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .authenticated_user_playlists(params, "jwt")
                    .await
                    .expect("failed to get playlists");
                assert_eq!(resp, expected);
            }
        }

        mod authenticated_user_sources {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(10, 0),
                    total: 0,
                };
                let params = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .authenticated_user_sources(params, "jwt")
                    .await
                    .expect("failed to get sources");
                assert_eq!(resp, expected);
            }
        }

        mod create_playlist {
            use super::*;

            // Tests

            #[tokio::test]
            async fn playlist() {
                let req = CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearEquals(1993),
                    src: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                };
                let expected = PlaylistResponse {
                    creation: DateTime::parse_from_rfc3339("2023-01-02T00:00:10Z")
                        .expect("failed to parse date")
                        .into(),
                    id: Uuid::from_u128(0xf28c11c3bfeb4583ba1646797f662b9a),
                    name: req.name.clone(),
                    predicate: req.predicate.clone(),
                    src: SourceResponse {
                        creation: DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
                            .expect("failed to parse date")
                            .into(),
                        id: Uuid::from_u128(0x2f3f13153bb74b3189c58bdffdb5e8de),
                        kind: req.src.clone(),
                        owner: Uuid::from_u128(0x730ea2158aa44463a1379c4c71d50ed6),
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let client = init();
                let resp = client
                    .create_playlist(&req, "jwt")
                    .await
                    .expect("failed to create playlist");
                assert_eq!(resp, expected);
            }
        }

        mod playlists {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(10, 0),
                    total: 0,
                };
                let params = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .playlists(params, "jwt")
                    .await
                    .expect("failed to get playlists");
                assert_eq!(resp, expected);
            }
        }

        mod sources {
            use super::*;

            // Tests

            #[tokio::test]
            async fn page() {
                let expected = Page {
                    first: true,
                    items: vec![],
                    last: true,
                    req: PageRequest::new(10, 0),
                    total: 0,
                };
                let params = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .sources(params, "jwt")
                    .await
                    .expect("failed to get sources");
                assert_eq!(resp, expected);
            }
        }

        mod spotify_authorize_url {
            use super::*;

            // Tests

            #[tokio::test]
            async fn url() {
                let param = RedirectUriQueryParam {
                    redirect_uri: "http://localhost:8080/".into(),
                };
                let client = init();
                let url = client
                    .spotify_authorize_url(&param)
                    .await
                    .expect("failed to get Spotify authorize URL");
                assert_eq!(url, "http://localhost:8081/spotify/auth");
            }
        }

        mod start_playlist_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn no_content() {
                let id = Uuid::from_u128(0x2f3f13153bb74b3189c58bdffdb5e8de);
                let client = init();
                client
                    .start_playlist_synchronization(id, "jwt")
                    .await
                    .expect("failed to start playlist synchronization");
            }
        }

        mod start_source_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn no_content() {
                let id = Uuid::from_u128(0x2f3f13153bb74b3189c58bdffdb5e8de);
                let client = init();
                client
                    .start_source_synchronization(id, "jwt")
                    .await
                    .expect("failed to start source synchronization");
            }
        }
    }
}
