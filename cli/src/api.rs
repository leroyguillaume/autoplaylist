use async_trait::async_trait;
use autoplaylist_common::{
    api::{
        AuthenticateViaSpotifyQueryParams, CreatePlaylistRequest, JwtResponse,
        PageRequestQueryParams, PlaylistResponse, RedirectUriQueryParam, SearchQueryParam,
        SourceResponse, UserResponse, PATH_ADMIN, PATH_AUTH_SPOTIFY, PATH_AUTH_SPOTIFY_TOKEN,
        PATH_PLAYLIST, PATH_SEARCH, PATH_SRC, PATH_SYNC, PATH_USR,
    },
    model::Page,
};
use reqwest::{
    header::{self, HeaderName, ToStrError},
    redirect::Policy,
    Client, ClientBuilder, Response, StatusCode,
};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{debug, debug_span, error, Instrument};
use uuid::Uuid;

// Types

pub type ApiResult<T> = Result<T, ApiError>;

// ApiError

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("API error ({status}): `{body}`")]
    Api { body: String, status: StatusCode },
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
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn authenticated_user_sources(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>>;

    async fn create_playlist(
        &self,
        req: &CreatePlaylistRequest,
        token: &str,
    ) -> ApiResult<PlaylistResponse>;

    async fn delete_playlist(&self, id: Uuid, token: &str) -> ApiResult<()>;

    async fn playlists(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn search_authenticated_user_playlists_by_name(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn search_playlists_by_name(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>>;

    async fn search_users_by_email(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<UserResponse>>;

    async fn sources(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>>;

    async fn spotify_authorize_url(&self, params: &RedirectUriQueryParam) -> ApiResult<String>;

    async fn start_playlist_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()>;

    async fn start_source_synchronization(&self, id: Uuid, token: &str) -> ApiResult<()>;

    async fn users(
        &self,
        params: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<UserResponse>>;
}

// DefautApiClient

pub struct DefaultApiClient {
    base_url: String,
}

impl DefaultApiClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    #[inline]
    async fn decode_text_response(resp: Response) -> String {
        resp.text().await.unwrap_or_else(|err| {
            error!(details = %err, "failed to decode response body");
            String::new()
        })
    }

    #[inline]
    async fn parse_json_response<T: DeserializeOwned>(resp: Response) -> ApiResult<T> {
        let status = resp.status();
        if status.is_success() {
            let resp: T = resp.json().await?;
            Ok(resp)
        } else {
            let body = Self::decode_text_response(resp).await;
            Err(ApiError::Api { body, status })
        }
    }

    #[inline]
    async fn parse_empty_response(resp: Response) -> ApiResult<()> {
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = Self::decode_text_response(resp).await;
            Err(ApiError::Api { body, status })
        }
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
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn authenticated_user_playlists(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!(
            "authenticated_user_playlists",
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            let url = format!("{}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn authenticated_user_sources(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>> {
        let span = debug_span!(
            "authenticated_user_sources",
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            let url = format!("{}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
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
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn delete_playlist(&self, id: Uuid, token: &str) -> ApiResult<()> {
        let span = debug_span!("delete_playlist", playlist.id = %id);
        async {
            let url = format!("{}{PATH_PLAYLIST}/{id}", self.base_url);
            debug!(url, "doing DELETE");
            let resp = Client::new().delete(&url).bearer_auth(token).send().await?;
            Self::parse_empty_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn playlists(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!(
            "playlists",
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_PLAYLIST}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn search_authenticated_user_playlists_by_name(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!(
            "search_authenticated_user_playlists_by_name",
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = params.q
        );
        async {
            let url = format!("{}{PATH_PLAYLIST}{PATH_SEARCH}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn search_playlists_by_name(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<PlaylistResponse>> {
        let span = debug_span!(
            "search_playlists_by_name",
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = params.q
        );
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_PLAYLIST}{PATH_SEARCH}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn search_users_by_email(
        &self,
        params: &SearchQueryParam,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<UserResponse>> {
        let span = debug_span!(
            "search_users_by_email",
            params.limit = req.limit,
            params.offset = req.offset,
            params.q = params.q
        );
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_USR}{PATH_SEARCH}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&params)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn sources(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<SourceResponse>> {
        let span = debug_span!(
            "sources",
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_SRC}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
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
                let body = Self::decode_text_response(resp).await;
                Err(ApiError::Api { body, status })
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
            Self::parse_empty_response(resp).await
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
            Self::parse_empty_response(resp).await
        }
        .instrument(span)
        .await
    }

    async fn users(
        &self,
        req: PageRequestQueryParams<25>,
        token: &str,
    ) -> ApiResult<Page<UserResponse>> {
        let span = debug_span!(
            "users",
            params.limit = req.limit,
            params.offset = req.offset,
        );
        async {
            let url = format!("{}{PATH_ADMIN}{PATH_USR}", self.base_url);
            debug!(url, "doing GET");
            let resp = Client::new()
                .get(&url)
                .bearer_auth(token)
                .query(&req)
                .send()
                .await?;
            Self::parse_json_response(resp).await
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
        model::{
            PageRequest, Predicate, Role, SourceKind, SpotifyResourceKind, Synchronization, Target,
        },
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
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .authenticated_user_playlists(req, "jwt")
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
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .authenticated_user_sources(req, "jwt")
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
                        owner: UserResponse {
                            creation: DateTime::parse_from_rfc3339("2022-01-02T00:00:00Z")
                                .expect("failed to parse date")
                                .into(),
                            email: "user@test".into(),
                            id: Uuid::from_u128(0x730ea2158aa44463a1379c4c71d50ed6),
                            role: Role::User,
                        },
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

        mod delete_playlist {
            use super::*;

            // Tests

            #[tokio::test]
            async fn no_content() {
                let id = Uuid::from_u128(0x2f3f13153bb74b3189c58bdffdb5e8de);
                let client = init();
                client
                    .delete_playlist(id, "jwt")
                    .await
                    .expect("failed to delete playlist");
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
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .playlists(req, "jwt")
                    .await
                    .expect("failed to get playlists");
                assert_eq!(resp, expected);
            }
        }

        mod search_authenticated_user_playlists_by_name {
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
                let params = SearchQueryParam { q: "name".into() };
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .search_authenticated_user_playlists_by_name(&params, req, "jwt")
                    .await
                    .expect("failed to get playlists");
                assert_eq!(resp, expected);
            }
        }

        mod search_playlists_by_name {
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
                let params = SearchQueryParam { q: "name".into() };
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .search_playlists_by_name(&params, req, "jwt")
                    .await
                    .expect("failed to get playlists");
                assert_eq!(resp, expected);
            }
        }

        mod search_users_by_email {
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
                let params = SearchQueryParam { q: "name".into() };
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .search_users_by_email(&params, req, "jwt")
                    .await
                    .expect("failed to get users");
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
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client
                    .sources(req, "jwt")
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
                let params = RedirectUriQueryParam {
                    redirect_uri: "http://localhost:8080/".into(),
                };
                let client = init();
                let url = client
                    .spotify_authorize_url(&params)
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

        mod users {
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
                let req = PageRequestQueryParams::from(expected.req);
                let client = init();
                let resp = client.users(req, "jwt").await.expect("failed to get users");
                assert_eq!(resp, expected);
            }
        }
    }
}
