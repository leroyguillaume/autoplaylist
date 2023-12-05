use chrono::{DateTime, Utc};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{
    PageRequest, Playlist, PlaylistSynchronization, Predicate, Source, SourceKind,
    SourceSynchronization, Target,
};

// Consts - Paths

pub const PATH_ADMIN: &str = "/admin";
pub const PATH_AUTH_SPOTIFY: &str = "/auth/spotify";
pub const PATH_AUTH_SPOTIFY_TOKEN: &str = "/auth/spotify/token";
pub const PATH_HEALTH: &str = "/health";
pub const PATH_PLAYLIST: &str = "/playlist";
pub const PATH_SEARCH: &str = "/search";
pub const PATH_SRC: &str = "/source";
pub const PATH_SYNC: &str = "/sync";

// AuthenticateViaSpotifyQueryParams

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticateViaSpotifyQueryParams {
    pub code: String,
    pub redirect_uri: String,
}

// CreatePlaylistRequest

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePlaylistRequest {
    pub name: String,
    pub platform: Platform,
    pub predicate: Predicate,
    pub src: SourceKind,
}

// PageRequest

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageRequestQueryParams<const LIMIT: u32> {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

impl<const LIMIT: u32> From<PageRequest> for PageRequestQueryParams<LIMIT> {
    fn from(req: PageRequest) -> Self {
        Self {
            limit: Some(req.limit),
            offset: Some(req.offset),
        }
    }
}

// Platform

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
pub enum Platform {
    Spotify,
}

// PlaylistResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistResponse {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub name: String,
    pub predicate: Predicate,
    pub src: SourceResponse,
    pub sync: PlaylistSynchronization,
    pub tgt: Target,
}

impl From<Playlist> for PlaylistResponse {
    fn from(playlist: Playlist) -> Self {
        Self {
            creation: playlist.creation,
            id: playlist.id,
            name: playlist.name,
            predicate: playlist.predicate,
            src: playlist.src.into(),
            sync: playlist.sync,
            tgt: playlist.tgt,
        }
    }
}

// JwtResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtResponse {
    pub jwt: String,
}

impl From<String> for JwtResponse {
    fn from(jwt: String) -> Self {
        Self { jwt }
    }
}

// QQueryParam

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QQueryParam {
    pub q: String,
}

// RedirectUriQueryParam

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedirectUriQueryParam {
    pub redirect_uri: String,
}

impl From<String> for RedirectUriQueryParam {
    fn from(redirect_uri: String) -> Self {
        Self { redirect_uri }
    }
}

// SourceResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceResponse {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub kind: SourceKind,
    pub owner: Uuid,
    pub sync: SourceSynchronization,
}

impl From<Source> for SourceResponse {
    fn from(src: Source) -> Self {
        Self {
            creation: src.creation,
            id: src.id,
            kind: src.kind,
            owner: src.owner.id,
            sync: src.sync,
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use crate::model::{Role, SpotifyResourceKind, Target, User};

    use super::*;

    mod page_request_query_params {
        use super::*;

        mod from_page_request {
            use super::*;

            // Tests

            #[test]
            fn params() {
                let req = PageRequest::new(1, 2);
                let expected = PageRequestQueryParams::<25> {
                    limit: Some(req.limit),
                    offset: Some(req.offset),
                };
                let params = PageRequestQueryParams::from(req);
                assert_eq!(params, expected);
            }
        }
    }

    mod playlist_response {
        use super::*;

        mod from_playlist {
            use super::*;

            #[test]
            fn response() {
                let playlist = Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".into(),
                    predicate: Predicate::YearEquals(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: SourceSynchronization::Pending,
                    },
                    sync: PlaylistSynchronization::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let expected = PlaylistResponse {
                    creation: playlist.creation,
                    id: playlist.id,
                    name: playlist.name.clone(),
                    predicate: playlist.predicate.clone(),
                    src: playlist.src.clone().into(),
                    sync: playlist.sync.clone(),
                    tgt: playlist.tgt.clone(),
                };
                let resp = PlaylistResponse::from(playlist);
                assert_eq!(resp, expected);
            }
        }
    }

    mod jwt_response {
        use super::*;

        mod from_string {
            use super::*;

            #[test]
            fn response() {
                let jwt = "jwt";
                let expected = JwtResponse { jwt: jwt.into() };
                let resp = JwtResponse::from(String::from(jwt));
                assert_eq!(resp, expected);
            }
        }
    }

    mod redirect_uri_param {
        use super::*;

        mod from_string {
            use super::*;

            #[test]
            fn param() {
                let redirect_uri = "uri";
                let expected = RedirectUriQueryParam {
                    redirect_uri: redirect_uri.into(),
                };
                let param = RedirectUriQueryParam::from(String::from(redirect_uri));
                assert_eq!(param, expected);
            }
        }
    }

    mod source_response {
        use super::*;

        mod from_source {
            use super::*;

            #[test]
            fn response() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: SourceSynchronization::Pending,
                };
                let expected = SourceResponse {
                    creation: src.creation,
                    id: src.id,
                    kind: src.kind.clone(),
                    owner: src.owner.id,
                    sync: src.sync.clone(),
                };
                let resp = SourceResponse::from(src);
                assert_eq!(resp, expected);
            }
        }
    }
}
