use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_trim::string_trim;
use uuid::Uuid;

use crate::model::{
    PageRequest, Platform, Playlist, PlaylistSynchronization, Predicate, Role, Source, SourceKind,
    SourceSynchronization, Target, User,
};

// Consts - Paths

pub const PATH_ADMIN: &str = "/admin";
pub const PATH_AUTH: &str = "/auth";
pub const PATH_HEALTH: &str = "/health";
pub const PATH_ME: &str = "/me";
pub const PATH_PLAYLIST: &str = "/playlist";
pub const PATH_SEARCH: &str = "/search";
pub const PATH_SPOTIFY: &str = "/spotify";
pub const PATH_SRC: &str = "/source";
pub const PATH_SYNC: &str = "/sync";
pub const PATH_TOKEN: &str = "/token";
pub const PATH_USR: &str = "/user";

// Types

pub type ValidationResult = Result<(), ValidationErrorResponse>;

// Validate

pub trait Validate {
    fn validate(&self) -> ValidationResult;
}

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
    #[serde(deserialize_with = "string_trim")]
    pub name: String,
    pub platform: Platform,
    pub predicate: Predicate,
    pub src: SourceKind,
}

impl Validate for CreatePlaylistRequest {
    fn validate(&self) -> ValidationResult {
        let mut resp = ValidationErrorResponse::new();
        let len = self.name.len();
        if !(1..=100).contains(&len) {
            resp.errs
                .insert("name".into(), vec![ValidationErrorKind::Length(1, 100)]);
        }
        if let Err(predicate_resp) = self.predicate.validate() {
            resp.merge_with_prefix("predicate.", predicate_resp);
        }
        if resp.errs.is_empty() {
            Ok(())
        } else {
            Err(resp)
        }
    }
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

// RedirectUriQueryParam

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedirectUriQueryParam {
    pub redirect_uri: String,
}

// SearchQueryParam

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SearchQueryParam {
    pub q: String,
}

// SourceResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceResponse {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub kind: SourceKind,
    pub owner: UserResponse,
    pub sync: SourceSynchronization,
}

impl From<Source> for SourceResponse {
    fn from(src: Source) -> Self {
        Self {
            creation: src.creation,
            id: src.id,
            kind: src.kind,
            owner: src.owner.into(),
            sync: src.sync,
        }
    }
}

// UserResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub creation: DateTime<Utc>,
    pub email: String,
    pub id: Uuid,
    pub role: Role,
}

impl From<User> for UserResponse {
    fn from(usr: User) -> Self {
        Self {
            creation: usr.creation,
            email: usr.email,
            id: usr.id,
            role: usr.role,
        }
    }
}

// ValidationErrorKind

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationErrorKind {
    Length(usize, usize),
    StartAfterEnd,
}

// ValidationErrorResponse

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationErrorResponse {
    pub errs: HashMap<String, Vec<ValidationErrorKind>>,
}

impl ValidationErrorResponse {
    pub fn new() -> Self {
        Self {
            errs: HashMap::new(),
        }
    }

    pub fn merge_with_prefix(&mut self, prefix: &str, resp: Self) {
        for (k, v) in resp.errs {
            self.errs.insert(format!("{prefix}{k}"), v);
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use crate::model::{Role, SpotifySourceKind, Target, User};

    use super::*;

    // Mods

    mod create_playlist_request {
        use super::*;

        // Mods

        mod validate {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let req = CreatePlaylistRequest {
                    name: "name".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                };
                req.validate().expect("request should be valid");
            }

            #[test]
            fn resp() {
                let req = CreatePlaylistRequest {
                    name: "".into(),
                    platform: Platform::Spotify,
                    predicate: Predicate::ArtistsAre(Default::default()),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                };
                let resp = req.validate().expect_err("request should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter([
                        ("name".into(), vec![ValidationErrorKind::Length(1, 100)]),
                        (
                            "predicate.artistsAre".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                    ]),
                };
                assert_eq!(resp, expected);
            }
        }
    }

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
                    predicate: Predicate::YearIs(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
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

    mod source_response {
        use super::*;

        mod from_source {
            use super::*;

            #[test]
            fn response() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
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
                    owner: src.owner.clone().into(),
                    sync: src.sync.clone(),
                };
                let resp = SourceResponse::from(src);
                assert_eq!(resp, expected);
            }
        }
    }

    mod user_response {
        use super::*;

        mod from_user {
            use super::*;

            #[test]
            fn response() {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    email: "user@test".into(),
                    id: Uuid::new_v4(),
                    role: Role::User,
                };
                let expected = UserResponse {
                    creation: usr.creation,
                    email: usr.email.clone(),
                    id: usr.id,
                    role: usr.role,
                };
                let resp = UserResponse::from(usr);
                assert_eq!(resp, expected);
            }
        }
    }

    mod validation_error_response {
        use super::*;

        // Mods

        mod merge_with_prefix {
            use super::*;

            // Tests

            #[test]
            fn response() {
                let a = ValidationErrorResponse {
                    errs: HashMap::from_iter([(
                        "foo".into(),
                        vec![ValidationErrorKind::Length(1, 100)],
                    )]),
                };
                let mut b = ValidationErrorResponse {
                    errs: HashMap::from_iter([(
                        "b.foo".into(),
                        vec![ValidationErrorKind::Length(1, 50)],
                    )]),
                };
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter([
                        ("a.foo".into(), vec![ValidationErrorKind::Length(1, 100)]),
                        ("b.foo".into(), vec![ValidationErrorKind::Length(1, 50)]),
                    ]),
                };
                b.merge_with_prefix("a.", a);
                assert_eq!(b, expected);
            }
        }
    }
}
