use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_trim::{btreeset_non_empty_string_trim, string_trim};
use uuid::Uuid;

use crate::model::{Album, PageRequest, Predicate, Role, SourceKind, Target};

// Consts - Paths

pub const PATH_AUTH: &str = "/auth";
pub const PATH_HEALTH: &str = "/health";
pub const PATH_PLAYLIST: &str = "/playlist";
pub const PATH_REFRESH: &str = "/refresh";
pub const PATH_SEARCH: &str = "/search";
pub const PATH_SPOTIFY: &str = "/spotify";
pub const PATH_SRC: &str = "/source";
pub const PATH_SYNC: &str = "/sync";
pub const PATH_TOKEN: &str = "/token";
pub const PATH_TRACK: &str = "/track";
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
    pub predicate: Predicate,
    pub src: SourceKind,
}

impl Validate for CreatePlaylistRequest {
    fn validate(&self) -> ValidationResult {
        validate_playlist_request(&self.name, &self.predicate)
    }
}

// CredentialsResponse

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsResponse {
    pub spotify: Option<SpotifyCredentialsResponse>,
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
    pub sync: SynchronizationResponse,
    pub tgt: Target,
}

// PreconditionFailedResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreconditionFailedResponse {
    pub details: String,
}

// JwtClaims

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtClaims {
    pub sub: Uuid,
    pub exp: i64,
    pub role: Role,
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

// SpotifyCredentialsResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotifyCredentialsResponse {
    pub email: String,
    pub id: String,
}

// SourceResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceResponse {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub kind: SourceKind,
    pub owner: UserResponse,
    pub sync: SynchronizationResponse,
}

// SynchronizationResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SynchronizationResponse {
    Aborted {
        end: DateTime<Utc>,
        start: DateTime<Utc>,
    },
    Failed {
        details: Option<String>,
        end: DateTime<Utc>,
        start: DateTime<Utc>,
    },
    Pending,
    Running(DateTime<Utc>),
    Succeeded {
        end: DateTime<Utc>,
        start: DateTime<Utc>,
    },
}

// UpdatePlaylistRequest

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlaylistRequest {
    #[serde(deserialize_with = "string_trim")]
    pub name: String,
    pub predicate: Predicate,
}

impl Validate for UpdatePlaylistRequest {
    fn validate(&self) -> ValidationResult {
        validate_playlist_request(&self.name, &self.predicate)
    }
}

// UpdateTrackRequest

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrackRequest {
    pub album: Album,
    #[serde(deserialize_with = "btreeset_non_empty_string_trim")]
    pub artists: BTreeSet<String>,
    #[serde(deserialize_with = "string_trim")]
    pub title: String,
    pub year: i32,
}

impl Validate for UpdateTrackRequest {
    fn validate(&self) -> ValidationResult {
        let mut resp = ValidationErrorResponse::new();
        if self.album.name.is_empty() {
            resp.errs.insert(
                "album.name".into(),
                vec![ValidationErrorKind::Length(1, usize::MAX)],
            );
        }
        if self.artists.is_empty() {
            resp.errs.insert(
                "artists".into(),
                vec![ValidationErrorKind::Length(1, usize::MAX)],
            );
        }
        if self.title.is_empty() {
            resp.errs.insert(
                "title".into(),
                vec![ValidationErrorKind::Length(1, usize::MAX)],
            );
        }
        if resp.errs.is_empty() {
            Ok(())
        } else {
            Err(resp)
        }
    }
}

// UpdateUserRequest

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    pub role: Role,
}

// UserResponse

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub creation: DateTime<Utc>,
    pub creds: CredentialsResponse,
    pub id: Uuid,
    pub role: Role,
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

// validate_playlist_request

#[inline]
fn validate_playlist_request(name: &str, predicate: &Predicate) -> ValidationResult {
    let mut resp = ValidationErrorResponse::new();
    let len = name.len();
    if !(1..=100).contains(&len) {
        resp.errs
            .insert("name".into(), vec![ValidationErrorKind::Length(1, 100)]);
    }
    if let Err(predicate_resp) = predicate.validate() {
        resp.merge_with_prefix("predicate.", predicate_resp);
    }
    if resp.errs.is_empty() {
        Ok(())
    } else {
        Err(resp)
    }
}

// Tests

#[cfg(test)]
mod test {
    use crate::model::SpotifySourceKind;

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
                    predicate: Predicate::YearIs(1993),
                    src: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                };
                req.validate().expect("request should be valid");
            }

            #[test]
            fn resp() {
                let req = CreatePlaylistRequest {
                    name: "".into(),
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

    mod update_playlist_request {
        use super::*;

        // Mods

        mod validate {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let req = UpdatePlaylistRequest {
                    name: "name".into(),
                    predicate: Predicate::YearIs(1993),
                };
                req.validate().expect("request should be valid");
            }

            #[test]
            fn resp() {
                let req = UpdatePlaylistRequest {
                    name: "".into(),
                    predicate: Predicate::ArtistsAre(Default::default()),
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

    mod update_track_request {
        use super::*;

        // Mods

        mod validate {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let req = UpdateTrackRequest {
                    album: Album {
                        compil: true,
                        name: "name".into(),
                    },
                    artists: BTreeSet::from_iter(["artist".into()]),
                    title: "title".into(),
                    year: 1993,
                };
                req.validate().expect("request should be valid");
            }

            #[test]
            fn resp() {
                let req = UpdateTrackRequest {
                    album: Album {
                        compil: true,
                        name: "".into(),
                    },
                    artists: Default::default(),
                    title: "".into(),
                    year: 1993,
                };
                let resp = req.validate().expect_err("request should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter([
                        (
                            "album.name".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                        (
                            "artists".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                        (
                            "title".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                    ]),
                };
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
