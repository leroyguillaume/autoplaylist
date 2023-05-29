use std::borrow::Cow;

use autoplaylist_core::{
    db::Page,
    domain::{
        Base, BaseKind, Platform, Playlist, PlaylistFilter as DomainPlaylistFilter,
        PlaylistFilterOperator as DomainPlaylistFilterOperator, Sync, SyncState,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_trim::string_trim;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

// Consts

pub const DEFAULT_PAGE_LIMIT: u32 = 10;
pub const DEFAULT_PAGE_OFFSET: u32 = 0;

// Enums - Filter

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlaylistFilter {
    Artist(PlaylistFilterOperator),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlaylistFilterOperator {
    #[serde(deserialize_with = "string_trim")]
    Is(String),
}

// Struct - Queries

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

// Structs - Requests

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthWithSpotifyRequest {
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct BaseRequest {
    pub kind: BaseKind,
    pub platform: Platform,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreatePlaylistRequest {
    pub base: BaseRequest,
    #[validate(length(min = 1), custom = "validate_filters")]
    pub filters: Vec<PlaylistFilter>,
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1, max = 50))]
    pub name: String,
}

// Structs - Response

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseResponse {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
    pub sync: SyncResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictResponse {
    pub id: Uuid,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtResponse {
    pub jwt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageResponse<T> {
    pub content: Vec<T>,
    pub total: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreconditionFailedResponse {
    pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistResponse {
    pub base: BaseResponse,
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub last_err_msg: Option<String>,
    pub last_start_date: Option<DateTime<Utc>>,
    pub last_success_date: Option<DateTime<Utc>>,
    pub state: Option<SyncState>,
}

// Impl - BaseResponse

impl From<Base> for BaseResponse {
    fn from(base: Base) -> Self {
        Self {
            creation_date: base.creation_date,
            id: base.id,
            kind: base.kind,
            platform: base.platform,
            sync: base.sync.into(),
        }
    }
}

// Impl - PageQuery

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_PAGE_LIMIT),
            offset: Some(DEFAULT_PAGE_OFFSET),
        }
    }
}

// Impl - DomainPlaylistFilter

impl From<PlaylistFilter> for DomainPlaylistFilter {
    fn from(op: PlaylistFilter) -> Self {
        match op {
            PlaylistFilter::Artist(op) => Self::Artist(op.into()),
        }
    }
}

// Impl - DomainPlaylistFilterOperator

impl From<PlaylistFilterOperator> for DomainPlaylistFilterOperator {
    fn from(op: PlaylistFilterOperator) -> Self {
        match op {
            PlaylistFilterOperator::Is(val) => Self::Is(val),
        }
    }
}

// Impl - PageResponse

impl<F, T: From<F>> From<Page<F>> for PageResponse<T> {
    fn from(page: Page<F>) -> Self {
        Self {
            content: page.content.into_iter().map(T::from).collect(),
            total: page.total,
        }
    }
}

// Impl - PlaylistFilter

impl Validate for PlaylistFilter {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::Artist(op) => op.validate(),
        }
    }
}

// Impl - PlaylistFilterOperator

impl Validate for PlaylistFilterOperator {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::Is(val) => {
                if val.is_empty() || val.len() > 255 {
                    let mut errs = ValidationErrors::new();
                    errs.add("is", ValidationError::new("length"));
                    Err(errs)
                } else {
                    Ok(())
                }
            }
        }
    }
}

// Impl - PlaylistResponse

impl From<Playlist> for PlaylistResponse {
    fn from(playlist: Playlist) -> Self {
        Self {
            base: playlist.base.into(),
            creation_date: playlist.creation_date,
            id: playlist.id,
            name: playlist.name,
        }
    }
}

// Impl - SyncResponse

impl From<Sync> for SyncResponse {
    fn from(sync: Sync) -> Self {
        Self {
            last_err_msg: sync.last_err_msg,
            last_start_date: sync.last_start_date,
            last_success_date: sync.last_success_date,
            state: sync.state,
        }
    }
}

// Functions

fn validate_filters(filters: &[PlaylistFilter]) -> Result<(), ValidationError> {
    let errs: Vec<(usize, ValidationErrors)> = filters
        .iter()
        .enumerate()
        .filter_map(|(idx, filter)| match filter.validate() {
            Ok(()) => None,
            Err(errs) => Some((idx, errs)),
        })
        .collect();
    if errs.is_empty() {
        Ok(())
    } else {
        let mut err = ValidationError::new("filters");
        for (idx, errs) in errs {
            err.add_param(Cow::Owned(format!("[{idx}]")), &errs);
        }
        Err(err)
    }
}
