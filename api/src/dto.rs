use autoplaylist_core::{
    db::Page,
    domain::{Base, BaseKind, Platform, Playlist, Sync, SyncState},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// Consts

pub const DEFAULT_PAGE_LIMIT: u32 = 10;
pub const DEFAULT_PAGE_OFFSET: u32 = 0;

// Enums - Requests

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlaylistFilterOperatorRequest<T> {
    Is(T),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlaylistFilterRequest {
    Artist(PlaylistFilterOperatorRequest<String>),
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
    #[validate(length(min = 1))]
    pub filters: Vec<PlaylistFilterRequest>,
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
    pub total: i64,
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

// Impl - PageResponse

impl<F, T: From<F>> From<Page<F>> for PageResponse<T> {
    fn from(page: Page<F>) -> Self {
        Self {
            content: page.content.into_iter().map(T::from).collect(),
            total: page.total,
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
