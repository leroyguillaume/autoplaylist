use autoplaylist_core::{
    db::Page,
    domain::{Base, BaseKind, Grouping, Platform, Query},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// Consts

pub const DEFAULT_PAGE_LIMIT: u32 = 10;
pub const DEFAULT_PAGE_OFFSET: u32 = 0;

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

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct BaseRequest {
    pub kind: BaseKind,
    pub platform: Platform,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateQueryRequest {
    pub base: BaseRequest,
    pub grouping: Option<Grouping>,
    #[validate(length(min = 1, max = 50))]
    pub name_prefix: Option<String>,
}

// Structs - Response

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseResponse {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictResponse {
    pub id: Uuid,
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
pub struct QueryResponse {
    pub base: BaseResponse,
    pub creation_date: DateTime<Utc>,
    pub grouping: Option<Grouping>,
    pub id: Uuid,
    pub name_prefix: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtResponse {
    pub jwt: String,
}

// Impl - BaseResponse

impl From<Base> for BaseResponse {
    fn from(base: Base) -> Self {
        Self {
            creation_date: base.creation_date,
            id: base.id,
            kind: base.kind,
            platform: base.platform,
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

impl From<Page<Query>> for PageResponse<QueryResponse> {
    fn from(page: Page<Query>) -> Self {
        Self {
            content: page.content.into_iter().map(QueryResponse::from).collect(),
            total: page.total,
        }
    }
}

// Impl - QueryResponse

impl From<Query> for QueryResponse {
    fn from(query: Query) -> Self {
        Self {
            base: query.base.into(),
            creation_date: query.creation_date,
            grouping: query.grouping,
            id: query.id,
            name_prefix: query.name_prefix,
        }
    }
}
