use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::domain::{Base, BaseKind, Grouping, Platform, Query};

// Structs - Requests

#[derive(Deserialize)]
pub struct AuthWithSpotifyRequest {
    pub code: String,
}

#[derive(Deserialize, Validate)]
pub struct BaseRequest {
    pub kind: BaseKind,
    pub platform: Platform,
}

#[derive(Deserialize, Validate)]
pub struct CreateQueryRequest {
    pub base: BaseRequest,
    pub grouping: Option<Grouping>,
    #[validate(length(min = 1, max = 50))]
    pub name_prefix: Option<String>,
}

// Structs - Response

#[derive(Serialize)]
pub struct BaseResponse {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
}

#[derive(Serialize)]
pub struct ConflictResponse {
    pub id: Uuid,
}

#[derive(Serialize)]
pub struct PreconditionFailedResponse {
    pub detail: String,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub base: BaseResponse,
    pub creation_date: DateTime<Utc>,
    pub grouping: Option<Grouping>,
    pub id: Uuid,
    pub name_prefix: Option<String>,
}

#[derive(Serialize)]
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

// Impl - QueryResponse

impl QueryResponse {
    pub fn from_query(query: Query, base: Base) -> Self {
        Self {
            base: base.into(),
            creation_date: query.creation_date,
            grouping: query.grouping,
            id: query.id,
            name_prefix: query.name_prefix,
        }
    }
}
