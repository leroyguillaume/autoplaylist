use std::fmt::{Display, Formatter, Result as FmtResult};

use chrono::{DateTime, Utc};
use postgres_types::{FromSql, ToSql};
use securefmt::Debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Enums

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseKind {
    Likes,
    Playlist(String),
}

#[derive(Clone, Copy, Debug, Deserialize, FromSql, Serialize, ToSql)]
#[postgres(name = "grouping")]
#[serde(rename_all = "snake_case")]
pub enum Grouping {
    #[postgres(name = "decades")]
    Decades,
}

#[derive(Clone, Copy, Debug, Deserialize, FromSql, Serialize, ToSql)]
#[postgres(name = "platform")]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    #[postgres(name = "spotify")]
    Spotify,
}

#[derive(Debug, Deserialize, Eq, FromSql, PartialEq, Serialize, ToSql)]
#[postgres(name = "role")]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[postgres(name = "admin")]
    Admin,
    #[postgres(name = "user")]
    User,
}

#[derive(Debug, Deserialize, FromSql, Serialize, ToSql)]
#[postgres(name = "sync_state")]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    #[postgres(name = "aborted")]
    Aborted,
    #[postgres(name = "failed")]
    Failed,
    #[postgres(name = "running")]
    Running,
    #[postgres(name = "succeeded")]
    Succeeded,
}

// Structs

#[derive(Debug)]
pub struct Base {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
    pub sync: Sync,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct Query {
    pub base: Base,
    pub creation_date: DateTime<Utc>,
    pub grouping: Option<Grouping>,
    pub id: Uuid,
    pub name_prefix: Option<String>,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct SpotifyAuth {
    pub email: String,
    #[sensitive]
    pub access_token: String,
    #[sensitive]
    pub refresh_token: Option<String>,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct Sync {
    pub last_err_msg: Option<String>,
    pub last_start_date: Option<DateTime<Utc>>,
    pub last_success_date: Option<DateTime<Utc>>,
    pub state: Option<SyncState>,
}

#[derive(Debug)]
pub struct User {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub role: Role,
}

// Impl - Platform

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Spotify => write!(f, "Spotify"),
        }
    }
}
