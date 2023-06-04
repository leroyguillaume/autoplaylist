use std::fmt::{Display, Formatter, Result as FmtResult};

use chrono::{DateTime, Utc};
use securefmt::Debug as SecureDebug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Enums

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseKind {
    Likes,
    Playlist(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Spotify,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilter {
    Artist(PlaylistFilterOperator),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilterOperator {
    Is(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Aborted,
    Failed,
    Running,
    Succeeded,
}

// Structs

#[derive(Debug)]
pub struct Base {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
    pub sync: Option<Sync>,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct Playlist {
    pub base_id: Uuid,
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct SpotifyAuth {
    pub email: String,
    pub token: SpotifyToken,
    pub user_id: Uuid,
}

#[derive(Clone, SecureDebug)]
pub struct SpotifyToken {
    #[sensitive]
    pub access_token: String,
    pub expiration_date: DateTime<Utc>,
    #[sensitive]
    pub refresh_token: Option<String>,
}

#[derive(Debug)]
pub struct Sync {
    pub last_err_msg: Option<String>,
    pub last_offset: u32,
    pub last_start_date: DateTime<Utc>,
    pub last_success_date: Option<DateTime<Utc>>,
    pub state: SyncState,
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
