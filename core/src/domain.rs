use std::fmt::{Display, Formatter, Result as FmtResult};

use chrono::{DateTime, Utc};
use securefmt::Debug as SecureDebug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// BaseKind

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseKind {
    Likes,
    Playlist(String),
}

// Platform

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Spotify,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Spotify => write!(f, "Spotify"),
        }
    }
}

// PlaylistFilter

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilter {
    Artist(PlaylistFilterOperator),
}

// PlaylistFilterOperator

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaylistFilterOperator {
    Is(String),
}

// Role

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

// SyncState

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Aborted,
    Failed,
    Running,
    Succeeded,
}

// Base

#[derive(Debug)]
pub struct Base {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub kind: BaseKind,
    pub platform: Platform,
    pub sync: Option<Sync>,
    pub user_id: Uuid,
}

// Playlist

#[derive(Debug)]
pub struct Playlist {
    pub base_id: Uuid,
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
}

// Sync

#[derive(Clone, Debug)]
pub struct Sync {
    pub last_err_msg: Option<String>,
    pub last_offset: u32,
    pub last_start_date: DateTime<Utc>,
    pub last_success_date: Option<DateTime<Utc>>,
    pub last_total: u32,
    pub state: SyncState,
}

// User

#[derive(Debug)]
pub struct User {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub role: Role,
}

// SpotifyAuth

#[derive(Debug)]
pub struct SpotifyAuth {
    pub email: String,
    pub token: SpotifyToken,
    pub user_id: Uuid,
}

// SpotifyToken

#[derive(Clone, SecureDebug)]
pub struct SpotifyToken {
    #[sensitive]
    pub access_token: String,
    pub expiration_date: DateTime<Utc>,
    #[sensitive]
    pub refresh_token: Option<String>,
}

// SpotifyArtist

#[derive(Debug)]
pub struct SpotifyArtist {
    pub id: Option<String>,
    pub name: String,
}

// SpotifyAlbum

#[derive(Debug)]
pub struct SpotifyAlbum {
    pub id: Option<String>,
    pub name: String,
}

// SpotifyTrack

#[derive(Debug)]
pub struct SpotifyTrack {
    pub album: SpotifyAlbum,
    pub artists: Vec<SpotifyArtist>,
    pub id: Option<String>,
}

// Page

#[derive(Debug)]
pub struct Page<T> {
    pub is_last: bool,
    pub items: Vec<T>,
    pub total: u32,
}

// Artist

#[derive(Debug)]
pub struct Artist {
    pub id: Uuid,
    pub name: String,
}

// Track

#[derive(Debug)]
pub struct Track {
    pub album: String,
    pub id: Uuid,
    pub name: String,
}
