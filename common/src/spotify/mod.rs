use std::collections::BTreeSet;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{Album, Page, PageRequest, PlatformTrack, SpotifyCredentials, SpotifyToken};

// Consts - Spotify

pub const PAGE_LIMIT_MAX: u32 = 50;

// Types

pub type SpotifyResult<T> = Result<T, SpotifyError>;

// SpotifyError

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SpotifyError(
    #[from]
    #[source]
    Box<dyn std::error::Error + Send + Sync>,
);

// SpotifyTrack

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotifyTrack {
    pub album: Album,
    pub artists: BTreeSet<String>,
    pub id: String,
    pub title: String,
    pub year: i32,
}

impl PlatformTrack for SpotifyTrack {
    #[cfg(feature = "db")]
    fn into_track_creation(self) -> crate::db::TrackCreation {
        crate::db::TrackCreation {
            album: self.album,
            artists: self.artists,
            platform: crate::model::Platform::Spotify,
            platform_id: self.id,
            title: self.title,
            year: self.year,
        }
    }
}

// SpotifyUser

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotifyUser {
    pub id: String,
    pub email: String,
}

// SpotifyClient

#[cfg_attr(any(test, feature = "test"), mockall::automock)]
#[async_trait]
pub trait SpotifyClient: Send + Sync {
    async fn add_tracks_to_playlist(
        &self,
        id: &str,
        tracks: &[String],
        token: &mut SpotifyToken,
    ) -> SpotifyResult<()>;

    async fn authenticate(&self, code: &str, redirect_uri: &str) -> SpotifyResult<SpotifyToken>;

    async fn authenticated_user(&self, token: &mut SpotifyToken) -> SpotifyResult<SpotifyUser>;

    fn authorize_url(&self, redirect_uri: &str) -> SpotifyResult<String>;

    async fn create_playlist(
        &self,
        name: &str,
        creds: &mut SpotifyCredentials,
    ) -> SpotifyResult<String>;

    async fn playlist_tracks(
        &self,
        id: &str,
        req: PageRequest,
        token: &mut SpotifyToken,
    ) -> SpotifyResult<Page<SpotifyTrack>>;

    async fn remove_tracks_from_playlist(
        &self,
        id: &str,
        tracks: &[String],
        token: &mut SpotifyToken,
    ) -> SpotifyResult<()>;

    async fn saved_tracks(
        &self,
        req: PageRequest,
        token: &mut SpotifyToken,
    ) -> SpotifyResult<Page<SpotifyTrack>>;
}

// Mods

pub mod rspotify;

// Tests

#[cfg(test)]
mod test {
    use super::*;

    // Mods

    mod spotify_track {
        use super::*;

        // Mods

        mod into_track_creation {
            use super::*;

            // Tests

            #[cfg(feature = "db")]
            #[test]
            fn creation() {
                let track = SpotifyTrack {
                    album: Album {
                        compil: false,
                        name: "The Dark Side of the Moon".into(),
                    },
                    artists: BTreeSet::from_iter(["Pink Floyd".into()]),
                    id: "id".into(),
                    title: "Time".into(),
                    year: 1973,
                };
                let expected = crate::db::TrackCreation {
                    album: track.album.clone(),
                    artists: track.artists.clone(),
                    platform: crate::model::Platform::Spotify,
                    platform_id: track.id.clone(),
                    title: track.title.clone(),
                    year: track.year,
                };
                let creation = track.into_track_creation();
                assert_eq!(creation, expected);
            }
        }
    }
}
