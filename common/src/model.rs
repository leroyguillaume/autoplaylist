use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Types

pub type PlaylistSynchronization = Synchronization<PlaylistSynchronizationStep>;
pub type PlaylistSynchronizationState = SynchronizationState<PlaylistSynchronizationStep>;
pub type SourceSynchronization = Synchronization<SourceSynchronizationStep>;
pub type SourceSynchronizationState = SynchronizationState<SourceSynchronizationStep>;

// PlatformTrack

pub trait PlatformTrack: Send + Sync {}

// Synchronizable

pub trait Synchronizable<STEP: SynchronizationStep>: Send + Sync {
    fn id(&self) -> Uuid;

    fn owner(&self) -> &User;

    fn owner_mut(&mut self) -> &mut User;

    fn set_synchronization(&mut self, sync: Synchronization<STEP>);

    fn to_resource(&self) -> PlatformResource;
}

// SynchronizationStep

pub trait SynchronizationStep: Send + Sync {
    fn first() -> Self;
}

// Album

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Album {
    pub compil: bool,
    pub name: String,
}

// Credentials

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub spotify: Option<SpotifyCredentials>,
}

// Page

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<ITEM> {
    pub first: bool,
    pub items: Vec<ITEM>,
    pub last: bool,
    pub req: PageRequest,
    pub total: u32,
}

// PageRequest

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageRequest {
    pub limit: u32,
    pub offset: u32,
}

impl PageRequest {
    pub fn new(limit: u32, offset: u32) -> Self {
        Self { limit, offset }
    }
}

// PlatformResource

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlatformResource {
    Spotify(SpotifyResourceKind),
}

// Playlist

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Playlist {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub name: String,
    pub predicate: Predicate,
    pub src: Source,
    pub sync: PlaylistSynchronization,
    pub tgt: Target,
}

impl Synchronizable<PlaylistSynchronizationStep> for Playlist {
    fn id(&self) -> Uuid {
        self.id
    }

    fn owner(&self) -> &User {
        &self.src.owner
    }

    fn owner_mut(&mut self) -> &mut User {
        &mut self.src.owner
    }

    fn set_synchronization(&mut self, sync: Synchronization<PlaylistSynchronizationStep>) {
        self.sync = sync;
    }

    fn to_resource(&self) -> PlatformResource {
        match &self.tgt {
            Target::Spotify(id) => {
                PlatformResource::Spotify(SpotifyResourceKind::Playlist(id.clone()))
            }
        }
    }
}

// PlaylistSynchronizationStep

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlaylistSynchronizationStep {
    AddTracks(u32),
    DeleteOldPull,
    DeleteTracks(u32),
    PullFromPlatform(u32),
    Finished,
}

impl SynchronizationStep for PlaylistSynchronizationStep {
    fn first() -> Self {
        Self::DeleteOldPull
    }
}

// Predicate

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Predicate {
    YearEquals(i32),
}

impl Predicate {
    pub fn apply(&self, track: &Track) -> bool {
        match self {
            Self::YearEquals(year) => track.year == *year,
        }
    }
}

// Role

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
pub enum Role {
    Admin,
    User,
}

// Source

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub kind: SourceKind,
    pub owner: User,
    pub sync: SourceSynchronization,
}

impl Synchronizable<SourceSynchronizationStep> for Source {
    fn id(&self) -> Uuid {
        self.id
    }

    fn owner(&self) -> &User {
        &self.owner
    }

    fn owner_mut(&mut self) -> &mut User {
        &mut self.owner
    }

    fn set_synchronization(&mut self, sync: Synchronization<SourceSynchronizationStep>) {
        self.sync = sync;
    }

    fn to_resource(&self) -> PlatformResource {
        match &self.kind {
            SourceKind::Spotify(kind) => PlatformResource::Spotify(kind.clone()),
        }
    }
}

// SourceKind

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    Spotify(SpotifyResourceKind),
}

// SourceSynchronizationStep

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceSynchronizationStep {
    DeleteOldPull,
    Finished,
    PublishPlaylistMessages(u32),
    PullFromPlatform(u32),
}

impl SynchronizationStep for SourceSynchronizationStep {
    fn first() -> Self {
        Self::DeleteOldPull
    }
}

// SpotifyCredentials

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotifyCredentials {
    pub id: String,
    pub token: SpotifyToken,
}

// SpotifyResourceKind

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SpotifyResourceKind {
    Playlist(String),
    SavedTracks,
}

// SpotifyToken

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotifyToken {
    pub access: String,
    pub expiration: DateTime<Utc>,
    pub refresh: String,
}

// Synchronization

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Synchronization<STEP: SynchronizationStep> {
    Aborted(SynchronizationState<STEP>),
    Failed {
        details: String,
        state: SynchronizationState<STEP>,
    },
    Pending,
    Running,
    Succeeded {
        end: DateTime<Utc>,
        start: DateTime<Utc>,
    },
}

// SynchronizationState

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizationState<STEP: SynchronizationStep> {
    pub start: DateTime<Utc>,
    pub step: STEP,
}

// Target

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Target {
    Spotify(String),
}

// Track

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Track {
    pub album: Album,
    pub artists: BTreeSet<String>,
    pub creation: DateTime<Utc>,
    pub id: Uuid,
    pub spotify_id: Option<String>,
    pub title: String,
    pub year: i32,
}

// User

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub creation: DateTime<Utc>,
    pub creds: Credentials,
    pub email: String,
    pub id: Uuid,
    pub role: Role,
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    // playlist

    fn playlist(tgt: Target) -> Playlist {
        Playlist {
            creation: Utc::now(),
            id: Uuid::new_v4(),
            name: "name".into(),
            predicate: Predicate::YearEquals(2020),
            src: source(SourceKind::Spotify(SpotifyResourceKind::SavedTracks)),
            sync: Synchronization::Pending,
            tgt,
        }
    }

    // source

    fn source(kind: SourceKind) -> Source {
        Source {
            creation: Utc::now(),
            id: Uuid::new_v4(),
            kind,
            owner: User {
                creation: Utc::now(),
                creds: Default::default(),
                email: "user@test".into(),
                id: Uuid::new_v4(),
                role: Role::User,
            },
            sync: Synchronization::Pending,
        }
    }

    // Mods

    mod playlist {
        use super::*;

        // Mods

        mod id {
            use super::*;

            // Tests

            #[test]
            fn id() {
                let playlist = playlist(Target::Spotify("id".into()));
                let id = playlist.id();
                assert_eq!(id, playlist.id);
            }
        }

        mod set_synchronization {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let mut playlist = playlist(Target::Spotify("id".into()));
                let sync = Synchronization::Running;
                let expected = Playlist {
                    sync: sync.clone(),
                    ..playlist.clone()
                };
                playlist.set_synchronization(sync);
                assert_eq!(playlist, expected);
            }
        }

        mod to_resource {
            use super::*;

            // Tests

            #[test]
            fn spotify() {
                let id = "id";
                let playlist = playlist(Target::Spotify(id.into()));
                let expected = PlatformResource::Spotify(SpotifyResourceKind::Playlist(id.into()));
                let res = playlist.to_resource();
                assert_eq!(res, expected);
            }
        }
    }

    mod playlist_synchronization_step {
        use super::*;

        // Mods

        mod first {
            use super::*;

            // Tests

            #[test]
            fn first() {
                let step = PlaylistSynchronizationStep::first();
                assert_eq!(step, PlaylistSynchronizationStep::DeleteOldPull);
            }
        }
    }

    mod predicate {
        use super::*;

        // Mods

        mod apply {
            use super::*;

            // Tests

            #[test]
            fn year_equals_false() {
                let track = Track {
                    album: Album {
                        compil: false,
                        name: "the dark side of the moon".into(),
                    },
                    artists: BTreeSet::from_iter(["pink floyd".into()]),
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    spotify_id: None,
                    title: "time".into(),
                    year: 1973,
                };
                let predicate = Predicate::YearEquals(1980);
                let res = predicate.apply(&track);
                assert!(!res);
            }
        }
    }

    mod source {
        use super::*;

        // Mods

        mod id {
            use super::*;

            // Tests

            #[test]
            fn id() {
                let src = source(SourceKind::Spotify(SpotifyResourceKind::SavedTracks));
                let id = src.id();
                assert_eq!(id, src.id);
            }
        }

        mod set_synchronization {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let mut src = source(SourceKind::Spotify(SpotifyResourceKind::SavedTracks));
                let sync = Synchronization::Running;
                let expected = Source {
                    sync: sync.clone(),
                    ..src.clone()
                };
                src.set_synchronization(sync);
                assert_eq!(src, expected);
            }
        }

        mod to_resource {
            use super::*;

            // spotify

            fn spotify(expected: SpotifyResourceKind) {
                let src = source(SourceKind::Spotify(expected.clone()));
                let res = src.to_resource();
                match res {
                    PlatformResource::Spotify(kind) => {
                        assert_eq!(kind, expected)
                    }
                }
            }

            // Tests

            #[test]
            fn spotify_playlist() {
                let expected = SpotifyResourceKind::Playlist("id".into());
                spotify(expected);
            }

            #[test]
            fn spotify_saved_track() {
                let expected = SpotifyResourceKind::SavedTracks;
                spotify(expected);
            }
        }
    }

    mod source_synchronization_step {
        use super::*;

        // Mods

        mod first {
            use super::*;

            // Tests

            #[test]
            fn first() {
                let step = SourceSynchronizationStep::first();
                assert_eq!(step, SourceSynchronizationStep::DeleteOldPull);
            }
        }
    }
}
