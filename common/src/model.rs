use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use enum_display::EnumDisplay;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

// Types

pub type PlaylistSynchronization = Synchronization<PlaylistSynchronizationStep>;
pub type PlaylistSynchronizationState = SynchronizationState<PlaylistSynchronizationStep>;
pub type SourceSynchronization = Synchronization<SourceSynchronizationStep>;
pub type SourceSynchronizationState = SynchronizationState<SourceSynchronizationStep>;

// PlatformTrack

pub trait PlatformTrack: Send + Sync {
    #[cfg(feature = "db")]
    fn into_track_creation(self) -> crate::db::TrackCreation;
}

// Synchronizable

#[cfg_attr(feature = "db", async_trait::async_trait)]
pub trait Synchronizable<STEP: SynchronizationStep>: Send + Sync {
    #[cfg(feature = "db")]
    async fn by_id(
        id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<Self>>
    where
        Self: Sized;

    #[cfg(feature = "db")]
    async fn add_track(
        &self,
        track_id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()>;

    fn id(&self) -> Uuid;

    #[cfg(feature = "db")]
    async fn lock_synchronization(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<Synchronization<STEP>>>;

    fn owner(&self) -> &User;

    fn owner_mut(&mut self) -> &mut User;

    fn source_kind(&self) -> SourceKind;

    fn set_synchronization(&mut self, sync: Synchronization<STEP>);

    #[cfg(feature = "db")]
    async fn update(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()>;
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

impl<ITEM> Page<ITEM> {
    pub fn map<T, F: Fn(ITEM) -> T>(self, f: F) -> Page<T> {
        Page {
            first: self.first,
            items: self.items.into_iter().map(f).collect(),
            last: self.last,
            req: self.req,
            total: self.total,
        }
    }
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

#[cfg(feature = "api")]
impl<const LIMIT: u32> From<crate::api::PageRequestQueryParams<LIMIT>> for PageRequest {
    fn from(params: crate::api::PageRequestQueryParams<LIMIT>) -> Self {
        Self {
            limit: params.limit.unwrap_or(LIMIT),
            offset: params.offset.unwrap_or(0),
        }
    }
}

// Platform

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(feature = "db", sqlx(type_name = "platform", rename_all = "lowercase"))]
pub enum Platform {
    Spotify,
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

#[cfg_attr(feature = "db", async_trait::async_trait)]
impl Synchronizable<PlaylistSynchronizationStep> for Playlist {
    #[cfg(feature = "db")]
    async fn by_id(
        id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<Self>> {
        db_conn.playlist_by_id(id).await
    }

    #[cfg(feature = "db")]
    async fn add_track(
        &self,
        track_id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()> {
        db_conn.add_track_to_playlist(self.id, track_id).await
    }

    fn id(&self) -> Uuid {
        self.id
    }

    #[cfg(feature = "db")]
    async fn lock_synchronization(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<PlaylistSynchronization>> {
        db_conn.lock_playlist_synchronization(self.id).await
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

    fn source_kind(&self) -> SourceKind {
        match &self.tgt {
            Target::Spotify(id) => SourceKind::Spotify(SpotifySourceKind::Playlist(id.clone())),
        }
    }

    #[cfg(feature = "db")]
    async fn update(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()> {
        db_conn.update_playlist(self).await
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
    And(Box<Predicate>, Box<Predicate>),
    ArtistsAre(#[serde(deserialize_with = "btreeset_string_trim_lowercase")] BTreeSet<String>),
    ArtistsAreExactly(
        #[serde(deserialize_with = "btreeset_string_trim_lowercase")] BTreeSet<String>,
    ),
    Or(Box<Predicate>, Box<Predicate>),
    YearIs(i32),
    YearIsBetween(i32, i32),
}

impl Predicate {
    pub fn apply(&self, track: &Track) -> bool {
        match self {
            Self::And(left, right) => left.apply(track) && right.apply(track),
            Self::ArtistsAre(artists) => track.artists.is_superset(artists),
            Self::ArtistsAreExactly(artists) => track.artists == *artists,
            Self::Or(left, right) => left.apply(track) || right.apply(track),
            Self::YearIs(year) => track.year == *year,
            Self::YearIsBetween(start, end) => track.year >= *start && track.year <= *end,
        }
    }
}

#[cfg(feature = "api")]
impl crate::api::Validate for Predicate {
    fn validate(&self) -> crate::api::ValidationResult {
        let mut resp = crate::api::ValidationErrorResponse::new();
        match &self {
            Self::And(left, right) => {
                if let Err(left_resp) = left.validate() {
                    resp.merge_with_prefix("0.", left_resp);
                }
                if let Err(right_resp) = right.validate() {
                    resp.merge_with_prefix("1.", right_resp);
                }
            }
            Self::ArtistsAre(artists) => {
                if artists.is_empty() {
                    resp.errs.insert(
                        "artistsAre".into(),
                        vec![crate::api::ValidationErrorKind::Length(1, usize::MAX)],
                    );
                }
            }
            Self::ArtistsAreExactly(artists) => {
                if artists.is_empty() {
                    resp.errs.insert(
                        "artistsAreExactly".into(),
                        vec![crate::api::ValidationErrorKind::Length(1, usize::MAX)],
                    );
                }
            }
            Self::Or(left, right) => {
                if let Err(left_resp) = left.validate() {
                    resp.merge_with_prefix("0.", left_resp);
                }
                if let Err(right_resp) = right.validate() {
                    resp.merge_with_prefix("1.", right_resp);
                }
            }
            Self::YearIsBetween(start, end) => {
                if start > end {
                    resp.errs.insert(
                        "yearIsBetween".into(),
                        vec![crate::api::ValidationErrorKind::StartAfterEnd],
                    );
                }
            }
            _ => (),
        }
        if resp.errs.is_empty() {
            Ok(())
        } else {
            Err(resp)
        }
    }
}

// Role

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[enum_display(case = "Kebab")]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(feature = "db", sqlx(type_name = "role", rename_all = "lowercase"))]
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

#[cfg_attr(feature = "db", async_trait::async_trait)]
impl Synchronizable<SourceSynchronizationStep> for Source {
    #[cfg(feature = "db")]
    async fn by_id(
        id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<Self>> {
        db_conn.source_by_id(id).await
    }

    #[cfg(feature = "db")]
    async fn add_track(
        &self,
        track_id: Uuid,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()> {
        db_conn.add_track_to_source(self.id, track_id).await
    }

    fn id(&self) -> Uuid {
        self.id
    }

    #[cfg(feature = "db")]
    async fn lock_synchronization(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<Option<SourceSynchronization>> {
        db_conn.lock_source_synchronization(self.id).await
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

    fn source_kind(&self) -> SourceKind {
        self.kind.clone()
    }

    #[cfg(feature = "db")]
    async fn update(
        &self,
        db_conn: &mut dyn crate::db::DatabaseClient,
    ) -> crate::db::DatabaseResult<()> {
        db_conn.update_source(self).await
    }
}

// SourceKind

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    Spotify(SpotifySourceKind),
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

// SpotifySourceKind

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SpotifySourceKind {
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
    pub platform: Platform,
    pub platform_id: String,
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

// btreeset_string_trim_lowercase

#[inline]
fn btreeset_string_trim_lowercase<'a, D: Deserializer<'a>>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error> {
    let set = BTreeSet::deserialize(deserializer)?
        .into_iter()
        .filter_map(|s: String| {
            let s = s.trim().to_lowercase();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect();
    Ok(set)
}

// Tests

#[cfg(test)]
mod test {
    use mockall::predicate::eq;

    use super::*;

    // new_playlist

    fn new_playlist(tgt: Target) -> Playlist {
        Playlist {
            creation: Utc::now(),
            id: Uuid::new_v4(),
            name: "name".into(),
            predicate: Predicate::YearIs(2020),
            src: new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks)),
            sync: Synchronization::Pending,
            tgt,
        }
    }

    // new_source

    fn new_source(kind: SourceKind) -> Source {
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

    mod btreeset_string_trim_lowercase {
        use super::*;

        // Dummy

        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        struct Dummy {
            #[serde(deserialize_with = "btreeset_string_trim_lowercase")]
            set: BTreeSet<String>,
        }

        // Tests

        #[test]
        fn dummy() {
            let json = "{\"set\":[\"   fOo\", \"    \",\"   BaR\"]}";
            let expected = Dummy {
                set: BTreeSet::from_iter(["foo".into(), "bar".into()]),
            };
            let dummy: Dummy = serde_json::from_str(json).expect("failed to deserialize JSON");
            assert_eq!(dummy, expected);
        }
    }

    mod page {
        use super::*;

        // Mods

        mod map {
            use super::*;

            // Tests

            #[test]
            fn page() {
                let page = Page {
                    first: false,
                    items: vec![1, 2, 3],
                    last: false,
                    req: PageRequest::new(1, 0),
                    total: 3,
                };
                let expected = Page {
                    first: false,
                    items: vec!["1".into(), "2".into(), "3".into()],
                    last: false,
                    req: PageRequest::new(1, 0),
                    total: 3,
                };
                let page = page.map(|i| i.to_string());
                assert_eq!(page, expected);
            }
        }
    }

    mod page_request {
        use super::*;

        #[cfg(feature = "api")]
        mod from_page_request_query_params {
            use crate::api::PageRequestQueryParams;

            use super::*;

            // Tests

            #[test]
            fn default() {
                let params = PageRequestQueryParams::<1>::default();
                let expected = PageRequest::new(1, 0);
                let req = PageRequest::from(params);
                assert_eq!(req, expected);
            }

            #[test]
            fn not_default() {
                let params = PageRequestQueryParams::<1> {
                    limit: Some(3),
                    offset: Some(4),
                };
                let expected = PageRequest::new(3, 4);
                let req = PageRequest::from(params);
                assert_eq!(req, expected);
            }
        }
    }

    mod playlist {
        use super::*;

        // Mods

        #[cfg(feature = "db")]
        mod by_id {
            use super::*;

            // Tests

            #[tokio::test]
            async fn playlist() {
                let expected = new_playlist(Target::Spotify("id".into()));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_playlist_by_id()
                    .with(eq(expected.id))
                    .times(1)
                    .returning({
                        let playlist = expected.clone();
                        move |_| Ok(Some(playlist.clone()))
                    });
                let playlist = Playlist::by_id(expected.id, &mut db_conn)
                    .await
                    .expect("failed to fetch playlist")
                    .expect("playlist doesn't exist");
                assert_eq!(playlist, expected);
            }
        }

        #[cfg(feature = "db")]
        mod add_track {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let playlist = new_playlist(Target::Spotify("id".into()));
                let track_id = Uuid::new_v4();
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_add_track_to_playlist()
                    .with(eq(playlist.id), eq(track_id))
                    .times(1)
                    .returning(|_, _| Ok(()));
                playlist
                    .add_track(track_id, &mut db_conn)
                    .await
                    .expect("failed to add track to playlist");
            }
        }

        mod id {
            use super::*;

            // Tests

            #[test]
            fn id() {
                let playlist = new_playlist(Target::Spotify("id".into()));
                let id = playlist.id();
                assert_eq!(id, playlist.id);
            }
        }

        #[cfg(feature = "db")]
        mod lock_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let playlist = new_playlist(Target::Spotify("id".into()));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_lock_playlist_synchronization()
                    .with(eq(playlist.id))
                    .times(1)
                    .returning({
                        let sync = playlist.sync.clone();
                        move |_| Ok(Some(sync.clone()))
                    });
                let sync = playlist
                    .lock_synchronization(&mut db_conn)
                    .await
                    .expect("failed to lock playlist synchronization")
                    .expect("synchronization doesn't exist");
                assert_eq!(sync, playlist.sync);
            }
        }

        mod set_synchronization {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let mut playlist = new_playlist(Target::Spotify("id".into()));
                let sync = Synchronization::Running;
                let expected = Playlist {
                    sync: sync.clone(),
                    ..playlist.clone()
                };
                playlist.set_synchronization(sync);
                assert_eq!(playlist, expected);
            }
        }

        mod source_kind {
            use super::*;

            // Tests

            #[test]
            fn spotify() {
                let id = "id";
                let playlist = new_playlist(Target::Spotify(id.into()));
                let expected = SourceKind::Spotify(SpotifySourceKind::Playlist(id.into()));
                let kind = playlist.source_kind();
                assert_eq!(kind, expected);
            }
        }

        #[cfg(feature = "db")]
        mod update {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let playlist = new_playlist(Target::Spotify("id".into()));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_update_playlist()
                    .with(eq(playlist.clone()))
                    .times(1)
                    .returning(|_| Ok(()));
                playlist
                    .update(&mut db_conn)
                    .await
                    .expect("failed to update playlist");
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

            // run

            fn run<F: Fn(&Track) -> Predicate>(predicate: F, expected: bool) {
                let track = Track {
                    album: Album {
                        compil: false,
                        name: "the dark side of the moon".into(),
                    },
                    artists: BTreeSet::from_iter([
                        "pink floyd".into(),
                        "oasis".into(),
                        "the beatles".into(),
                    ]),
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    platform: Platform::Spotify,
                    platform_id: "id".into(),
                    title: "time".into(),
                    year: 1974,
                };
                let predicate = predicate(&track);
                assert_eq!(predicate.apply(&track), expected);
            }

            // Tests

            #[test]
            fn and_true() {
                run(
                    |track| {
                        Predicate::And(
                            Box::new(Predicate::YearIs(track.year)),
                            Box::new(Predicate::ArtistsAreExactly(track.artists.clone())),
                        )
                    },
                    true,
                );
            }

            #[test]
            fn and_false_left() {
                run(
                    |track| {
                        Predicate::And(
                            Box::new(Predicate::YearIs(track.year + 1)),
                            Box::new(Predicate::ArtistsAreExactly(track.artists.clone())),
                        )
                    },
                    false,
                );
            }

            #[test]
            fn and_false_right() {
                run(
                    |track| {
                        Predicate::And(
                            Box::new(Predicate::YearIs(track.year)),
                            Box::new(Predicate::ArtistsAreExactly(BTreeSet::from_iter([
                                "oasis".into()
                            ]))),
                        )
                    },
                    false,
                );
            }

            #[test]
            fn artists_are_true() {
                run(
                    |_| {
                        Predicate::ArtistsAre(BTreeSet::from_iter([
                            "oasis".into(),
                            "the beatles".into(),
                        ]))
                    },
                    true,
                );
            }

            #[test]
            fn artists_are_false() {
                run(
                    |_| Predicate::ArtistsAre(BTreeSet::from_iter(["genesis".into()])),
                    false,
                );
            }

            #[test]
            fn artists_are_exactly_true() {
                run(
                    |track| Predicate::ArtistsAreExactly(track.artists.clone()),
                    true,
                );
            }

            #[test]
            fn artists_are_exactly_false() {
                run(
                    |_| Predicate::ArtistsAreExactly(BTreeSet::from_iter(["pink floyd".into()])),
                    false,
                );
            }

            #[test]
            fn or_false() {
                run(
                    |track| {
                        Predicate::Or(
                            Box::new(Predicate::YearIs(track.year + 1)),
                            Box::new(Predicate::ArtistsAreExactly(BTreeSet::from_iter([
                                "oasis".into()
                            ]))),
                        )
                    },
                    false,
                );
            }

            #[test]
            fn or_true_right() {
                run(
                    |track| {
                        Predicate::Or(
                            Box::new(Predicate::YearIs(track.year + 1)),
                            Box::new(Predicate::ArtistsAreExactly(track.artists.clone())),
                        )
                    },
                    true,
                );
            }

            #[test]
            fn or_true_left() {
                run(
                    |track| {
                        Predicate::Or(
                            Box::new(Predicate::YearIs(track.year)),
                            Box::new(Predicate::ArtistsAreExactly(BTreeSet::from_iter([
                                "oasis".into()
                            ]))),
                        )
                    },
                    true,
                );
            }

            #[test]
            fn year_is_true() {
                run(|track| Predicate::YearIs(track.year), true);
            }

            #[test]
            fn year_is_false() {
                run(|track| Predicate::YearIs(track.year + 1), false);
            }

            #[test]
            fn year_is_between_true() {
                run(|_| Predicate::YearIsBetween(1970, 1979), true);
            }

            #[test]
            fn year_is_between_false() {
                run(|track| Predicate::YearIsBetween(1970, track.year + 1), true);
            }
        }

        #[cfg(feature = "api")]
        mod validate {
            use std::collections::HashMap;

            use crate::api::{Validate, ValidationErrorKind, ValidationErrorResponse};

            use super::*;

            // Tests

            #[test]
            fn and_unit() {
                let predicate = Predicate::And(
                    Box::new(Predicate::YearIs(1990)),
                    Box::new(Predicate::YearIs(1990)),
                );
                predicate.validate().expect("predicate should be valid");
            }

            #[test]
            fn and_resp() {
                let predicate = Predicate::And(
                    Box::new(Predicate::ArtistsAre(BTreeSet::new())),
                    Box::new(Predicate::ArtistsAre(BTreeSet::new())),
                );
                let resp = predicate
                    .validate()
                    .expect_err("predicate should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter(vec![
                        (
                            "0.artistsAre".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                        (
                            "1.artistsAre".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                    ]),
                };
                assert_eq!(resp, expected);
            }

            #[test]
            fn artists_are_unit() {
                let predicate = Predicate::ArtistsAre(BTreeSet::from_iter(["pink floyd".into()]));
                predicate.validate().expect("predicate should be valid");
            }

            #[test]
            fn artists_are_resp() {
                let predicate = Predicate::ArtistsAre(BTreeSet::new());
                let resp = predicate
                    .validate()
                    .expect_err("predicate should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter(vec![(
                        "artistsAre".into(),
                        vec![ValidationErrorKind::Length(1, usize::MAX)],
                    )]),
                };
                assert_eq!(resp, expected);
            }

            #[test]
            fn artists_are_exactly_unit() {
                let predicate =
                    Predicate::ArtistsAreExactly(BTreeSet::from_iter(["pink floyd".into()]));
                predicate.validate().expect("predicate should be valid");
            }

            #[test]
            fn artists_are_exactly_resp() {
                let predicate = Predicate::ArtistsAreExactly(BTreeSet::new());
                let resp = predicate
                    .validate()
                    .expect_err("predicate should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter(vec![(
                        "artistsAreExactly".into(),
                        vec![ValidationErrorKind::Length(1, usize::MAX)],
                    )]),
                };
                assert_eq!(resp, expected);
            }

            #[test]
            fn or_unit() {
                let predicate = Predicate::Or(
                    Box::new(Predicate::YearIs(1990)),
                    Box::new(Predicate::YearIs(1990)),
                );
                predicate.validate().expect("predicate should be valid");
            }

            #[test]
            fn or_resp() {
                let predicate = Predicate::Or(
                    Box::new(Predicate::ArtistsAre(BTreeSet::new())),
                    Box::new(Predicate::ArtistsAre(BTreeSet::new())),
                );
                let resp = predicate
                    .validate()
                    .expect_err("predicate should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter(vec![
                        (
                            "0.artistsAre".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                        (
                            "1.artistsAre".into(),
                            vec![ValidationErrorKind::Length(1, usize::MAX)],
                        ),
                    ]),
                };
                assert_eq!(resp, expected);
            }

            #[test]
            fn year_is_between_unit() {
                let predicate = Predicate::YearIsBetween(1970, 1979);
                predicate.validate().expect("predicate should be valid");
            }

            #[test]
            fn year_is_between_resp() {
                let predicate = Predicate::YearIsBetween(1980, 1979);
                let resp = predicate
                    .validate()
                    .expect_err("predicate should be invalid");
                let expected = ValidationErrorResponse {
                    errs: HashMap::from_iter(vec![(
                        "yearIsBetween".into(),
                        vec![ValidationErrorKind::StartAfterEnd],
                    )]),
                };
                assert_eq!(resp, expected);
            }
        }
    }

    mod source {
        use super::*;

        // Mods

        #[cfg(feature = "db")]
        mod by_id {
            use super::*;

            // Tests

            #[tokio::test]
            async fn source() {
                let expected = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_source_by_id()
                    .with(eq(expected.id))
                    .times(1)
                    .returning({
                        let src = expected.clone();
                        move |_| Ok(Some(src.clone()))
                    });
                let src = Source::by_id(expected.id, &mut db_conn)
                    .await
                    .expect("failed to fetch source")
                    .expect("source doesn't exist");
                assert_eq!(src, expected);
            }
        }

        #[cfg(feature = "db")]
        mod add_track {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let src = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
                let track_id = Uuid::new_v4();
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_add_track_to_source()
                    .with(eq(src.id), eq(track_id))
                    .times(1)
                    .returning(|_, _| Ok(()));
                src.add_track(track_id, &mut db_conn)
                    .await
                    .expect("failed to add track to source");
            }
        }

        mod id {
            use super::*;

            // Tests

            #[test]
            fn id() {
                let src = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
                let id = src.id();
                assert_eq!(id, src.id);
            }
        }

        #[cfg(feature = "db")]
        mod lock_synchronization {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let src = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_lock_source_synchronization()
                    .with(eq(src.id))
                    .times(1)
                    .returning({
                        let sync = src.sync.clone();
                        move |_| Ok(Some(sync.clone()))
                    });
                let sync = src
                    .lock_synchronization(&mut db_conn)
                    .await
                    .expect("failed to lock source synchronization")
                    .expect("synchronization doesn't exist");
                assert_eq!(sync, src.sync);
            }
        }

        mod set_synchronization {
            use super::*;

            // Tests

            #[test]
            fn unit() {
                let mut src = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
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

            fn spotify(expected: SpotifySourceKind) {
                let src = new_source(SourceKind::Spotify(expected.clone()));
                let kind = src.source_kind();
                assert_eq!(kind, SourceKind::Spotify(expected));
            }

            // Tests

            #[test]
            fn spotify_playlist() {
                let expected = SpotifySourceKind::Playlist("id".into());
                spotify(expected);
            }

            #[test]
            fn spotify_saved_track() {
                let expected = SpotifySourceKind::SavedTracks;
                spotify(expected);
            }
        }

        #[cfg(feature = "db")]
        mod update {
            use super::*;

            // Tests

            #[tokio::test]
            async fn unit() {
                let src = new_source(SourceKind::Spotify(SpotifySourceKind::SavedTracks));
                let mut db_conn = crate::db::MockDatabaseClient::new();
                db_conn
                    .expect_update_source()
                    .with(eq(src.clone()))
                    .times(1)
                    .returning(|_| Ok(()));
                src.update(&mut db_conn)
                    .await
                    .expect("failed to update source");
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
