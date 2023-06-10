use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    num::ParseIntError,
    result::Result as StdResult,
    sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    db::{Client as DatabaseClient, Pool as DatabasePool},
    domain::{Artist, Base, BaseKind, Page, SpotifyToken, SpotifyTrack, Sync, SyncState, Track},
    spotify::Client as SpotifyClient,
};
use chrono::Utc;
use regex::Regex;
use tokio::{select, sync::watch::Receiver};
use tracing::{enabled, info, warn, Level};
use uuid::Uuid;

// Consts

const BASE_PAGE_SIZE: u32 = 50;
const RELEASE_DATE_PATTERN: &str = r"^([0-9]{4}).*$";

// Result

pub type Result<T> = StdResult<T, Error>;

// ErrorKind

#[derive(Debug)]
pub enum ErrorKind {
    DatabaseClient(Box<dyn StdError + Send + StdSync>),
    NoSpotifyAuth(Uuid),
    SpotifyClient(Box<dyn StdError + Send + StdSync>),
}

// Error

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    pub sync: Sync,
}

impl Error {
    fn database_client(err: Box<dyn StdError + Send + StdSync>, sync: Sync) -> Self {
        Self {
            kind: ErrorKind::DatabaseClient(err),
            sync,
        }
    }

    fn no_spotify_auth(user_id: Uuid, sync: Sync) -> Self {
        Self {
            kind: ErrorKind::NoSpotifyAuth(user_id),
            sync,
        }
    }

    fn spotify_client(err: Box<dyn StdError + Send + StdSync>, sync: Sync) -> Self {
        Self {
            kind: ErrorKind::SpotifyClient(err),
            sync,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.kind {
            ErrorKind::DatabaseClient(err) => write!(f, "{err}"),
            ErrorKind::NoSpotifyAuth(user_id) => {
                write!(f, "user {user_id} doesn't authenticated with Spotify")
            }
            ErrorKind::SpotifyClient(err) => write!(f, "{err}"),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match &self.kind {
            ErrorKind::DatabaseClient(err) => Some(err.as_ref()),
            ErrorKind::NoSpotifyAuth(_) => None,
            ErrorKind::SpotifyClient(err) => Some(err.as_ref()),
        }
    }
}

// SpotifyTrackSyncError

#[derive(Debug)]
enum SpotifyTrackSyncError {
    DatabaseClient(Box<dyn StdError + Send + StdSync>),
    MismatchedReleaseDate {
        date: String,
        id: String,
    },
    MissingArtistId(String),
    MissingTrackId,
    MissingTrackReleaseDate(String),
    ReleaseYearParsing {
        err: ParseIntError,
        id: String,
        year: String,
    },
}

impl Display for SpotifyTrackSyncError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::DatabaseClient(err) => write!(f, "{err}"),
            Self::MismatchedReleaseDate { date, id } => {
                write!(f, "Spotify track {id} release date `{date}` doesn't match pattern `{RELEASE_DATE_PATTERN}`")
            }
            Self::MissingArtistId(id) => {
                write!(f, "one of Spotify artists of track {id} doesn't have ID")
            }
            Self::MissingTrackId => write!(f, "Spotify track doesn't have ID"),
            Self::MissingTrackReleaseDate(id) => {
                write!(f, "Spotify track {id} doesn't have release date")
            }
            Self::ReleaseYearParsing { err, id, year } => write!(
                f,
                "parsing of Spotify track {id} year `{year}` failed: {err}"
            ),
        }
    }
}

impl StdError for SpotifyTrackSyncError {
    fn cause(&self) -> Option<&dyn StdError> {
        match self {
            Self::DatabaseClient(err) => Some(err.as_ref()),
            Self::MismatchedReleaseDate { .. } => None,
            Self::MissingArtistId(_) => None,
            Self::MissingTrackId => None,
            Self::MissingTrackReleaseDate(_) => None,
            Self::ReleaseYearParsing { err, .. } => Some(err),
        }
    }
}

// Synchronizer

#[async_trait]
pub trait Synchronizer: Send + StdSync {
    async fn sync(&self, base: &Base, sync: Sync) -> Result<Sync>;
}

// SpotifySynchronizer

pub struct SpotifySynchronizer {
    pub db_pool: Arc<Box<dyn DatabasePool>>,
    pub spotify_client: Arc<Box<dyn SpotifyClient>>,
    pub stop_rx: Receiver<()>,
}

impl SpotifySynchronizer {
    #[inline]
    async fn fetch_page(
        &self,
        kind: &BaseKind,
        sync: &Sync,
        token: &SpotifyToken,
    ) -> Result<Page<SpotifyTrack>> {
        let res = match kind {
            BaseKind::Likes => {
                self.spotify_client
                    .user_liked_tacks(BASE_PAGE_SIZE, sync.last_offset, token)
                    .await
            }
            BaseKind::Playlist(id) => {
                self.spotify_client
                    .playlist_tacks(id, BASE_PAGE_SIZE, sync.last_offset, token)
                    .await
            }
        };
        res.map_err(|err| Error::spotify_client(err, sync.clone()))
    }

    #[inline]
    async fn handle_spotify_track(
        spotify_track: SpotifyTrack,
        db_client: &dyn DatabaseClient,
    ) -> StdResult<Track, SpotifyTrackSyncError> {
        let repos = db_client.repositories();
        let artist_repo = repos.artist();
        let track_repo = repos.track();
        let spotify_track_id = spotify_track
            .id
            .ok_or_else(|| SpotifyTrackSyncError::MissingTrackId)?;
        let mut artists = vec![];
        for spotify_artist in spotify_track.artists {
            let spotify_artist_id = spotify_artist
                .id
                .ok_or_else(|| SpotifyTrackSyncError::MissingArtistId(spotify_track_id.clone()))?;
            let artist = artist_repo
                .get_by_spotify_id(&spotify_artist_id)
                .await
                .map_err(SpotifyTrackSyncError::DatabaseClient)?;
            let artist = match artist {
                Some(artist) => artist,
                None => {
                    let artist = Artist {
                        id: Uuid::new_v4(),
                        name: spotify_artist.name,
                        spotify_id: Some(spotify_artist_id),
                    };
                    artist_repo
                        .insert(&artist)
                        .await
                        .map_err(SpotifyTrackSyncError::DatabaseClient)?;
                    artist
                }
            };
            artists.push(artist);
        }
        let date_re = Regex::new(RELEASE_DATE_PATTERN).unwrap();
        let date = spotify_track.release_date.ok_or_else(|| {
            SpotifyTrackSyncError::MissingTrackReleaseDate(spotify_track_id.clone())
        })?;
        let year = date_re
            .captures(&date)
            .and_then(|caps| caps.get(1))
            .ok_or_else({
                let date = date.clone();
                || SpotifyTrackSyncError::MismatchedReleaseDate {
                    date,
                    id: spotify_track_id.clone(),
                }
            })?;
        let release_year: u16 =
            year.as_str()
                .parse()
                .map_err(|err| SpotifyTrackSyncError::ReleaseYearParsing {
                    err,
                    id: spotify_track_id.clone(),
                    year: year.as_str().into(),
                })?;
        let track = Track {
            from_compilation: spotify_track.from_compilation,
            id: Uuid::new_v4(),
            name: spotify_track.name,
            release_year,
            spotify_id: Some(spotify_track_id),
        };
        let artist_ids: Vec<Uuid> = artists.iter().map(|artist| artist.id).collect();
        track_repo
            .insert(&track, &artist_ids)
            .await
            .map_err(SpotifyTrackSyncError::DatabaseClient)?;
        if enabled!(Level::INFO) {
            let artist_names: Vec<String> =
                artists.iter().map(|artist| artist.name.clone()).collect();
            info!("track `{} - {}` added", track.name, artist_names.join(", "));
        }
        Ok(track)
    }

    #[inline]
    async fn sync_page(
        &self,
        base_id: Uuid,
        page: Page<SpotifyTrack>,
        sync: &Sync,
        db_client: &dyn DatabaseClient,
    ) -> Result<u32> {
        let mut offset = sync.last_offset;
        for spotify_track in page.items {
            let res = self
                .sync_track(base_id, sync.last_id, spotify_track, db_client)
                .await;
            if let Err(err) = res {
                let err_str = err.to_string();
                match err {
                    SpotifyTrackSyncError::DatabaseClient(err) => {
                        let sync = Sync {
                            last_offset: offset,
                            ..sync.clone()
                        };
                        return Err(Error::database_client(err, sync));
                    }
                    SpotifyTrackSyncError::MismatchedReleaseDate { .. } => {
                        warn!("{err_str}");
                    }
                    SpotifyTrackSyncError::MissingArtistId(_) => {
                        warn!("{err_str}");
                    }
                    SpotifyTrackSyncError::MissingTrackId => {
                        warn!("{err_str}");
                    }
                    SpotifyTrackSyncError::MissingTrackReleaseDate(_) => {
                        warn!("{err_str}");
                    }
                    SpotifyTrackSyncError::ReleaseYearParsing { .. } => {
                        warn!("{err_str}");
                    }
                }
            }
            offset += 1;
        }
        Ok(offset)
    }

    #[inline]
    async fn sync_track(
        &self,
        base_id: Uuid,
        sync_id: Uuid,
        spotify_track: SpotifyTrack,
        db_client: &dyn DatabaseClient,
    ) -> StdResult<(), SpotifyTrackSyncError> {
        match spotify_track.id.as_ref() {
            Some(id) => {
                let repos = db_client.repositories();
                let base_repo = repos.base();
                let track_repo = repos.track();
                let track = track_repo
                    .get_by_spotify_id(id)
                    .await
                    .map_err(SpotifyTrackSyncError::DatabaseClient)?;
                let track = match track {
                    Some(track) => track,
                    None => Self::handle_spotify_track(spotify_track, db_client).await?,
                };
                base_repo
                    .upsert_track(&base_id, &track.id, &sync_id)
                    .await
                    .map_err(SpotifyTrackSyncError::DatabaseClient)?;
                Ok(())
            }
            None => Err(SpotifyTrackSyncError::MissingTrackId),
        }
    }
}

#[async_trait]
impl Synchronizer for SpotifySynchronizer {
    async fn sync(&self, base: &Base, mut sync: Sync) -> Result<Sync> {
        let db_client = self
            .db_pool
            .client()
            .await
            .map_err(|err| Error::database_client(err, sync.clone()))?;
        let repos = db_client.repositories();
        let user_repo = repos.user();
        let auth = user_repo
            .get_spotify_auth_by_id(&base.user.id)
            .await
            .map_err(|err| Error::database_client(err, sync.clone()))?
            .ok_or_else(|| Error::no_spotify_auth(base.user.id, sync.clone()))?;
        drop(user_repo);
        drop(repos);
        let mut stop_rx = self.stop_rx.clone();
        let start_date = if sync.state == SyncState::Succeeded {
            Utc::now()
        } else {
            sync.last_start_date
        };
        info!("sync of base {} started", base.id);
        loop {
            select! {
                page = self.fetch_page(&base.kind, &sync, &auth.token) => {
                    let page = page?;
                    let is_last_page = page.is_last;
                    let total = page.total;
                    sync.last_offset = self.sync_page(base.id, page, &sync, db_client.as_ref()).await?;
                    if is_last_page {
                        let now = Utc::now();
                        let duration = start_date - now;
                        sync = Sync {
                            last_duration: Some(duration),
                            last_err_msg: None,
                            last_offset: 0,
                            last_success_date: Some(now),
                            last_total: total,
                            state: SyncState::Succeeded,
                            ..sync
                        };
                        info!("sync of base {} finished with success (in {} sec.)", base.id, duration.num_seconds());
                        break;
                    }
                },
                _ = stop_rx.changed() => {
                    warn!("sync of base {} aborted", base.id);
                    sync = Sync {
                        last_start_date: start_date,
                        state: SyncState::Aborted,
                        ..sync
                    };
                    break;
                }
            }
        }
        Ok(sync)
    }
}
