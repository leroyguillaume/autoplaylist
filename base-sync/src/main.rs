use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    broker::{
        rabbitmq::RabbitMqBroker, BaseCommand, BaseCommandKind, BaseEvent, BaseEventKind, Broker,
        ConsumerError, ConsumerHandler,
    },
    db::{
        in_transaction, postgres::PostgresPool, Client as DatabaseClient, InTransactionError,
        Pool as DatabasePool,
    },
    domain::{
        Artist, Base, BaseKind, Page, Platform, SpotifyToken, SpotifyTrack, Sync, SyncState, Track,
        User,
    },
    init_tracing,
    spotify::{rspotify::RSpotifyClient, Client as SpotifyClient},
};
use chrono::Utc;
use opentelemetry::global::shutdown_tracer_provider;
use regex::Regex;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
    sync::watch::{channel as watch_channel, Receiver, Sender},
};
use tracing::{debug, enabled, error, info, trace, warn, Level};
use uuid::Uuid;

use self::cfg::Config;

// Consts

const RELEASE_DATE_PATTERN: &str = r"^([0-9]{4}).*$";
const PAGE_LIMIT: u32 = 50;

// Error

#[derive(Debug)]
enum Error {
    BaseNotFound(Uuid),
    DatabaseClient {
        err: Box<dyn StdError + Send + StdSync>,
        sync: Option<Sync>,
    },
    MissingSpotifyArtistMetadata(&'static str),
    MissingSpotifyTrackMetadata(&'static str),
    NoSpotifyAuth(Uuid),
    SpotifyClient {
        err: Box<dyn StdError + Send + StdSync>,
        sync: Sync,
    },
    SyncAlreadyRunning,
    UnprocessableReleaseDate(String),
    UserNotFound(Uuid),
}

impl Error {
    fn database_client(err: Box<dyn StdError + Send + StdSync>) -> Self {
        Self::DatabaseClient { err, sync: None }
    }

    fn database_client_with_sync(err: Box<dyn StdError + Send + StdSync>, sync: Sync) -> Self {
        Self::DatabaseClient {
            err,
            sync: Some(sync),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::BaseNotFound(id) => write!(f, "base {id} doesn't exist"),
            Self::DatabaseClient { err, .. } => write!(f, "{err}"),
            Self::MissingSpotifyArtistMetadata(metadata) => write!(
                f,
                "Spotify artist is unprocessable because it missing metadata `{metadata}`"
            ),
            Self::MissingSpotifyTrackMetadata(metadata) => write!(
                f,
                "Spotify track is unprocessable because it missing metadata `{metadata}`"
            ),
            Self::NoSpotifyAuth(user_id) => {
                write!(f, "user {user_id} doesn't authenticated with Spotify")
            }
            Self::SpotifyClient { err, .. } => write!(f, "{err}"),
            Self::SyncAlreadyRunning => write!(f, "sync is already running"),
            Self::UnprocessableReleaseDate(date) => write!(
                f,
                "date `{date}` doesn't match pattern `{RELEASE_DATE_PATTERN}`"
            ),
            Self::UserNotFound(id) => write!(f, "user {id} doesn't exist"),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match self {
            Self::BaseNotFound(_) => None,
            Self::DatabaseClient { err, .. } => Some(err.as_ref()),
            Self::MissingSpotifyArtistMetadata(_) => None,
            Self::MissingSpotifyTrackMetadata(_) => None,
            Self::NoSpotifyAuth(_) => None,
            Self::SpotifyClient { err, .. } => Some(err.as_ref()),
            Self::SyncAlreadyRunning => None,
            Self::UnprocessableReleaseDate(_) => None,
            Self::UserNotFound(_) => None,
        }
    }
}

// Handler

struct Handler {
    db_pool: Arc<Box<dyn DatabasePool>>,
    spotify_client: Arc<Box<dyn SpotifyClient>>,
    stop_rx: Receiver<()>,
}

impl Handler {
    #[inline]
    async fn fail_sync(
        base_id: &Uuid,
        sync: Option<Sync>,
        err: Box<dyn StdError + Send + StdSync>,
        db_client: &dyn DatabaseClient,
    ) -> Result<(), ConsumerError> {
        error!("sync of base {base_id} failed: {err}");
        if let Some(mut sync) = sync {
            let repos = db_client.repositories();
            let base_repo = repos.base();
            sync.state = SyncState::Failed;
            sync.last_err_msg = Some(err.to_string());
            base_repo
                .update_sync(base_id, &sync)
                .await
                .map_err(ConsumerError::with_requeue)
        } else {
            Err(ConsumerError::with_requeue(err))
        }
    }

    #[inline]
    async fn handle(&self, base_id: Uuid) -> Result<(), ConsumerError> {
        let mut db_client = self
            .db_pool
            .client()
            .await
            .map_err(ConsumerError::without_requeue)?;
        if let Err(err) = self.sync(base_id, db_client.as_mut()).await {
            let err_str = err.to_string();
            match err {
                Error::DatabaseClient { err, sync } => {
                    Self::fail_sync(&base_id, sync, err, db_client.as_ref()).await
                }
                Error::SpotifyClient { err, sync } => {
                    Self::fail_sync(&base_id, Some(sync), err, db_client.as_ref()).await
                }
                _ => {
                    info!("ignoring sync of base {base_id}: {err_str}");
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    #[inline]
    async fn fetch_page(
        &self,
        base_kind: &BaseKind,
        sync: &Sync,
        token: &SpotifyToken,
    ) -> Result<Page<SpotifyTrack>, Error> {
        let res = match base_kind {
            BaseKind::Likes => {
                self.spotify_client
                    .user_liked_tacks(PAGE_LIMIT, sync.last_offset, token)
                    .await
            }
            BaseKind::Playlist(id) => {
                self.spotify_client
                    .playlist_tacks(id, PAGE_LIMIT, sync.last_offset, token)
                    .await
            }
        };
        res.map_err(|err| Error::SpotifyClient {
            err,
            sync: sync.clone(),
        })
    }

    #[inline]
    async fn sync_page(
        base_id: &Uuid,
        page: Page<SpotifyTrack>,
        mut sync: Sync,
        db_client: &mut dyn DatabaseClient,
    ) -> Result<Sync, Error> {
        sync.last_err_msg = None;
        sync.last_total = page.total;
        for track in page.items {
            let res = Self::sync_spotify_track(track, &sync, db_client).await;
            if let Err(err) = res {
                match &err {
                    Error::MissingSpotifyArtistMetadata(_) => {
                        warn!("Spotify track is ignored: {err}");
                    }
                    Error::MissingSpotifyTrackMetadata(_) => {
                        warn!("Spotify track is ignored: {err}");
                    }
                    Error::UnprocessableReleaseDate(_) => {
                        warn!("Spotify track is ignored: {err}");
                    }
                    _ => return Err(err),
                }
            }
            sync.last_offset += 1;
        }
        if page.is_last {
            sync.state = SyncState::Succeeded;
            sync.last_success_date = Some(Utc::now());
            sync.last_offset = 0;
        }
        let repos = db_client.repositories();
        let base_repo = repos.base();
        base_repo
            .update_sync(base_id, &sync)
            .await
            .map_err(|err| Error::database_client_with_sync(err, sync.clone()))?;
        Ok(sync)
    }

    #[inline]
    async fn insert_track_from_spotify_metadata(
        spotify_track: SpotifyTrack,
        sync: &Sync,
        db_client: &mut dyn DatabaseClient,
    ) -> Result<Track, Error> {
        in_transaction(db_client, {
            let sync = sync.clone();
            move |tx| {
                Box::pin(async move {
                    let repos = tx.repositories();
                    let artist_repo = repos.artist();
                    let track_repo = repos.track();
                    let mut artists = vec![];
                    for spotify_artist in spotify_track.artists {
                        let spotify_artist_id = spotify_artist
                            .id
                            .ok_or_else(|| Error::MissingSpotifyArtistMetadata("id"))?;
                        let artist = artist_repo
                            .get_by_spotify_id(&spotify_artist_id)
                            .await
                            .map_err(|err| Error::database_client_with_sync(err, sync.clone()))?;
                        let artist = match artist {
                            Some(artist) => artist,
                            None => {
                                let artist = Artist {
                                    id: Uuid::new_v4(),
                                    name: spotify_artist.name,
                                    spotify_id: Some(spotify_artist_id),
                                };
                                artist_repo.insert(&artist).await.map_err(|err| {
                                    Error::database_client_with_sync(err, sync.clone())
                                })?;
                                artist
                            }
                        };
                        artists.push(artist);
                    }
                    let spotify_track_id = spotify_track
                        .id
                        .ok_or_else(|| Error::MissingSpotifyTrackMetadata("id"))?;
                    let release_date_re = Regex::new(RELEASE_DATE_PATTERN).unwrap();
                    let release_date = spotify_track
                        .release_date
                        .ok_or_else(|| Error::MissingSpotifyTrackMetadata("release_date"))?;
                    let release_year = release_date_re
                        .captures(&release_date)
                        .and_then(|caps| caps.get(0))
                        .ok_or_else({
                            let release_date = release_date.clone();
                            move || Error::UnprocessableReleaseDate(release_date)
                        })?;
                    let release_year: u32 = release_year
                        .as_str()
                        .parse()
                        .map_err(move |_| Error::UnprocessableReleaseDate(release_date))?;
                    let track = Track {
                        id: Uuid::new_v4(),
                        name: spotify_track.name,
                        release_year,
                        spotify_id: Some(spotify_track_id),
                    };
                    let artist_ids: Vec<Uuid> = artists.iter().map(|artist| artist.id).collect();
                    track_repo
                        .insert(&track, &artist_ids)
                        .await
                        .map_err(|err| Error::database_client_with_sync(err, sync.clone()))?;
                    if enabled!(Level::INFO) {
                        let artist_names: Vec<String> =
                            artists.iter().map(|artist| artist.name.clone()).collect();
                        info!("track `{} - {}` added", track.name, artist_names.join(", "));
                    }
                    Ok(track)
                })
            }
        })
        .await
        .map_err(|err| match err {
            InTransactionError::Client(err) => Error::database_client_with_sync(err, sync.clone()),
            InTransactionError::Execution(err) => err,
        })
    }

    #[inline]
    async fn sync_spotify_track(
        spotify_track: SpotifyTrack,
        sync: &Sync,
        db_client: &mut dyn DatabaseClient,
    ) -> Result<(), Error> {
        let repos = db_client.repositories();
        let track_repo = repos.track();
        let spotify_track_id = spotify_track
            .id
            .as_ref()
            .ok_or_else(|| Error::MissingSpotifyTrackMetadata("id"))?;
        let track = track_repo
            .get_by_spotify_id(spotify_track_id)
            .await
            .map_err(|err| Error::database_client_with_sync(err, sync.clone()))?;
        drop(track_repo);
        drop(repos);
        let _track = match track {
            Some(track) => track,
            None => {
                Self::insert_track_from_spotify_metadata(spotify_track, sync, db_client).await?
            }
        };
        Ok(())
    }

    #[inline]
    async fn spotify_sync(
        &self,
        base: Base,
        user: User,
        db_client: &mut dyn DatabaseClient,
    ) -> Result<(), Error> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let auth = user_repo
            .get_spotify_auth_by_id(&user.id)
            .await
            .map_err(Error::database_client)?
            .ok_or_else(|| Error::NoSpotifyAuth(user.id))?;
        let mut sync = base_repo
            .lock_sync(&base.id, Uuid::new_v4(), Utc::now())
            .await
            .map_err(Error::database_client)?
            .ok_or(Error::SyncAlreadyRunning)?;
        drop(user_repo);
        drop(base_repo);
        drop(repos);
        let mut stop_rx = self.stop_rx.clone();
        info!("sync of base {} started", base.id);
        loop {
            select! {
                res = self.fetch_page(&base.kind, &sync, &auth.token) => {
                    sync = Self::sync_page(&base.id, res?, sync, db_client).await?;
                }
                _ = stop_rx.changed() => {
                    debug!("stop signal received");
                    break;
                },
            }
        }
        Ok(())
    }

    #[inline]
    async fn sync(&self, base_id: Uuid, db_client: &mut dyn DatabaseClient) -> Result<(), Error> {
        let repos = db_client.repositories();
        let base_repo = repos.base();
        let user_repo = repos.user();
        let base = base_repo
            .get_by_id(&base_id)
            .await
            .map_err(Error::database_client)?
            .ok_or_else(|| Error::BaseNotFound(base_id))?;
        let user = user_repo
            .get_by_id(&base.user_id)
            .await
            .map_err(Error::database_client)?
            .ok_or_else(|| Error::UserNotFound(base.user_id))?;
        drop(user_repo);
        drop(base_repo);
        drop(repos);
        match base.platform {
            Platform::Spotify => self.spotify_sync(base, user, db_client).await,
        }
    }
}

#[async_trait]
impl ConsumerHandler<BaseCommand> for Handler {
    async fn handle(&self, cmd: BaseCommand) -> Result<(), ConsumerError> {
        match cmd.kind {
            BaseCommandKind::Sync => self.handle(cmd.id).await,
        }
    }
}

#[async_trait]
impl ConsumerHandler<BaseEvent> for Handler {
    async fn handle(&self, event: BaseEvent) -> Result<(), ConsumerError> {
        match event.kind {
            BaseEventKind::Created => self.handle(event.id).await,
        }
    }
}

// main

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    init_tracing("autoplaylist-base-sync")?;
    let res = run().await;
    if let Err(err) = &res {
        error!("{err}");
    }
    shutdown_tracer_provider();
    res
}

// signal_listener

#[inline]
fn signal_listener(kind: SignalKind) -> Result<Signal, Box<dyn StdError + Send + StdSync>> {
    trace!("creating UNIX signal listener on {kind:?}");
    signal(kind).map_err(|err| Box::new(err) as Box<dyn StdError + Send + StdSync>)
}

// run

#[inline]
async fn run() -> Result<(), Box<dyn StdError + Send + StdSync>> {
    let mut sig_int = signal_listener(SignalKind::interrupt())?;
    let mut sig_term = signal_listener(SignalKind::terminate())?;
    let cfg = Config::from_env().map_err(Box::new)?;
    let db_pool = PostgresPool::init(cfg.db).await.map_err(Box::new)?;
    let db_pool: Arc<Box<dyn DatabasePool>> = Arc::new(Box::new(db_pool));
    let broker = RabbitMqBroker::init(cfg.rabbitmq).await.map_err(Box::new)?;
    let spotify_client = RSpotifyClient::new(cfg.spotify);
    let spotify_client: Arc<Box<dyn SpotifyClient>> = Arc::new(Box::new(spotify_client));
    let (stop_tx, stop_rx) = watch_channel(());
    let base_cmd_handler: Box<dyn ConsumerHandler<BaseCommand>> = Box::new(Handler {
        db_pool: db_pool.clone(),
        stop_rx: stop_rx.clone(),
        spotify_client: spotify_client.clone(),
    });
    let base_event_handler: Box<dyn ConsumerHandler<BaseEvent>> = Box::new(Handler {
        db_pool: db_pool.clone(),
        stop_rx: stop_rx.clone(),
        spotify_client,
    });
    let base_cmd_csm = broker
        .start_base_command_consumer(cfg.queues.base_cmd, stop_rx.clone(), base_cmd_handler)
        .await?;
    let base_event_csm = broker
        .start_base_event_consumer(cfg.queues.base_event, stop_rx, base_event_handler)
        .await?;
    info!("synchronizer is started");
    select! {
        _ = sig_int.recv() => send_stop_signal(SignalKind::interrupt(), stop_tx).await,
        _ = sig_term.recv() => send_stop_signal(SignalKind::terminate(), stop_tx).await,
    }
    debug!("waiting for consumers shutdown");
    base_cmd_csm.wait_for_shutdown().await;
    base_event_csm.wait_for_shutdown().await;
    info!("synchronizer stopped");
    Ok(())
}

// send_stop_signal

#[inline]
async fn send_stop_signal(sig_kind: SignalKind, stop_sig_tx: Sender<()>) {
    debug!("{sig_kind:?} received, synchronizer will shutdown");
    trace!("sending stop signal");
    if let Err(err) = stop_sig_tx.send(()) {
        error!("sending stop signal to all consumers failed: {err}");
    }
}

// Mods

mod cfg;
