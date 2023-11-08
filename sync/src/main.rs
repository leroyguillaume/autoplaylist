use std::{io::stdout, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use autoplaylist_common::{
    broker::{
        rabbitmq::{RabbitMqClient, RabbitMqConfig},
        BrokerClient, BrokerError, Consumer, Message, MessageHandler, PlaylistMessage,
        PlaylistMessageKind, Publisher, SourceMessage,
    },
    db::{
        pg::{PostgresConfig, PostgresPool},
        DatabaseConnection, DatabaseError, DatabasePool, DatabaseTransaction,
    },
    model::{
        Page, PageRequest, PlatformResource, PlatformTrack, Playlist, PlaylistSynchronizationStep,
        Source, SourceSynchronizationStep, SpotifyResourceKind, Synchronizable, Synchronization,
        SynchronizationState, SynchronizationStep, Target, Track,
    },
    sigs::TerminationSignalListener,
    spotify::{
        self,
        rspotify::{RSpotifyClient, RSpotifyConfig},
        SpotifyClient, SpotifyError,
    },
    TracingConfig,
};
use mockable::{Clock, DefaultClock, DefaultEnv, Env};
use thiserror::Error;
use tokio::{select, sync::watch::Receiver};
use tracing::{error, info, warn};
use uuid::Uuid;

// main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = DefaultEnv;
    TracingConfig::new("autoplaylist-sync", stdout).init(&env);
    let term = TerminationSignalListener::init()?;
    let db_cfg = PostgresConfig::from_env(&env)?;
    let db = Arc::new(PostgresPool::init(db_cfg).await?);
    let broker_cfg = RabbitMqConfig::from_env(&env);
    let broker = RabbitMqClient::init(broker_cfg).await?;
    let spotify_cfg = RSpotifyConfig::from_env(&env)?;
    let spotify = RSpotifyClient::new(spotify_cfg);
    let svc = Arc::new(DefaultServices {
        broker,
        clock: DefaultClock,
        spotify,
    });
    let playlist_msg_queue = env
        .string("QUEUE_PLAYLIST_MESSAGE")
        .unwrap_or_else(|| "playlist-sync_playlist".into());
    let src_msg_queue = env
        .string("QUEUE_SOURCE_MESSAGE")
        .unwrap_or_else(|| "playlist-sync_source".into());
    let playlist_msg_handler =
        DefaultMessageHandler::new(db.clone(), svc.clone(), PlaylistStateProcessor::new());
    let src_msg_handler = DefaultMessageHandler::new(db, svc.clone(), SourceStateProcessor::new());
    let playlist_csm = svc
        .broker
        .start_playlist_message_consumer(&playlist_msg_queue, playlist_msg_handler)
        .await?;
    let src_csm = svc
        .broker
        .start_source_message_consumer(&src_msg_queue, src_msg_handler)
        .await?;
    term.await;
    playlist_csm.stop().await?;
    src_csm.stop().await?;
    Ok(())
}

// Consts

const PLAYLIST_PAGE_LIMIT: u32 = 100;
const TRACK_PAGE_LIMIT: u32 = 100;

// Types

type StateProcessorResult<T> = Result<T, StateProcessorError>;
type SynchronizerResult<T> = Result<T, SynchronizerError>;

// HandleError

#[derive(Debug, Error)]
enum HandlerError {
    #[error("database error: {0}")]
    Database(
        #[from]
        #[source]
        DatabaseError,
    ),
    #[error("synchronizable {0} doesn't exist")]
    NotFound(Uuid),
    #[error("{0}")]
    Synchronization(
        #[from]
        #[source]
        SynchronizerError,
    ),
}

// StateProcessorError

#[derive(Debug, Error)]
enum StateProcessorError {
    #[error("broker error: {0}")]
    Broker(
        #[from]
        #[source]
        BrokerError,
    ),
    #[error("database error: {0}")]
    Database(
        #[from]
        #[source]
        DatabaseError,
    ),
    #[error("user {0} doesn't have Sotify credentials")]
    NoSpotifyCredentials(Uuid),
    #[error("Spotify error: {0}")]
    Spotify(
        #[from]
        #[source]
        SpotifyError,
    ),
    #[error("synchronization was aborted")]
    SynchronizationAborted,
}

// SynchronizerError

#[derive(Debug, Error)]
enum SynchronizerError {
    #[error("{0}")]
    StateProcessing(
        #[from]
        #[source]
        StateProcessorError,
    ),
    #[error("synchronization is already running")]
    SynchronizationAlreadyRunning,
}

// Puller

#[async_trait]
trait Puller<STEP: SynchronizationStep, SYNCABLE: Synchronizable<STEP>>: Send + Sync {
    async fn pull(
        &self,
        syncable: &mut SYNCABLE,
        offset: u32,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> StateProcessorResult<Page<Track>>;
}

// Services

trait Services: Send + Sync {
    fn clock(&self) -> &dyn Clock;

    fn publisher(&self) -> &dyn Publisher;

    fn spotify(&self) -> &dyn SpotifyClient;
}

// StateComputer

#[cfg_attr(test, mockall::automock)]
trait StateComputer<STEP: SynchronizationStep>: Send + Sync {
    fn compute(
        &self,
        sync: Synchronization<STEP>,
        clock: &dyn Clock,
    ) -> SynchronizerResult<SynchronizationState<STEP>>;
}

// StateProcessor

#[async_trait]
trait StateProcessor<STEP: SynchronizationStep, SYNCABLE: Synchronizable<STEP>>: Send + Sync {
    async fn process(
        &self,
        syncable: &mut SYNCABLE,
        state: &mut SynchronizationState<STEP>,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> StateProcessorResult<bool>;
}

// Synchronizer

#[async_trait]
trait Synchronizer<STEP: SynchronizationStep, SYNCABLE: Synchronizable<STEP>>: Send + Sync {
    async fn synchronize(
        &self,
        syncable: &mut SYNCABLE,
        sync: Synchronization<STEP>,
        stop_rx: Receiver<()>,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> SynchronizerResult<()>;
}

// DefaultMessageHandler

struct DefaultMessageHandler<
    DBCONN: DatabaseConnection,
    DBTX: DatabaseTransaction,
    DB: DatabasePool<DBCONN, DBTX>,
    SVC: Services,
    STEP: SynchronizationStep,
    SYNCABLE: Synchronizable<STEP>,
    SYNCER: Synchronizer<STEP, SYNCABLE>,
> {
    db: Arc<DB>,
    svc: Arc<SVC>,
    syncer: SYNCER,
    _dbconn: PhantomData<DBCONN>,
    _dbtx: PhantomData<DBTX>,
    _step: PhantomData<STEP>,
    _syncable: PhantomData<SYNCABLE>,
}

impl<
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services,
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        STATEPROC: StateProcessor<STEP, SYNCABLE>,
    >
    DefaultMessageHandler<
        DBCONN,
        DBTX,
        DB,
        SVC,
        STEP,
        SYNCABLE,
        DefaultSynchronizer<STEP, SYNCABLE, DefaultStateComputer, STATEPROC>,
    >
{
    fn new(db: Arc<DB>, svc: Arc<SVC>, proc: STATEPROC) -> Self {
        Self {
            db,
            svc,
            syncer: DefaultSynchronizer::new(proc),
            _dbconn: PhantomData,
            _dbtx: PhantomData,
            _step: PhantomData,
            _syncable: PhantomData,
        }
    }
}

impl<
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services,
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        SYNCER: Synchronizer<STEP, SYNCABLE>,
    > DefaultMessageHandler<DBCONN, DBTX, DB, SVC, STEP, SYNCABLE, SYNCER>
{
    #[inline]
    async fn synchronize<M: Message>(&self, msg: M, stop_rx: Receiver<()>) -> anyhow::Result<()> {
        let res = async {
            let id = msg.id();
            let mut db_conn = self.db.acquire().await?;
            let mut syncable = SYNCABLE::by_id(id, &mut db_conn)
                .await?
                .ok_or(HandlerError::NotFound(id))?;
            let sync = syncable
                .lock_synchronization(&mut db_conn)
                .await?
                .ok_or(HandlerError::NotFound(id))?;
            self.syncer
                .synchronize(
                    &mut syncable,
                    sync,
                    stop_rx,
                    &mut db_conn,
                    self.svc.as_ref(),
                )
                .await?;
            syncable.update(&mut db_conn).await?;
            db_conn.update_user(syncable.owner()).await?;
            Ok::<(), HandlerError>(())
        }
        .await;
        if let Err(err) = res {
            match err {
                HandlerError::NotFound(_) => {
                    warn!(details = %err, "synchronization ignored");
                }
                HandlerError::Synchronization(SynchronizerError::SynchronizationAlreadyRunning) => {
                    info!(details = %err, "synchronization ignored");
                }
                _ => return Err(err.into()),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services,
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        SYNCER: Synchronizer<STEP, SYNCABLE>,
    > MessageHandler<SourceMessage>
    for DefaultMessageHandler<DBCONN, DBTX, DB, SVC, STEP, SYNCABLE, SYNCER>
{
    async fn handle(&self, msg: SourceMessage, stop_rx: Receiver<()>) -> anyhow::Result<()> {
        self.synchronize(msg, stop_rx).await
    }
}

#[async_trait]
impl<
        DBCONN: DatabaseConnection,
        DBTX: DatabaseTransaction,
        DB: DatabasePool<DBCONN, DBTX>,
        SVC: Services,
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        SYNCER: Synchronizer<STEP, SYNCABLE>,
    > MessageHandler<PlaylistMessage>
    for DefaultMessageHandler<DBCONN, DBTX, DB, SVC, STEP, SYNCABLE, SYNCER>
{
    async fn handle(&self, msg: PlaylistMessage, stop_rx: Receiver<()>) -> anyhow::Result<()> {
        self.synchronize(msg, stop_rx).await
    }
}

// DefaultServices

struct DefaultServices {
    broker: RabbitMqClient,
    clock: DefaultClock,
    spotify: RSpotifyClient,
}

impl Services for DefaultServices {
    fn clock(&self) -> &dyn Clock {
        &self.clock
    }

    fn publisher(&self) -> &dyn Publisher {
        self.broker.publisher()
    }

    fn spotify(&self) -> &dyn SpotifyClient {
        &self.spotify
    }
}

// DefaultPuller

struct DefaultPuller;

impl DefaultPuller {
    async fn add_tracks_to_platform_resource<
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        TRACK: PlatformTrack,
    >(
        page: Page<TRACK>,
        syncable: &SYNCABLE,
        db_conn: &mut dyn DatabaseConnection,
    ) -> StateProcessorResult<Page<Track>> {
        let mut items = vec![];
        for track in page.items {
            let creation = track.into_track_creation();
            let track = db_conn
                .track_by_title_artists_album_year(
                    &creation.title,
                    &creation.artists,
                    &creation.album.name,
                    creation.year,
                )
                .await?;
            let track = if let Some(mut track) = track {
                if let Some(id) = creation.spotify_id {
                    track.spotify_id = Some(id);
                }
                db_conn.update_track(&track).await?;
                track
            } else {
                let track = db_conn.create_track(&creation).await?;
                info!(
                    sync.track.album = track.album.name,
                    sync.track.artists = ?track.artists,
                    sync.track.id = %track.id,
                    sync.track.title = track.title,
                    sync.track.year = track.year,
                    "track created",
                );
                track
            };
            syncable
                .add_track(track.id, db_conn.as_client_mut())
                .await?;
            items.push(track);
        }
        Ok(Page {
            first: page.first,
            items,
            last: page.last,
            req: page.req,
            total: page.total,
        })
    }
}

#[async_trait]
impl<STEP: SynchronizationStep, SYNCABLE: Synchronizable<STEP>> Puller<STEP, SYNCABLE>
    for DefaultPuller
{
    async fn pull(
        &self,
        syncable: &mut SYNCABLE,
        offset: u32,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> StateProcessorResult<Page<Track>> {
        match syncable.to_resource() {
            PlatformResource::Spotify(kind) => {
                let spotify = svc.spotify();
                let user = syncable.owner_mut();
                let req = PageRequest::new(spotify::PAGE_LIMIT_MAX, offset);
                let creds = user
                    .creds
                    .spotify
                    .as_mut()
                    .ok_or_else(|| StateProcessorError::NoSpotifyCredentials(user.id))?;
                let page = match kind {
                    SpotifyResourceKind::Playlist(id) => {
                        spotify.playlist_tracks(&id, req, &mut creds.token).await
                    }
                    SpotifyResourceKind::SavedTracks => {
                        spotify.saved_tracks(req, &mut creds.token).await
                    }
                }?;
                Self::add_tracks_to_platform_resource(page, syncable, db_conn).await
            }
        }
    }
}

// DefaultStateComputer

struct DefaultStateComputer;

impl DefaultStateComputer {
    #[inline]
    fn initial_state<STEP: SynchronizationStep>(clock: &dyn Clock) -> SynchronizationState<STEP> {
        SynchronizationState {
            start: clock.utc(),
            step: STEP::first(),
        }
    }
}

impl<STEP: SynchronizationStep> StateComputer<STEP> for DefaultStateComputer {
    fn compute(
        &self,
        sync: Synchronization<STEP>,
        clock: &dyn Clock,
    ) -> SynchronizerResult<SynchronizationState<STEP>> {
        match sync {
            Synchronization::Aborted(state) => Ok(state),
            Synchronization::Failed { state, .. } => Ok(state),
            Synchronization::Pending => Ok(Self::initial_state(clock)),
            Synchronization::Running => Err(SynchronizerError::SynchronizationAlreadyRunning),
            Synchronization::Succeeded { .. } => Ok(Self::initial_state(clock)),
        }
    }
}

// DefaultSynchronizer

struct DefaultSynchronizer<
    STEP: SynchronizationStep,
    SYNCABLE: Synchronizable<STEP> + 'static,
    STATECMPTER: StateComputer<STEP>,
    STATEPROC: StateProcessor<STEP, SYNCABLE>,
> {
    state_cmpter: STATECMPTER,
    state_proc: STATEPROC,
    _step: PhantomData<STEP>,
    _syncable: PhantomData<SYNCABLE>,
}

impl<
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        STATEPROC: StateProcessor<STEP, SYNCABLE>,
    > DefaultSynchronizer<STEP, SYNCABLE, DefaultStateComputer, STATEPROC>
{
    fn new(proc: STATEPROC) -> Self {
        Self {
            state_cmpter: DefaultStateComputer,
            state_proc: proc,
            _step: PhantomData,
            _syncable: PhantomData,
        }
    }
}

#[async_trait]
impl<
        STEP: SynchronizationStep,
        SYNCABLE: Synchronizable<STEP>,
        STATECMPTER: StateComputer<STEP>,
        STATEPROC: StateProcessor<STEP, SYNCABLE>,
    > Synchronizer<STEP, SYNCABLE> for DefaultSynchronizer<STEP, SYNCABLE, STATECMPTER, STATEPROC>
{
    async fn synchronize(
        &self,
        syncable: &mut SYNCABLE,
        sync: Synchronization<STEP>,
        mut stop_rx: Receiver<()>,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> SynchronizerResult<()> {
        let clock = svc.clock();
        let mut state = self.state_cmpter.compute(sync, clock)?;
        let res = loop {
            select! {
                succeeded = self.state_proc.process(
                    syncable,
                    &mut state,
                    db_conn,
                    svc,
                ) => {
                    match succeeded {
                        Ok(true) => break Ok(()),
                        Err(err) => break Err(err),
                        _ => {}
                    }
                },
                _ = stop_rx.changed() => {
                    break Err(StateProcessorError::SynchronizationAborted)
                }
            }
        };
        match res {
            Ok(()) => {
                syncable.set_synchronization(Synchronization::Succeeded {
                    end: clock.utc(),
                    start: state.start,
                });
                info!("synchronization succeeded");
            }
            Err(err) => match err {
                StateProcessorError::SynchronizationAborted => {
                    syncable.set_synchronization(Synchronization::Aborted(state));
                    info!("synchronization aborted");
                }
                _ => {
                    syncable.set_synchronization(Synchronization::Failed {
                        details: format!("{err}"),
                        state,
                    });
                    error!(details = %err, "synchronization failed");
                }
            },
        }
        Ok(())
    }
}

// PlaylistStateProcessor

struct PlaylistStateProcessor<PULLER: Puller<PlaylistSynchronizationStep, Playlist>>(PULLER);

impl PlaylistStateProcessor<DefaultPuller> {
    fn new() -> Self {
        Self(DefaultPuller)
    }
}

#[async_trait]
impl<PULLER: Puller<PlaylistSynchronizationStep, Playlist>>
    StateProcessor<PlaylistSynchronizationStep, Playlist> for PlaylistStateProcessor<PULLER>
{
    async fn process(
        &self,
        syncable: &mut Playlist,
        state: &mut SynchronizationState<PlaylistSynchronizationStep>,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> StateProcessorResult<bool> {
        match state.step {
            PlaylistSynchronizationStep::AddTracks(offset) => {
                let req = PageRequest::new(TRACK_PAGE_LIMIT, offset);
                let page = db_conn.source_tracks(syncable.src.id, req).await?;
                let mut tracks = vec![];
                for track in page.items {
                    if syncable.predicate.apply(&track) {
                        let contains = db_conn
                            .playlist_contains_track(syncable.id, track.id)
                            .await?;
                        if !contains {
                            tracks.push(track);
                        }
                    }
                }
                if !tracks.is_empty() {
                    match syncable.tgt.clone() {
                        Target::Spotify(id) => {
                            let tracks: Vec<String> = tracks
                                .into_iter()
                                .filter_map(|track| match track.spotify_id {
                                    Some(id) => Some(id),
                                    None => {
                                        warn!(
                                            sync.track.album = track.album.name,
                                            sync.track.artists = ?track.artists,
                                            sync.track.id = %track.id,
                                            sync.track.title = track.title,
                                            sync.track.year = track.year,
                                            "track doesn't have Spotify ID"
                                        );
                                        None
                                    }
                                })
                                .collect();
                            let user = syncable.owner_mut();
                            let creds = user.creds.spotify.as_mut().ok_or_else(|| {
                                StateProcessorError::NoSpotifyCredentials(user.id)
                            })?;
                            svc.spotify()
                                .add_tracks_to_playlist(&id, &tracks, &mut creds.token)
                                .await?;
                        }
                    }
                }
                if page.last {
                    state.step = PlaylistSynchronizationStep::DeleteTracks(0);
                    Ok(false)
                } else {
                    state.step = PlaylistSynchronizationStep::AddTracks(offset + page.req.limit);
                    Ok(false)
                }
            }
            PlaylistSynchronizationStep::DeleteOldPull => {
                db_conn.delete_tracks_from_playlist(syncable.id).await?;
                state.step = PlaylistSynchronizationStep::PullFromPlatform(0);
                Ok(false)
            }
            PlaylistSynchronizationStep::DeleteTracks(offset) => {
                let req = PageRequest::new(TRACK_PAGE_LIMIT, offset);
                let page = db_conn.playlist_tracks(syncable.id, req).await?;
                let mut tracks = vec![];
                for track in page.items {
                    if syncable.predicate.apply(&track) {
                        let contains = db_conn
                            .source_contains_track(syncable.src.id, track.id)
                            .await?;
                        if !contains {
                            tracks.push(track);
                        }
                    } else {
                        tracks.push(track);
                    }
                }
                if !tracks.is_empty() {
                    match syncable.tgt.clone() {
                        Target::Spotify(id) => {
                            let tracks: Vec<String> = tracks
                                .into_iter()
                                .filter_map(|track| match track.spotify_id {
                                    Some(id) => Some(id),
                                    None => {
                                        warn!(
                                            sync.track.album = track.album.name,
                                            sync.track.artists = ?track.artists,
                                            sync.track.id = %track.id,
                                            sync.track.title = track.title,
                                            sync.track.year = track.year,
                                            "track doesn't have Spotify ID"
                                        );
                                        None
                                    }
                                })
                                .collect();
                            let user = syncable.owner_mut();
                            let creds = user.creds.spotify.as_mut().ok_or_else(|| {
                                StateProcessorError::NoSpotifyCredentials(user.id)
                            })?;
                            svc.spotify()
                                .remove_tracks_from_playlist(&id, &tracks, &mut creds.token)
                                .await?;
                        }
                    }
                }
                if page.last {
                    state.step = PlaylistSynchronizationStep::Finished;
                    Ok(true)
                } else {
                    state.step = PlaylistSynchronizationStep::DeleteTracks(offset + page.req.limit);
                    Ok(false)
                }
            }
            PlaylistSynchronizationStep::Finished => Ok(true),
            PlaylistSynchronizationStep::PullFromPlatform(offset) => {
                let page = self.0.pull(syncable, offset, db_conn, svc).await?;
                if page.last {
                    state.step = PlaylistSynchronizationStep::AddTracks(0);
                    Ok(false)
                } else {
                    state.step =
                        PlaylistSynchronizationStep::PullFromPlatform(offset + page.req.limit);
                    Ok(false)
                }
            }
        }
    }
}

// SourceStateProcessor

struct SourceStateProcessor<PULLER: Puller<SourceSynchronizationStep, Source>>(PULLER);

impl SourceStateProcessor<DefaultPuller> {
    fn new() -> Self {
        Self(DefaultPuller)
    }
}

#[async_trait]
impl<PULLER: Puller<SourceSynchronizationStep, Source>>
    StateProcessor<SourceSynchronizationStep, Source> for SourceStateProcessor<PULLER>
{
    async fn process(
        &self,
        syncable: &mut Source,
        state: &mut SynchronizationState<SourceSynchronizationStep>,
        db_conn: &mut dyn DatabaseConnection,
        svc: &dyn Services,
    ) -> StateProcessorResult<bool> {
        match state.step {
            SourceSynchronizationStep::DeleteOldPull => {
                db_conn.delete_tracks_from_source(syncable.id).await?;
                state.step = SourceSynchronizationStep::PullFromPlatform(0);
                Ok(false)
            }
            SourceSynchronizationStep::Finished => Ok(true),
            SourceSynchronizationStep::PublishPlaylistMessages(offset) => {
                let req = PageRequest::new(PLAYLIST_PAGE_LIMIT, offset);
                let page = db_conn.playlist_ids_by_source(syncable.id, req).await?;
                for id in page.items {
                    let msg = PlaylistMessage {
                        id,
                        kind: PlaylistMessageKind::Sync,
                    };
                    svc.publisher().publish_playlist_message(&msg).await?;
                }
                if page.last {
                    state.step = SourceSynchronizationStep::Finished;
                    Ok(true)
                } else {
                    state.step =
                        SourceSynchronizationStep::PublishPlaylistMessages(offset + page.req.limit);
                    Ok(false)
                }
            }
            SourceSynchronizationStep::PullFromPlatform(offset) => {
                let page = self.0.pull(syncable, offset, db_conn, svc).await?;
                if page.last {
                    state.step = SourceSynchronizationStep::PublishPlaylistMessages(0);
                    Ok(false)
                } else {
                    state.step =
                        SourceSynchronizationStep::PullFromPlatform(offset + page.req.limit);
                    Ok(false)
                }
            }
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::{collections::BTreeSet, sync::Arc};

    use autoplaylist_common::{
        broker::{MockPublisher, SourceMessageKind},
        db::{MockDatabaseConnection, MockDatabasePool, TrackCreation},
        model::{
            Album, Credentials, PlaylistSynchronizationState, Predicate, Role, Source, SourceKind,
            SourceSynchronization, SourceSynchronizationState, SpotifyCredentials,
            SpotifyResourceKind, SpotifyToken, Synchronization, User,
        },
        spotify::{MockSpotifyClient, SpotifyTrack},
    };
    use chrono::{DateTime, Utc};
    use mockable::{Mock, MockClock};
    use mockall::predicate::{always, eq};
    use tokio::sync::watch;

    use super::*;

    // Types

    type MockStateProcessFn<STEP, SYNCABLE> = Mock<
        (
            StateProcessorResult<bool>,
            SYNCABLE,
            SynchronizationState<STEP>,
        ),
        (SYNCABLE, SynchronizationState<STEP>),
    >;

    // MockPuller

    struct MockPuller<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone> {
        mock: Mock<Page<Track>, (SYNCABLE, u32)>,
        _step: PhantomData<STEP>,
    }

    impl<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>
        MockPuller<STEP, SYNCABLE>
    {
        fn new(mock: Mock<Page<Track>, (SYNCABLE, u32)>) -> Self {
            Self {
                mock,
                _step: PhantomData,
            }
        }
    }

    #[async_trait]
    impl<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>
        Puller<STEP, SYNCABLE> for MockPuller<STEP, SYNCABLE>
    {
        async fn pull(
            &self,
            syncable: &mut SYNCABLE,
            offset: u32,
            _: &mut dyn DatabaseConnection,
            _: &dyn Services,
        ) -> StateProcessorResult<Page<Track>> {
            Ok(self.mock.call_with_args((syncable.clone(), offset)))
        }
    }

    // MockServices

    #[derive(Default)]
    struct MockServices {
        clock: MockClock,
        publisher: MockPublisher,
        spotify: MockSpotifyClient,
    }

    impl Services for MockServices {
        fn clock(&self) -> &dyn Clock {
            &self.clock
        }

        fn publisher(&self) -> &dyn Publisher {
            &self.publisher
        }

        fn spotify(&self) -> &dyn SpotifyClient {
            &self.spotify
        }
    }

    // MockStateProcessor

    struct MockStateProcessor<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>(
        MockStateProcessFn<STEP, SYNCABLE>,
    );

    #[async_trait]
    impl<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>
        StateProcessor<STEP, SYNCABLE> for MockStateProcessor<STEP, SYNCABLE>
    {
        async fn process(
            &self,
            syncable: &mut SYNCABLE,
            state: &mut SynchronizationState<STEP>,
            _: &mut dyn DatabaseConnection,
            _: &dyn Services,
        ) -> StateProcessorResult<bool> {
            let ret = self.0.call_with_args((syncable.clone(), state.clone()));
            *syncable = ret.1;
            *state = ret.2;
            ret.0
        }
    }

    // MockSynchronizer

    struct MockSynchronizer<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>(
        Mock<SynchronizerResult<()>, (SYNCABLE, Synchronization<STEP>)>,
    );

    #[async_trait]
    impl<STEP: SynchronizationStep + Clone, SYNCABLE: Synchronizable<STEP> + Clone>
        Synchronizer<STEP, SYNCABLE> for MockSynchronizer<STEP, SYNCABLE>
    {
        async fn synchronize(
            &self,
            syncable: &mut SYNCABLE,
            sync: Synchronization<STEP>,
            _: Receiver<()>,
            _: &mut dyn DatabaseConnection,
            _: &dyn Services,
        ) -> SynchronizerResult<()> {
            self.0.call_with_args((syncable.clone(), sync))
        }
    }

    // spotify_track

    fn spotify_track(track: &Track, id: &str) -> SpotifyTrack {
        SpotifyTrack {
            album: track.album.clone(),
            artists: track.artists.clone(),
            id: id.into(),
            title: track.title.clone(),
            year: track.year,
        }
    }

    // Mods

    mod default_message_handler {
        use super::*;

        mod synchronize {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                msg: SourceMessage,
                src: Source,
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                lock_sync: Mock<Option<SourceSynchronization>>,
                source_by_id: Mock<Option<Source>>,
                synchronize: Mock<SynchronizerResult<()>, (Source, SourceSynchronization)>,
                update_src: Mock<()>,
                update_user: Mock<()>,
            }

            // run

            async fn run(data: Data, mocks: Mocks) {
                let db = MockDatabasePool {
                    acquire: Mock::once({
                        let data = data.clone();
                        move || {
                            let mut db_conn = MockDatabaseConnection::new();
                            db_conn
                                .0
                                .expect_source_by_id()
                                .with(eq(data.src.id))
                                .times(mocks.source_by_id.times())
                                .returning({
                                    let mock = mocks.source_by_id.clone();
                                    move |_| Ok(mock.call())
                                });
                            db_conn
                                .0
                                .expect_lock_source_synchronization()
                                .with(eq(data.src.id))
                                .times(mocks.lock_sync.times())
                                .returning({
                                    let mock = mocks.lock_sync.clone();
                                    move |_| Ok(mock.call())
                                });
                            db_conn
                                .0
                                .expect_update_source()
                                .with(eq(data.src.clone()))
                                .times(mocks.update_src.times())
                                .returning(|_| Ok(()));
                            db_conn
                                .0
                                .expect_update_user()
                                .with(eq(data.src.owner.clone()))
                                .times(mocks.update_user.times())
                                .returning(|_| Ok(()));
                            db_conn
                        }
                    }),
                    ..Default::default()
                };
                let syncer = MockSynchronizer(mocks.synchronize);
                let (_, stop_rx) = watch::channel(());
                let handler = DefaultMessageHandler {
                    db: Arc::new(db),
                    svc: Arc::new(MockServices::default()),
                    syncer,
                    _dbconn: PhantomData,
                    _dbtx: PhantomData,
                    _step: PhantomData,
                    _syncable: PhantomData,
                };
                handler
                    .handle(data.msg, stop_rx)
                    .await
                    .expect("failed to handle message");
            }

            // Tests

            #[tokio::test]
            async fn not_found_when_fetching_source() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                };
                let data = Data {
                    msg: SourceMessage {
                        id: src.id,
                        kind: SourceMessageKind::Sync,
                    },
                    src,
                };
                let mocks = Mocks {
                    source_by_id: Mock::once(|| None),
                    ..Default::default()
                };
                run(data, mocks).await;
            }

            #[tokio::test]
            async fn not_found_when_locking_source() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                };
                let data = Data {
                    msg: SourceMessage {
                        id: src.id,
                        kind: SourceMessageKind::Sync,
                    },
                    src,
                };
                let mocks = Mocks {
                    lock_sync: Mock::once(|| None),
                    source_by_id: Mock::once({
                        let src = data.src.clone();
                        move || Some(src.clone())
                    }),
                    ..Default::default()
                };
                run(data, mocks).await;
            }

            #[tokio::test]
            async fn already_running() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                };
                let data = Data {
                    msg: SourceMessage {
                        id: src.id,
                        kind: SourceMessageKind::Sync,
                    },
                    src,
                };
                let mocks = Mocks {
                    lock_sync: Mock::once(|| Some(Synchronization::Running)),
                    source_by_id: Mock::once({
                        let src = data.src.clone();
                        move || Some(src.clone())
                    }),
                    synchronize: Mock::once_with_args({
                        let data = data.clone();
                        move |(src, sync)| {
                            assert_eq!(src, data.src);
                            assert_eq!(sync, Synchronization::Running);
                            Err(SynchronizerError::SynchronizationAlreadyRunning)
                        }
                    }),
                    ..Default::default()
                };
                run(data, mocks).await;
            }

            #[tokio::test]
            async fn unit() {
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                };
                let data = Data {
                    msg: SourceMessage {
                        id: src.id,
                        kind: SourceMessageKind::Sync,
                    },
                    src,
                };
                let mocks = Mocks {
                    lock_sync: Mock::once(|| Some(Synchronization::Running)),
                    source_by_id: Mock::once({
                        let src = data.src.clone();
                        move || Some(src.clone())
                    }),
                    synchronize: Mock::once_with_args({
                        let data = data.clone();
                        move |(src, sync)| {
                            assert_eq!(src, data.src);
                            assert_eq!(sync, Synchronization::Running);
                            Ok(())
                        }
                    }),
                    update_src: Mock::once(|| ()),
                    update_user: Mock::once(|| ()),
                };
                run(data, mocks).await;
            }
        }
    }

    mod default_puller {
        use super::*;

        mod pull {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                offset: u32,
                spotify_playlist_id: &'static str,
                spotify_token: SpotifyToken,
                spotify_track_id_1: &'static str,
                spotify_track_id_2: &'static str,
                src: Source,
                track_1: Track,
                track_2: Track,
            }

            // Mocks

            #[derive(Clone, Default)]
            struct Mocks {
                add_track_to_source_1: Mock<()>,
                add_track_to_source_2: Mock<()>,
                create_track_2: Mock<()>,
                spotify_playlist_tracks: Mock<Page<SpotifyTrack>>,
                spotify_saved_tracks: Mock<Page<SpotifyTrack>>,
                track_by_title_artists_album_year_1: Mock<Option<Track>>,
                track_by_title_artists_album_year_2: Mock<Option<Track>>,
                update_track_1: Mock<()>,
            }

            // mock_add_track_to_source

            fn mock_add_track_to_source(
                src: &Source,
                track: &Track,
                mock: Mock<()>,
                db_conn: &mut MockDatabaseConnection,
            ) {
                db_conn
                    .0
                    .expect_add_track_to_source()
                    .with(eq(src.id), eq(track.id))
                    .times(mock.times())
                    .returning(|_, _| Ok(()));
            }

            // mock_track_by_title_artists_album_year

            fn mock_track_by_title_artists_album_year(
                track: &Track,
                mock: Mock<Option<Track>>,
                db_conn: &mut MockDatabaseConnection,
            ) {
                db_conn
                    .0
                    .expect_track_by_title_artists_album_year()
                    .with(
                        eq(track.title.clone()),
                        eq(track.artists.clone()),
                        eq(track.album.name.clone()),
                        eq(track.year),
                    )
                    .times(mock.times())
                    .returning(move |_, _, _, _| Ok(mock.call()));
            }

            // run

            async fn run(data: Data, mocks: Mocks) -> StateProcessorResult<Page<Track>> {
                let mut db_conn = MockDatabaseConnection::new();
                mock_track_by_title_artists_album_year(
                    &data.track_1,
                    mocks.track_by_title_artists_album_year_1,
                    &mut db_conn,
                );
                mock_track_by_title_artists_album_year(
                    &data.track_2,
                    mocks.track_by_title_artists_album_year_2,
                    &mut db_conn,
                );
                db_conn
                    .0
                    .expect_update_track()
                    .with(eq(data.track_1.clone()))
                    .times(mocks.update_track_1.times())
                    .returning(|_| Ok(()));
                let creation: TrackCreation = data.track_2.clone().into();
                db_conn
                    .0
                    .expect_create_track()
                    .with(eq(creation))
                    .times(mocks.create_track_2.times())
                    .returning({
                        let track = data.track_2.clone();
                        move |_| Ok(track.clone())
                    });
                let mut spotify = MockSpotifyClient::new();
                mock_add_track_to_source(
                    &data.src,
                    &data.track_1,
                    mocks.add_track_to_source_1,
                    &mut db_conn,
                );
                mock_add_track_to_source(
                    &data.src,
                    &data.track_2,
                    mocks.add_track_to_source_2,
                    &mut db_conn,
                );
                let req = PageRequest::new(spotify::PAGE_LIMIT_MAX, data.offset);
                spotify
                    .expect_playlist_tracks()
                    .with(
                        eq(data.spotify_playlist_id),
                        eq(req),
                        eq(data.spotify_token.clone()),
                    )
                    .times(mocks.spotify_playlist_tracks.times())
                    .returning({
                        let mock = mocks.spotify_playlist_tracks.clone();
                        move |_, _, _| Ok(mock.call())
                    });
                spotify
                    .expect_saved_tracks()
                    .with(eq(req), eq(data.spotify_token))
                    .times(mocks.spotify_saved_tracks.times())
                    .returning({
                        let mock = mocks.spotify_saved_tracks.clone();
                        move |_, _| Ok(mock.call())
                    });
                let svc = MockServices {
                    spotify,
                    ..Default::default()
                };
                let mut src = data.src.clone();
                DefaultPuller
                    .pull(&mut src, data.offset, &mut db_conn, &svc)
                    .await
            }

            // Tests

            #[tokio::test]
            async fn no_spotify_credentials() {
                let owner_id = Uuid::new_v4();
                let spotify_track_id_1 = "track_1";
                let spotify_track_id_2 = "track_2";
                let data = Data {
                    offset: 0,
                    spotify_playlist_id: "id",
                    spotify_token: SpotifyToken {
                        access: "access".into(),
                        expiration: Utc::now(),
                        refresh: "refresh".into(),
                    },
                    spotify_track_id_1,
                    spotify_track_id_2,
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: owner_id,
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    track_1: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_1.into()),
                        title: "time".into(),
                        year: 1973,
                    },
                    track_2: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_2.into()),
                        title: "money".into(),
                        year: 1973,
                    },
                };
                let mocks = Mocks::default();
                let err = run(data, mocks)
                    .await
                    .expect_err("pulling tracks should fail");
                match err {
                    StateProcessorError::NoSpotifyCredentials(id) => assert_eq!(id, owner_id),
                    _ => panic!("unexpected error: {err}"),
                }
            }

            #[tokio::test]
            async fn spotify_saved_tracks() {
                let spotify_token = SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                };
                let spotify_track_id_1 = "track_1";
                let spotify_track_id_2 = "track_2";
                let data = Data {
                    offset: 0,
                    spotify_playlist_id: "id",
                    spotify_token: spotify_token.clone(),
                    spotify_track_id_1,
                    spotify_track_id_2,
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token,
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    track_1: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_1.into()),
                        title: "time".into(),
                        year: 1973,
                    },
                    track_2: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_2.into()),
                        title: "money".into(),
                        year: 1973,
                    },
                };
                let page = Page {
                    first: true,
                    items: vec![
                        spotify_track(&data.track_1, data.spotify_track_id_1),
                        spotify_track(&data.track_2, data.spotify_track_id_2),
                    ],
                    last: true,
                    req: PageRequest::new(spotify::PAGE_LIMIT_MAX, data.offset),
                    total: 2,
                };
                let expected = Page {
                    first: page.first,
                    items: vec![data.track_1.clone(), data.track_2.clone()],
                    last: page.last,
                    req: page.req,
                    total: page.total,
                };
                let mocks = Mocks {
                    add_track_to_source_1: Mock::once(|| ()),
                    add_track_to_source_2: Mock::once(|| ()),
                    create_track_2: Mock::once(|| ()),
                    update_track_1: Mock::once(|| ()),
                    spotify_saved_tracks: Mock::once(move || page.clone()),
                    track_by_title_artists_album_year_1: Mock::once({
                        let track = Track {
                            spotify_id: None,
                            ..data.track_1.clone()
                        };
                        move || Some(track.clone())
                    }),
                    track_by_title_artists_album_year_2: Mock::once(|| None),
                    ..Default::default()
                };
                let page = run(data, mocks).await.expect("faield to pull tracks");
                assert_eq!(page, expected);
            }

            #[tokio::test]
            async fn spotify_playlist() {
                let spotify_playlist_id = "id";
                let spotify_token = SpotifyToken {
                    access: "access".into(),
                    expiration: Utc::now(),
                    refresh: "refresh".into(),
                };
                let spotify_track_id_1 = "track_1";
                let spotify_track_id_2 = "track_2";
                let data = Data {
                    offset: 0,
                    spotify_playlist_id,
                    spotify_token: spotify_token.clone(),
                    spotify_track_id_1,
                    spotify_track_id_2,
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::Playlist(
                            spotify_playlist_id.into(),
                        )),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token,
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    track_1: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_1.into()),
                        title: "time".into(),
                        year: 1973,
                    },
                    track_2: Track {
                        album: Album {
                            compil: false,
                            name: "the dark side of the moon".into(),
                        },
                        artists: BTreeSet::from_iter(["pink floyd".into()]),
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        spotify_id: Some(spotify_track_id_2.into()),
                        title: "money".into(),
                        year: 1973,
                    },
                };
                let page = Page {
                    first: true,
                    items: vec![
                        spotify_track(&data.track_1, data.spotify_track_id_1),
                        spotify_track(&data.track_2, data.spotify_track_id_2),
                    ],
                    last: true,
                    req: PageRequest::new(spotify::PAGE_LIMIT_MAX, data.offset),
                    total: 2,
                };
                let expected = Page {
                    first: page.first,
                    items: vec![data.track_1.clone(), data.track_2.clone()],
                    last: page.last,
                    req: page.req,
                    total: page.total,
                };
                let mocks = Mocks {
                    add_track_to_source_1: Mock::once(|| ()),
                    add_track_to_source_2: Mock::once(|| ()),
                    create_track_2: Mock::once(|| ()),
                    update_track_1: Mock::once(|| ()),
                    spotify_playlist_tracks: Mock::once(move || page.clone()),
                    track_by_title_artists_album_year_1: Mock::once({
                        let track = Track {
                            spotify_id: None,
                            ..data.track_1.clone()
                        };
                        move || Some(track.clone())
                    }),
                    track_by_title_artists_album_year_2: Mock::once(|| None),
                    ..Default::default()
                };
                let page = run(data, mocks).await.expect("faield to pull tracks");
                assert_eq!(page, expected);
            }
        }
    }

    mod default_synchronization_state_computer {
        use super::*;

        mod compute {
            use super::*;

            // run

            fn run(
                sync: SourceSynchronization,
                mock_clock: bool,
            ) -> (
                SynchronizerResult<SourceSynchronizationState>,
                DateTime<Utc>,
            ) {
                let now = Utc::now();
                let mut clock = MockClock::new();
                clock
                    .expect_utc()
                    .times(mock_clock as usize)
                    .return_const(now);
                let res = DefaultStateComputer.compute(sync, &clock);
                (res, now)
            }

            // Tests

            #[test]
            fn aborted() {
                let expected = SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PullFromPlatform(50),
                };
                let sync = Synchronization::Aborted(expected.clone());
                let state = run(sync, false)
                    .0
                    .expect("failed to compute synchronization state");
                assert_eq!(state, expected);
            }

            #[test]
            fn failed() {
                let expected = SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PullFromPlatform(50),
                };
                let sync = Synchronization::Failed {
                    details: "error".into(),
                    state: expected.clone(),
                };
                let state = run(sync, false)
                    .0
                    .expect("failed to compute synchronization state");
                assert_eq!(state, expected);
            }

            #[test]
            fn pending() {
                let (state, start) = run(Synchronization::Pending, true);
                let expected = SynchronizationState {
                    start,
                    step: SourceSynchronizationStep::DeleteOldPull,
                };
                let state = state.expect("failed to compute synchronization state");
                assert_eq!(state, expected);
            }

            #[test]
            fn running() {
                let err = run(Synchronization::Running, false)
                    .0
                    .expect_err("computing synchronization state should fail");
                assert!(matches!(
                    err,
                    SynchronizerError::SynchronizationAlreadyRunning
                ));
            }

            #[test]
            fn succeeded() {
                let sync = Synchronization::Succeeded {
                    end: Utc::now(),
                    start: Utc::now(),
                };
                let (state, start) = run(sync, true);
                let expected = SynchronizationState {
                    start,
                    step: SourceSynchronizationStep::DeleteOldPull,
                };
                let state = state.expect("failed to compute synchronization state");
                assert_eq!(state, expected);
            }
        }
    }

    mod default_synchronizer {
        use super::*;

        mod synchronize {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                src: Source,
                state_0: SourceSynchronizationState,
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                end: Mock<DateTime<Utc>>,
                process_state: MockStateProcessFn<SourceSynchronizationStep, Source>,
            }

            // run

            async fn run(
                data: Data,
                mocks: Mocks,
                stop_rx: Receiver<()>,
            ) -> (SynchronizerResult<()>, Source) {
                let sync = Synchronization::Pending;
                let mut clock = MockClock::new();
                clock.expect_utc().times(mocks.end.times()).returning({
                    let mock = mocks.end.clone();
                    move || mock.call()
                });
                let mut state_cmpter = MockStateComputer::new();
                state_cmpter
                    .expect_compute()
                    .with(eq(sync.clone()), always())
                    .times(1)
                    .returning({
                        let state = data.state_0.clone();
                        move |_, _| Ok(state.clone())
                    });
                let state_proc = MockStateProcessor(mocks.process_state);
                let mut db_conn = MockDatabaseConnection::new();
                let svc = MockServices {
                    clock,
                    ..Default::default()
                };
                let syncer = DefaultSynchronizer {
                    state_cmpter,
                    state_proc,
                    _step: PhantomData,
                    _syncable: PhantomData,
                };
                let mut src = data.src.clone();
                let res = syncer
                    .synchronize(&mut src, sync, stop_rx, &mut db_conn, &svc)
                    .await;
                (res, src)
            }

            // Tests

            #[tokio::test]
            async fn succeeded() {
                let end = Utc::now();
                let data = Data {
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    state_0: SynchronizationState {
                        start: Utc::now(),
                        step: SourceSynchronizationStep::DeleteOldPull,
                    },
                };
                let state_1 = SynchronizationState {
                    start: data.state_0.start,
                    step: SourceSynchronizationStep::PullFromPlatform(0),
                };
                let state_2 = SynchronizationState {
                    start: data.state_0.start,
                    step: SourceSynchronizationStep::PullFromPlatform(50),
                };
                let state_3 = SynchronizationState {
                    start: data.state_0.start,
                    step: SourceSynchronizationStep::Finished,
                };
                let expected = Source {
                    sync: Synchronization::Succeeded {
                        end,
                        start: data.state_0.start,
                    },
                    ..data.src.clone()
                };
                let (_stop_tx, stop_rx) = watch::channel(());
                let mocks = Mocks {
                    end: Mock::once(move || end),
                    process_state: Mock::always_with_args({
                        let data = data.clone();
                        let state_1 = state_1.clone();
                        let state_2 = state_2.clone();
                        move |idx, (src, state)| {
                            assert_eq!(src, data.src);
                            if idx == 0 {
                                assert_eq!(state, data.state_0);
                                (Ok(false), src, state_1.clone())
                            } else if idx == 1 {
                                assert_eq!(state, state_1);
                                (Ok(false), src, state_2.clone())
                            } else if idx == 2 {
                                assert_eq!(state, state_2);
                                (Ok(true), src, state_3.clone())
                            } else {
                                panic!("unexpected call");
                            }
                        }
                    }),
                };
                let (res, src) = run(data, mocks, stop_rx).await;
                res.expect("failed to synchronize");
                assert_eq!(src, expected);
            }

            #[tokio::test]
            async fn failed() {
                let data = Data {
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    state_0: SynchronizationState {
                        start: Utc::now(),
                        step: SourceSynchronizationStep::DeleteOldPull,
                    },
                };
                let state_1 = SynchronizationState {
                    start: data.state_0.start,
                    step: SourceSynchronizationStep::PullFromPlatform(0),
                };
                let expected = Source {
                    sync: Synchronization::Failed {
                        details: StateProcessorError::NoSpotifyCredentials(data.src.owner.id)
                            .to_string(),
                        state: state_1.clone(),
                    },
                    ..data.src.clone()
                };
                let (_stop_tx, stop_rx) = watch::channel(());
                let mocks = Mocks {
                    process_state: Mock::always_with_args({
                        let data = data.clone();
                        let state_1 = state_1.clone();
                        move |idx, (src, state)| {
                            assert_eq!(src, data.src);
                            if idx == 0 {
                                assert_eq!(state, data.state_0);
                                (Ok(false), src, state_1.clone())
                            } else if idx == 1 {
                                assert_eq!(state, state_1);
                                (
                                    Err(StateProcessorError::NoSpotifyCredentials(
                                        data.src.owner.id,
                                    )),
                                    src,
                                    state_1.clone(),
                                )
                            } else {
                                panic!("unexpected call");
                            }
                        }
                    }),
                    ..Default::default()
                };
                let (res, src) = run(data, mocks, stop_rx).await;
                res.expect("failed to synchronize");
                assert_eq!(src, expected);
            }

            #[tokio::test]
            async fn aborted() {
                let data = Data {
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    state_0: SynchronizationState {
                        start: Utc::now(),
                        step: SourceSynchronizationStep::DeleteOldPull,
                    },
                };
                let state_1 = SynchronizationState {
                    start: data.state_0.start,
                    step: SourceSynchronizationStep::PullFromPlatform(0),
                };
                let expected = Source {
                    sync: Synchronization::Aborted(state_1.clone()),
                    ..data.src.clone()
                };
                let (stop_tx, stop_rx) = watch::channel(());
                let mocks = Mocks {
                    process_state: Mock::always_with_args({
                        let data = data.clone();
                        let state_1 = state_1.clone();
                        move |idx, (src, state)| {
                            assert_eq!(src, data.src);
                            if idx == 0 {
                                assert_eq!(state, data.state_0);
                                (Ok(false), src, state_1.clone())
                            } else {
                                assert_eq!(state, state_1);
                                stop_tx.send(()).ok();
                                (Ok(false), src, state_1.clone())
                            }
                        }
                    }),
                    ..Default::default()
                };
                let (res, src) = run(data, mocks, stop_rx).await;
                res.expect("failed to synchronize");
                assert_eq!(src, expected);
            }
        }
    }

    mod playlist_state_processor {
        use super::*;

        // Data

        #[derive(Clone)]
        struct Data {
            playlist: Playlist,
            spotify_playlist_id: &'static str,
            spotify_token: SpotifyToken,
            state: PlaylistSynchronizationState,
        }

        // Mocks

        #[derive(Default)]
        struct Mocks {
            add_tracks_to_spotify_playlist: Mock<(), Vec<String>>,
            delete_tracks_from_playlist: Mock<()>,
            playlist_contains_tracks: Mock<bool, Uuid>,
            playlist_tracks: Mock<Page<Track>, PageRequest>,
            pull: Mock<Page<Track>, (Playlist, u32)>,
            remove_tracks_from_spotify_playlist: Mock<(), Vec<String>>,
            src_contains_tracks: Mock<bool, Uuid>,
            src_tracks: Mock<Page<Track>, PageRequest>,
        }

        // run

        async fn run(
            data: Data,
            mocks: Mocks,
        ) -> (StateProcessorResult<bool>, PlaylistSynchronizationState) {
            let mut db_conn = MockDatabaseConnection::new();
            db_conn
                .0
                .expect_source_tracks()
                .with(eq(data.playlist.src.id), always())
                .times(mocks.src_tracks.times())
                .returning({
                    let mock = mocks.src_tracks.clone();
                    move |_, req| Ok(mock.call_with_args(req))
                });
            db_conn
                .0
                .expect_playlist_contains_track()
                .with(eq(data.playlist.id), always())
                .times(mocks.playlist_contains_tracks.times())
                .returning({
                    let mock = mocks.playlist_contains_tracks.clone();
                    move |_, track_id| Ok(mock.call_with_args(track_id))
                });
            db_conn
                .0
                .expect_delete_tracks_from_playlist()
                .with(eq(data.playlist.id))
                .times(mocks.delete_tracks_from_playlist.times())
                .returning(|_| Ok(()));
            db_conn
                .0
                .expect_playlist_tracks()
                .with(eq(data.playlist.id), always())
                .times(mocks.playlist_tracks.times())
                .returning({
                    let mock = mocks.playlist_tracks.clone();
                    move |_, req| Ok(mock.call_with_args(req))
                });
            db_conn
                .0
                .expect_source_contains_track()
                .with(eq(data.playlist.src.id), always())
                .times(mocks.src_contains_tracks.times())
                .returning({
                    let mock = mocks.src_contains_tracks.clone();
                    move |_, track_id| Ok(mock.call_with_args(track_id))
                });
            let mut spotify = MockSpotifyClient::new();
            spotify
                .expect_add_tracks_to_playlist()
                .with(
                    eq(data.spotify_playlist_id),
                    always(),
                    eq(data.spotify_token.clone()),
                )
                .times(mocks.add_tracks_to_spotify_playlist.times())
                .returning({
                    let mock = mocks.add_tracks_to_spotify_playlist.clone();
                    move |_, tracks, _| {
                        mock.call_with_args(tracks.to_vec());
                        Ok(())
                    }
                });
            spotify
                .expect_remove_tracks_from_playlist()
                .with(
                    eq(data.spotify_playlist_id),
                    always(),
                    eq(data.spotify_token.clone()),
                )
                .times(mocks.remove_tracks_from_spotify_playlist.times())
                .returning({
                    let mock = mocks.remove_tracks_from_spotify_playlist.clone();
                    move |_, tracks, _| {
                        mock.call_with_args(tracks.to_vec());
                        Ok(())
                    }
                });
            let puller = MockPuller::new(mocks.pull);
            let svc = MockServices {
                spotify,
                ..Default::default()
            };
            let proc = PlaylistStateProcessor(puller);
            let mut playlist = data.playlist.clone();
            let mut state = data.state.clone();
            let succeeded = proc
                .process(&mut playlist, &mut state, &mut db_conn, &svc)
                .await;
            (succeeded, state)
        }

        // Tests

        #[tokio::test]
        async fn delete_old_pull() {
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::DeleteOldPull,
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::PullFromPlatform(0),
            };
            let mocks = Mocks {
                delete_tracks_from_playlist: Mock::once(|| ()),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn pull_from_platform_0() {
            let expected_offset = 0;
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::PullFromPlatform(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::PullFromPlatform(spotify::PAGE_LIMIT_MAX),
            };
            let mocks = Mocks {
                pull: Mock::once_with_args({
                    let data = data.clone();
                    move |(playlist, offset)| {
                        assert_eq!(playlist, data.playlist);
                        assert_eq!(offset, expected_offset);
                        Page {
                            first: true,
                            items: vec![],
                            last: false,
                            req: PageRequest::new(spotify::PAGE_LIMIT_MAX, expected_offset),
                            total: 0,
                        }
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn pull_from_platform_50() {
            let expected_offset = 50;
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::PullFromPlatform(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::AddTracks(0),
            };
            let mocks = Mocks {
                pull: Mock::once_with_args({
                    let data = data.clone();
                    move |(playlist, offset)| {
                        assert_eq!(playlist, data.playlist);
                        assert_eq!(offset, expected_offset);
                        Page {
                            first: true,
                            items: vec![],
                            last: true,
                            req: PageRequest::new(spotify::PAGE_LIMIT_MAX, expected_offset),
                            total: 0,
                        }
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn no_spotify_credentials_when_add_tracks() {
            let user_id = Uuid::new_v4();
            let expected_offset = 0;
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: user_id,
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::AddTracks(expected_offset),
                },
            };
            let mocks = Mocks {
                playlist_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                ]),
                src_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: false,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (res, _) = run(data, mocks).await;
            let err = res.expect_err("state processing should fail");
            match err {
                StateProcessorError::NoSpotifyCredentials(id) => {
                    assert_eq!(id, user_id)
                }
                _ => panic!("unexpected error"),
            }
        }

        #[tokio::test]
        async fn add_tracks_0() {
            let expected_offset = 0;
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::AddTracks(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::AddTracks(TRACK_PAGE_LIMIT),
            };
            let mocks = Mocks {
                add_tracks_to_spotify_playlist: Mock::once_with_args(move |tracks| {
                    assert_eq!(tracks, vec![spotify_track_id_1, spotify_track_id_5],);
                }),
                playlist_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                ]),
                src_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: false,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn add_tracks_100() {
            let expected_offset = 100;
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::AddTracks(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::DeleteTracks(0),
            };
            let mocks = Mocks {
                add_tracks_to_spotify_playlist: Mock::once_with_args(move |tracks| {
                    assert_eq!(tracks, vec![spotify_track_id_1, spotify_track_id_5],);
                }),
                playlist_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                ]),
                src_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: true,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn no_spotify_credentials_when_delete_tracks() {
            let expected_offset = 0;
            let user_id = Uuid::new_v4();
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            email: "user@test".into(),
                            id: user_id,
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::DeleteTracks(expected_offset),
                },
            };
            let mocks = Mocks {
                src_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                ]),
                playlist_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: false,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (succeeded, _) = run(data, mocks).await;
            let err = succeeded.expect_err("processing state should fail");
            match err {
                StateProcessorError::NoSpotifyCredentials(id) => {
                    assert_eq!(id, user_id)
                }
                _ => panic!("unexpected error"),
            }
        }

        #[tokio::test]
        async fn delete_tracks_0() {
            let expected_offset = 0;
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::DeleteTracks(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::DeleteTracks(TRACK_PAGE_LIMIT),
            };
            let mocks = Mocks {
                remove_tracks_from_spotify_playlist: Mock::once_with_args(move |tracks| {
                    assert_eq!(
                        tracks,
                        vec![spotify_track_id_1, spotify_track_id_2, spotify_track_id_5],
                    );
                }),
                src_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                ]),
                playlist_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: false,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn delete_tracks_100() {
            let expected_offset = 100;
            let spotify_track_id_1 = "4xHWH1jwV5j4mBYRhxPbwZ";
            let spotify_track_id_2 = "7ygpwy2qP3NbrxVkHvUhXY";
            let spotify_track_id_4 = "626wlz3bovvpH06PYht5R0";
            let spotify_track_id_5 = "4rQYDXfKFikLX4ad674jhg";
            let spotify_playlist_id = "626wlz3bovvpH06PYht5R0";
            let track_1 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_1.into()),
                title: "time".into(),
                year: 1973,
            };
            let track_2 = Track {
                album: Album {
                    compil: false,
                    name: "(what's the story) morning glory?".into(),
                },
                artists: BTreeSet::from_iter(["oasis".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_2.into()),
                title: "wonderwall".into(),
                year: 1995,
            };
            let track_3 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: None,
                title: "money".into(),
                year: 1973,
            };
            let track_4 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_4.into()),
                title: "us and them".into(),
                year: 1973,
            };
            let track_5 = Track {
                album: Album {
                    compil: false,
                    name: "the dark side of the moon".into(),
                },
                artists: BTreeSet::from_iter(["pink floyd".into()]),
                creation: Utc::now(),
                id: Uuid::new_v4(),
                spotify_id: Some(spotify_track_id_5.into()),
                title: "speak to me".into(),
                year: 1973,
            };
            let spotify_token = SpotifyToken {
                access: "access".into(),
                expiration: Utc::now(),
                refresh: "refresh".into(),
            };
            let data = Data {
                playlist: Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "playlist".into(),
                    predicate: Predicate::YearEquals(1973),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                        owner: User {
                            creation: Utc::now(),
                            creds: Credentials {
                                spotify: Some(SpotifyCredentials {
                                    id: "id".into(),
                                    token: spotify_token.clone(),
                                }),
                            },
                            email: "user@test".into(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        },
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify(spotify_playlist_id.into()),
                },
                spotify_playlist_id,
                spotify_token,
                state: SynchronizationState {
                    start: Utc::now(),
                    step: PlaylistSynchronizationStep::DeleteTracks(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: PlaylistSynchronizationStep::Finished,
            };
            let mocks = Mocks {
                remove_tracks_from_spotify_playlist: Mock::once_with_args(move |tracks| {
                    assert_eq!(
                        tracks,
                        vec![spotify_track_id_1, spotify_track_id_2, spotify_track_id_5],
                    );
                }),
                src_contains_tracks: Mock::with(vec![
                    Box::new({
                        let expected = track_1.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_3.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                    Box::new({
                        let expected = track_4.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            true
                        }
                    }),
                    Box::new({
                        let expected = track_5.id;
                        move |track_id| {
                            assert_eq!(track_id, expected);
                            false
                        }
                    }),
                ]),
                playlist_tracks: Mock::once_with_args(move |req| {
                    let expected = PageRequest::new(TRACK_PAGE_LIMIT, expected_offset);
                    assert_eq!(req, expected);
                    Page {
                        first: true,
                        items: vec![
                            track_1.clone(),
                            track_2.clone(),
                            track_3.clone(),
                            track_4.clone(),
                            track_5.clone(),
                        ],
                        last: true,
                        req: PageRequest::new(TRACK_PAGE_LIMIT, expected_offset),
                        total: 0,
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            let succeeded = succeeded.expect("failed to process state");
            assert!(succeeded);
            assert_eq!(state, expected);
        }
    }

    mod source_state_processor {
        use super::*;

        // Data

        #[derive(Clone)]
        struct Data {
            src: Source,
            state: SourceSynchronizationState,
        }

        // Mocks

        #[derive(Default)]
        struct Mocks {
            delete_tracks_from_src: Mock<()>,
            playlist_ids_by_src: Mock<Page<Uuid>, PageRequest>,
            publish_playlist_message: Mock<(), PlaylistMessage>,
            pull: Mock<Page<Track>, (Source, u32)>,
        }

        // run

        async fn run(data: Data, mocks: Mocks) -> (bool, SourceSynchronizationState) {
            let mut db_conn = MockDatabaseConnection::new();
            db_conn
                .0
                .expect_delete_tracks_from_source()
                .with(eq(data.src.id))
                .times(mocks.delete_tracks_from_src.times())
                .returning(|_| Ok(()));
            db_conn
                .0
                .expect_playlist_ids_by_source()
                .with(eq(data.src.id), always())
                .times(mocks.playlist_ids_by_src.times())
                .returning({
                    let mock = mocks.playlist_ids_by_src.clone();
                    move |_, req| Ok(mock.call_with_args(req))
                });
            let puller = MockPuller::new(mocks.pull);
            let mut publisher = MockPublisher::new();
            publisher
                .expect_publish_playlist_message()
                .times(mocks.publish_playlist_message.times())
                .returning({
                    let mock = mocks.publish_playlist_message.clone();
                    move |msg| {
                        mock.call_with_args(msg.clone());
                        Ok(())
                    }
                });
            let svc = MockServices {
                publisher,
                ..Default::default()
            };
            let proc = SourceStateProcessor(puller);
            let mut src = data.src.clone();
            let mut state = data.state.clone();
            let succeeded = proc
                .process(&mut src, &mut state, &mut db_conn, &svc)
                .await
                .expect("failed to process state");
            (succeeded, state)
        }

        // Tests

        #[tokio::test]
        async fn delete_old_pull() {
            let data = Data {
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                state: SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::DeleteOldPull,
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: SourceSynchronizationStep::PullFromPlatform(0),
            };
            let mocks = Mocks {
                delete_tracks_from_src: Mock::once(|| ()),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn pull_from_platform_0() {
            let expected_offset = 0;
            let data = Data {
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                state: SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PullFromPlatform(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: SourceSynchronizationStep::PullFromPlatform(spotify::PAGE_LIMIT_MAX),
            };
            let mocks = Mocks {
                pull: Mock::once_with_args({
                    let data = data.clone();
                    move |(src, offset)| {
                        assert_eq!(src, data.src);
                        assert_eq!(offset, expected_offset);
                        Page {
                            first: true,
                            items: vec![],
                            last: false,
                            req: PageRequest::new(spotify::PAGE_LIMIT_MAX, expected_offset),
                            total: 0,
                        }
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn pull_from_platform_50() {
            let expected_offset = 50;
            let data = Data {
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                state: SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PullFromPlatform(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: SourceSynchronizationStep::PublishPlaylistMessages(0),
            };
            let mocks = Mocks {
                pull: Mock::once_with_args({
                    let data = data.clone();
                    move |(src, offset)| {
                        assert_eq!(src, data.src);
                        assert_eq!(offset, expected_offset);
                        Page {
                            first: true,
                            items: vec![],
                            last: true,
                            req: PageRequest::new(spotify::PAGE_LIMIT_MAX, expected_offset),
                            total: 0,
                        }
                    }
                }),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn publish_playlist_messages_0() {
            let expected_offset = 0;
            let playlist_id_1 = Uuid::new_v4();
            let playlist_id_2 = Uuid::new_v4();
            let data = Data {
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                state: SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PublishPlaylistMessages(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: SourceSynchronizationStep::PublishPlaylistMessages(PLAYLIST_PAGE_LIMIT),
            };
            let mocks = Mocks {
                playlist_ids_by_src: Mock::once_with_args({
                    move |req| {
                        let expected = PageRequest::new(PLAYLIST_PAGE_LIMIT, expected_offset);
                        assert_eq!(req, expected);
                        Page {
                            first: true,
                            items: vec![playlist_id_1, playlist_id_2],
                            last: false,
                            req: expected,
                            total: 0,
                        }
                    }
                }),
                publish_playlist_message: Mock::with(vec![
                    Box::new(move |msg| {
                        let expected = PlaylistMessage {
                            id: playlist_id_1,
                            kind: PlaylistMessageKind::Sync,
                        };
                        assert_eq!(msg, expected);
                    }),
                    Box::new(move |msg| {
                        let expected = PlaylistMessage {
                            id: playlist_id_2,
                            kind: PlaylistMessageKind::Sync,
                        };
                        assert_eq!(msg, expected);
                    }),
                ]),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            assert!(!succeeded);
            assert_eq!(state, expected);
        }

        #[tokio::test]
        async fn publish_playlist_messages_100() {
            let expected_offset = PLAYLIST_PAGE_LIMIT;
            let playlist_id_1 = Uuid::new_v4();
            let playlist_id_2 = Uuid::new_v4();
            let data = Data {
                src: Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifyResourceKind::SavedTracks),
                    owner: User {
                        creation: Utc::now(),
                        creds: Default::default(),
                        email: "user@test".into(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    },
                    sync: Synchronization::Pending,
                },
                state: SynchronizationState {
                    start: Utc::now(),
                    step: SourceSynchronizationStep::PublishPlaylistMessages(expected_offset),
                },
            };
            let expected = SynchronizationState {
                start: data.state.start,
                step: SourceSynchronizationStep::Finished,
            };
            let mocks = Mocks {
                playlist_ids_by_src: Mock::once_with_args({
                    move |req| {
                        let expected = PageRequest::new(PLAYLIST_PAGE_LIMIT, expected_offset);
                        assert_eq!(req, expected);
                        Page {
                            first: true,
                            items: vec![playlist_id_1, playlist_id_2],
                            last: true,
                            req: expected,
                            total: 0,
                        }
                    }
                }),
                publish_playlist_message: Mock::with(vec![
                    Box::new(move |msg| {
                        let expected = PlaylistMessage {
                            id: playlist_id_1,
                            kind: PlaylistMessageKind::Sync,
                        };
                        assert_eq!(msg, expected);
                    }),
                    Box::new(move |msg| {
                        let expected = PlaylistMessage {
                            id: playlist_id_2,
                            kind: PlaylistMessageKind::Sync,
                        };
                        assert_eq!(msg, expected);
                    }),
                ]),
                ..Default::default()
            };
            let (succeeded, state) = run(data, mocks).await;
            assert!(succeeded);
            assert_eq!(state, expected);
        }
    }
}
