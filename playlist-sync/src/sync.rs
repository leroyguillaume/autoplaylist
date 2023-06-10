use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::Sync as StdSync,
    result::Result as StdResult,
    sync::Arc,
};

use async_trait::async_trait;
use autoplaylist_core::{
    db::Pool as DatabasePool,
    domain::{Playlist, Sync},
};
use tokio::sync::watch::Receiver;

// Result

pub type Result<T> = StdResult<T, Error>;

// ErrorKind

#[derive(Debug)]
pub enum ErrorKind {}

// Error

#[derive(Debug)]
pub struct Error {
    _kind: ErrorKind,
    pub sync: Sync,
}

impl Display for Error {
    fn fmt(&self, _f: &mut Formatter) -> FmtResult {
        Ok(())
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        None
    }
}

// Synchronizer

#[async_trait]
pub trait Synchronizer: Send + StdSync {
    async fn sync(&self, playlist: &Playlist, sync: Sync) -> Result<Sync>;
}

// DefaultSynchronizer

pub struct DefaultSynchronizer {
    pub db_pool: Arc<Box<dyn DatabasePool>>,
    pub stop_rx: Receiver<()>,
}

#[async_trait]
impl Synchronizer for DefaultSynchronizer {
    async fn sync(&self, _playlist: &Playlist, mut _sync: Sync) -> Result<Sync> {
        todo!()
    }
}
