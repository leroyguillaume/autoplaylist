use std::{error::Error as StdError, result::Result as StdResult};

use async_trait::async_trait;

use crate::domain::SpotifyToken;

// Result

pub type Result<T> = StdResult<T, Box<dyn StdError + Send + Sync>>;

// Client

#[async_trait]
pub trait Client: Send + Sync {
    async fn auth_url(&self) -> Result<String>;

    async fn request_token(&self, code: &str) -> Result<SpotifyToken>;

    async fn user_email(&self, token: &SpotifyToken) -> Result<String>;
}

// Mods

pub mod rspotify;
