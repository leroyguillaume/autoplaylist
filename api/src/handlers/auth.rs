use actix_web::{get, http::header, web::Data, HttpResponse, Responder};
use rspotify::{scopes, AuthCodeSpotify, Credentials, OAuth};
use tracing::debug;

use crate::{
    cfg::{Config, SpotifyConfig},
    handlers::{handle, Error},
};

// Funtions - Handlers

#[get("/auth/spotify")]
async fn spotify_redirect(cfg: Data<Config>) -> impl Responder {
    handle(move || {
        let spotify = spotify_oauth_client(cfg.spotify.clone());
        debug!("computing Spotify authorize URL");
        let url = spotify
            .get_authorize_url(false)
            .map_err(Error::SpotifyClientFailed)?;
        debug!("sending redirect to {url}");
        let mut resp = HttpResponse::TemporaryRedirect();
        resp.insert_header((header::LOCATION, url));
        Ok(resp.into())
    })
}

// Functions - Utils

#[inline]
fn spotify_oauth_client(cfg: SpotifyConfig) -> AuthCodeSpotify {
    let creds = Credentials {
        id: cfg.id,
        secret: Some(cfg.secret),
    };
    let oauth = OAuth {
        redirect_uri: cfg.redirect_url,
        scopes: scopes!(
            "playlist-modify-private",
            "playlist-modify-public",
            "playlist-read-collaborative",
            "playlist-read-private",
            "user-follow-read",
            "user-library-read",
            "user-modify-playback-state",
            "user-read-currently-playing",
            "user-read-playback-position",
            "user-read-playback-state",
            "user-read-recently-played",
            "user-read-email",
            "user-read-private",
            "user-top-read"
        ),
        ..Default::default()
    };
    AuthCodeSpotify::new(creds, oauth)
}
