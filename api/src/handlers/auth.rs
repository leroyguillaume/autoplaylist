use actix_web::{get, http::header, web::Data, HttpResponse, Responder};
use rspotify::{scopes, AuthCodeSpotify, Credentials, OAuth};
use tracing::debug;

use crate::{
    cfg::Config,
    handlers::{handle, Error},
};

// Funtions - Handlers

#[get("/auth/spotify")]
async fn spotify_redirect(cfg: Data<Config>) -> impl Responder {
    handle(move || {
        let spotify = spotify_oauth_client(&cfg);
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
fn spotify_oauth_client(cfg: &Config) -> AuthCodeSpotify {
    let creds = Credentials {
        id: cfg.spotify_client_id.clone(),
        secret: Some(cfg.spotify_client_secret.clone()),
    };
    let oauth = OAuth {
        redirect_uri: format!("{}/auth/spotify", cfg.webapp_url),
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
