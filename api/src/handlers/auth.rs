use std::collections::BTreeMap;

use actix_web::{
    body::BoxBody,
    get,
    http::header,
    post,
    web::{Data, Json},
    HttpResponse, Responder,
};
use chrono::Utc;
use jwt::{Claims, RegisteredClaims, SignWithKey};
use rspotify::{prelude::OAuthClient, scopes, AuthCodeSpotify, Credentials, OAuth};
use serde_json::json;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    cfg::{JwtConfig, SpotifyConfig},
    db::{
        client_from_pool, in_transaction, insert_user, upsert_spotify_auth, user_by_spotify_email,
    },
    domain::{Role, SpotifyAuth, User},
    dto::{AuthWithSpotifyRequest, JwtResponse},
    handlers::{generate_jwt_key, Error, Result, ROLE_JWT_CLAIM_KEY},
    Components,
};

// Functions - Handlers

#[post("/auth/spotify")]
async fn auth_with_spotify(
    payload: Json<AuthWithSpotifyRequest>,
    cmpts: Data<Components>,
) -> impl Responder {
    handle!(async {
        let spotify = spotify_oauth_client(cmpts.spotify_cfg.clone());
        debug!("requesting Spotify token");
        spotify
            .request_token(&payload.code)
            .await
            .map_err(Error::SpotifyClientFailed)?;
        debug!("requesting Spotify user");
        let user = spotify
            .current_user()
            .await
            .map_err(Error::SpotifyClientFailed)?;
        debug!("user: {user:?}");
        let token = spotify
            .token
            .lock()
            .await
            .map_err(|_| Error::SpotifyClientTokenLockFailed)?
            .clone()
            .ok_or(Error::NoSpotifyToken)?;
        let email = user.email.ok_or(Error::NoSpotifyUserEmail)?;
        let mut db_client = client_from_pool(&cmpts.db_pool)
            .await
            .map_err(Error::DatabasePoolFailed)?;
        let (user, user_created) = in_transaction(&mut db_client, move |tx| {
            Box::pin(async move {
                let user = user_by_spotify_email(&email, tx.client())
                    .await
                    .map_err(Error::DatabaseClientFailed)?;
                debug!("user fetched: {user:?}");
                let (user, user_created) = match user {
                    Some(user) => (user, false),
                    None => {
                        let user = User {
                            creation_date: Utc::now(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        };
                        insert_user(&user, tx.client())
                            .await
                            .map_err(Error::DatabaseClientFailed)?;
                        (user, true)
                    }
                };
                let auth = SpotifyAuth {
                    access_token: token.access_token,
                    email,
                    refresh_token: token.refresh_token,
                    user_id: user.id,
                };
                upsert_spotify_auth(&auth, tx.client())
                    .await
                    .map_err(Error::DatabaseClientFailed)?;
                Ok::<(User, bool), Error>((user, user_created))
            })
        })
        .await
        .map_err(Error::from)?;
        if user_created {
            info!("new user created");
        }
        let jwt = generate_jwt(&user, &cmpts.jwt_cfg)?;
        Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::Ok().json(JwtResponse { jwt }))
    })
}

#[get("/auth/spotify")]
async fn spotify_redirect(cmpts: Data<Components>) -> impl Responder {
    handle!(async {
        let spotify = spotify_oauth_client(cmpts.spotify_cfg.clone());
        debug!("computing Spotify authorize URL");
        let url = spotify
            .get_authorize_url(false)
            .map_err(Error::SpotifyClientFailed)?;
        debug!("sending redirect to {url}");
        let mut resp = HttpResponse::TemporaryRedirect();
        resp.insert_header((header::LOCATION, url));
        Ok::<HttpResponse<BoxBody>, Error>(resp.into())
    })
}

// Functions - Utils

#[inline]
fn generate_jwt(user: &User, cfg: &JwtConfig) -> Result<String> {
    debug!("generating JWT for {user:?}");
    let expiration_date = Utc::now() + cfg.validity;
    let expiration_ts: u64 = expiration_date
        .timestamp()
        .try_into()
        .map_err(Error::TimestampConversionFailed)?;
    let claims = Claims {
        private: BTreeMap::from_iter([(ROLE_JWT_CLAIM_KEY.into(), json!(user.role))]),
        registered: RegisteredClaims {
            expiration: Some(expiration_ts),
            issuer: Some(cfg.issuer.clone()),
            subject: Some(format!("{}", user.id)),
            ..Default::default()
        },
    };
    let key = generate_jwt_key(cfg)?;
    claims
        .sign_with_key(&key)
        .map_err(Error::JwtGenerationFailed)
}

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
