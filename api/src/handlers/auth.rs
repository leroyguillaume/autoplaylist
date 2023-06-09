use std::collections::BTreeMap;

use actix_web::{
    body::BoxBody,
    get,
    http::header,
    post,
    web::{Data, Json},
    HttpResponse, Responder,
};
use autoplaylist_core::{
    db::in_transaction,
    domain::{Role, SpotifyAuth, User},
};
use chrono::Utc;
use jwt::{Claims, RegisteredClaims, SignWithKey};
use serde_json::json;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    cfg::JwtConfig,
    dto::{AuthWithSpotifyRequest, JwtResponse},
    handlers::{generate_jwt_key, Error, Result, ROLE_JWT_CLAIM_KEY},
    Components,
};

// Functions - Handlers

#[post("/auth/spotify")]
async fn auth_with_spotify(
    payload: Json<AuthWithSpotifyRequest>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let token = cmpts
        .spotify_client
        .request_token(&payload.code)
        .await
        .map_err(Error::SpotifyClient)?;
    let email = cmpts
        .spotify_client
        .user_email(&token)
        .await
        .map_err(Error::SpotifyClient)?;
    let mut db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let (user, user_created) = in_transaction(db_client.as_mut(), move |tx| {
        Box::pin(async move {
            let repos = tx.repositories();
            let user_repo = repos.user();
            let user = user_repo
                .get_by_spotify_email(&email)
                .await
                .map_err(Error::DatabaseClient)?;
            let (user, user_created) = match user {
                Some(user) => (user, false),
                None => {
                    let user = User {
                        creation_date: Utc::now(),
                        id: Uuid::new_v4(),
                        role: Role::User,
                    };
                    user_repo
                        .insert(&user)
                        .await
                        .map_err(Error::DatabaseClient)?;
                    (user, true)
                }
            };
            let auth = SpotifyAuth {
                email,
                token,
                user_id: user.id,
            };
            user_repo
                .upsert_spotify_auth(&auth)
                .await
                .map_err(Error::DatabaseClient)?;
            Ok::<(User, bool), Error>((user, user_created))
        })
    })
    .await
    .map_err(Error::from)?;
    if user_created {
        info!("new user created");
    }
    let jwt = generate_jwt(&user, &cmpts.jwt_cfg)?;
    Ok(HttpResponse::Ok().json(JwtResponse { jwt }))
}

#[get("/auth/spotify")]
async fn spotify_redirect(cmpts: Data<Components>) -> Result<impl Responder> {
    let url = cmpts
        .spotify_client
        .auth_url()
        .await
        .map_err(Error::SpotifyClient)?;
    debug!("sending redirect to {url}");
    let mut resp = HttpResponse::TemporaryRedirect();
    resp.insert_header((header::LOCATION, url));
    let resp: HttpResponse<BoxBody> = resp.into();
    Ok(resp)
}

// Functions - Utils

#[inline]
fn generate_jwt(user: &User, cfg: &JwtConfig) -> Result<String> {
    debug!("generating JWT for {user:?}");
    let expiration_date = Utc::now() + cfg.validity;
    let expiration_ts: u64 = expiration_date
        .timestamp()
        .try_into()
        .map_err(Error::TimestampConversion)?;
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
    claims.sign_with_key(&key).map_err(Error::JwtGeneration)
}
