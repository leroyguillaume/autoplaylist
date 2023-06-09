use actix_web::{
    body::BoxBody,
    delete, get, post,
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::{
    broker::{BaseEvent, BaseEventKind},
    db::in_transaction,
    domain::{Base, Playlist, PlaylistFilter},
};
use chrono::Utc;
use tracing::{info, trace};
use uuid::Uuid;
use validator::Validate;

use crate::{
    dto::{
        CreatePlaylistRequest, PageQuery, PageResponse, PlaylistResponse, DEFAULT_PAGE_LIMIT,
        DEFAULT_PAGE_OFFSET,
    },
    handlers::{authenticated_user, Error, Result},
    Components,
};

// Functions - Handlers

#[post("/playlist")]
async fn create(
    req: HttpRequest,
    payload: Json<CreatePlaylistRequest>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let mut db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let auth_user = authenticated_user(
        &req,
        &cmpts.jwt_cfg,
        db_client.repositories().user().as_ref(),
    )
    .await?;
    let auth_user_id = auth_user.id;
    trace!("validating {payload:?}");
    payload.validate().map_err(Error::RequestValidation)?;
    let now = Utc::now();
    let (playlist, base_created) = in_transaction(db_client.as_mut(), move |tx| {
        Box::pin(async move {
            let repos = tx.repositories();
            let base_repo = repos.base();
            let playlist_repo = repos.playlist();
            let base = base_repo
                .get_by_user_kind_platform(&auth_user.id, &payload.base.kind, payload.base.platform)
                .await
                .map_err(Error::DatabaseClient)?;
            let (base, base_created) = match base {
                Some(base) => {
                    let playlist = repos
                        .playlist()
                        .get_by_user_name(&auth_user.id, &payload.name)
                        .await
                        .map_err(Error::DatabaseClient)?;
                    if let Some(playlist) = playlist {
                        return Err(Error::PlaylistAlreadyExists(playlist.id));
                    }
                    (base, false)
                }
                None => {
                    let base = Base {
                        creation_date: now,
                        id: Uuid::new_v4(),
                        kind: payload.base.kind.clone(),
                        platform: payload.base.platform,
                        sync: None,
                        user: auth_user,
                    };
                    base_repo
                        .insert(&base)
                        .await
                        .map_err(Error::DatabaseClient)?;
                    (base, true)
                }
            };
            let playlist = Playlist {
                base_id: base.id,
                creation_date: now,
                id: Uuid::new_v4(),
                name: payload.name.clone(),
                user_id: auth_user_id,
            };
            let filters: Vec<PlaylistFilter> = payload
                .filters
                .clone()
                .into_iter()
                .map(PlaylistFilter::from)
                .collect();
            playlist_repo
                .insert(&playlist, &filters)
                .await
                .map_err(Error::DatabaseClient)?;
            Ok::<(Playlist, bool), Error>((playlist, base_created))
        })
    })
    .await
    .map_err(Error::from)?;
    info!("new playlist created");
    if base_created {
        let event = BaseEvent {
            id: playlist.base_id,
            kind: BaseEventKind::Created,
        };
        cmpts
            .base_event_prd
            .produce(&event)
            .await
            .map_err(Error::broker_client)?;
    }
    let resp: PlaylistResponse = playlist.into();
    Ok(HttpResponse::Created().json(resp))
}

#[delete("/playlist/{id}")]
async fn delete(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let auth_user = authenticated_user(
        &req,
        &cmpts.jwt_cfg,
        db_client.repositories().user().as_ref(),
    )
    .await?;
    let repos = db_client.repositories();
    let playlist_repo = repos.playlist();
    let playlist = playlist_repo
        .get_by_id(&path)
        .await
        .map_err(Error::DatabaseClient)?;
    let playlist = match playlist {
        Some(playlist) => playlist,
        None => {
            return Err(Error::PlaylistNotFound(*path));
        }
    };
    if playlist.user_id != auth_user.id {
        return Err(Error::PlaylistNotOwnedByAuthenticatedUser(playlist.id));
    }
    playlist_repo
        .delete(&playlist.id)
        .await
        .map_err(Error::DatabaseClient)?;
    info!("playlist {} deleted", playlist.id);
    let resp: HttpResponse<BoxBody> = HttpResponse::NoContent().into();
    Ok(resp)
}

#[get("/playlist")]
async fn list(
    req: HttpRequest,
    page: Query<PageQuery>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let auth_user = authenticated_user(
        &req,
        &cmpts.jwt_cfg,
        db_client.repositories().user().as_ref(),
    )
    .await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = db_client
        .repositories()
        .playlist()
        .list_by_user(&auth_user.id, limit, offset)
        .await
        .map_err(Error::DatabaseClient)?;
    let resp: PageResponse<PlaylistResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}
