use actix_web::{
    body::BoxBody,
    delete, get, post,
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::{
    broker::{send_base_event, BaseEvent, BaseEventKind},
    db::{
        base, client_from_pool, delete_playlist as delete_playlist_from_database, in_transaction,
        insert_base, insert_playlist, list_playlists as list_playlists_from_database,
        playlist_by_id, playlist_by_name,
    },
    domain::{Base, Playlist, Sync},
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
    handlers::{current_user, Error, Result},
    Components,
};

// Functions - Handlers

#[post("/playlist")]
async fn create_playlist(
    req: HttpRequest,
    payload: Json<CreatePlaylistRequest>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let mut db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    trace!("validating {payload:?}");
    payload.validate().map_err(Error::RequestValidation)?;
    let now = Utc::now();
    let (playlist, base_created) = in_transaction(&mut db_client, move |tx| {
        Box::pin(async move {
            let base = base(
                &auth_user.id,
                &payload.base.kind,
                &payload.base.platform,
                tx.client(),
            )
            .await
            .map_err(Error::DatabaseClient)?;
            let (base, base_created) = match base {
                Some(base) => {
                    let playlist = playlist_by_name(&payload.name, tx.client())
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
                        sync: Sync {
                            last_err_msg: None,
                            last_start_date: None,
                            last_success_date: None,
                            state: None,
                        },
                        user_id: auth_user.id,
                    };
                    insert_base(&base, tx.client())
                        .await
                        .map_err(Error::DatabaseClient)?;
                    (base, true)
                }
            };
            let playlist = Playlist {
                base,
                creation_date: now,
                id: Uuid::new_v4(),
                name: payload.name.clone(),
                user_id: auth_user.id,
            };
            insert_playlist(&playlist, &payload.filters, tx.client())
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
            id: playlist.base.id,
            kind: BaseEventKind::Created,
        };
        send_base_event(&event, &cmpts.channels.base_event)
            .await
            .map_err(Error::BrokerClient)?;
    }
    let resp: PlaylistResponse = playlist.into();
    Ok(HttpResponse::Created().json(resp))
}

#[delete("/playlist/{id}")]
async fn delete_playlist(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    let playlist = playlist_by_id(&path, &db_client)
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
    delete_playlist_from_database(&playlist.id, &db_client)
        .await
        .map_err(Error::DatabaseClient)?;
    info!("playlist {} deleted", playlist.id);
    let resp: HttpResponse<BoxBody> = HttpResponse::NoContent().into();
    Ok(resp)
}

#[get("/playlist")]
async fn list_playlists(
    req: HttpRequest,
    page: Query<PageQuery>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = list_playlists_from_database(&auth_user.id, limit.into(), offset.into(), &db_client)
        .await
        .map_err(Error::DatabaseClient)?;
    let resp: PageResponse<PlaylistResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}
