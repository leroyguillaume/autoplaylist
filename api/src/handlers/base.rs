use actix_web::{
    body::BoxBody,
    get, put,
    web::{Data, Path, Query},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::{
    broker::{BaseCommand, BaseCommandKind},
    domain::Role,
};
use tracing::info;
use uuid::Uuid;

use crate::{
    dto::{BaseResponse, PageQuery, PageResponse, DEFAULT_PAGE_LIMIT, DEFAULT_PAGE_OFFSET},
    handlers::{current_user, Error, Result},
    Components,
};

#[get("/base")]
async fn list_bases(
    req: HttpRequest,
    page: Query<PageQuery>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let repos = db_client.repositories();
    let auth_user = current_user(&req, &cmpts.jwt_cfg, repos.user().as_ref()).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = repos
        .base()
        .list_by_user(&auth_user.id, limit, offset)
        .await
        .map_err(Error::DatabaseClient)?;
    let resp: PageResponse<BaseResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}

#[put("/base/{id}")]
async fn start_base_sync(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let auth_user = current_user(
        &req,
        &cmpts.jwt_cfg,
        db_client.repositories().user().as_ref(),
    )
    .await?;
    if auth_user.role != Role::Admin {
        return Err(Error::AuthenticatedUserIsNotAdmin(auth_user.id));
    }
    let cmd = BaseCommand {
        id: *path,
        kind: BaseCommandKind::Sync,
    };
    cmpts
        .base_cmd_prd
        .produce(&cmd)
        .await
        .map_err(Error::broker_client)?;
    info!("synchronization requested for base {}", *path);
    Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::NoContent().into())
}
