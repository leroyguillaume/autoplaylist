use actix_web::{
    body::BoxBody,
    get, put,
    web::{Data, Path, Query},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::broker::{BaseCommand, BaseCommandKind};
use tracing::info;
use uuid::Uuid;

use crate::{
    dto::{BaseResponse, PageQuery, PageResponse, DEFAULT_PAGE_LIMIT, DEFAULT_PAGE_OFFSET},
    handlers::{authenticated_admin, Error, Result},
    Components,
};

// list_bases

#[get("/sync/base")]
async fn list_bases(
    req: HttpRequest,
    page: Query<PageQuery>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    let repos = db_client.repositories();
    authenticated_admin(&req, &cmpts.jwt_cfg, repos.user().as_ref()).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = repos
        .base()
        .list(limit, offset)
        .await
        .map_err(Error::DatabaseClient)?;
    let resp: PageResponse<BaseResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}

#[put("/sync/base/{id}")]
async fn base_sync(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = cmpts.db_pool.client().await.map_err(Error::DatabasePool)?;
    authenticated_admin(
        &req,
        &cmpts.jwt_cfg,
        db_client.repositories().user().as_ref(),
    )
    .await?;
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
