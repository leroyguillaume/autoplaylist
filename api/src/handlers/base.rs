use actix_web::{
    get,
    web::{Data, Query},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::db::{client_from_pool, list_bases as list_bases_from_database};
use tracing::debug;

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
    let db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = list_bases_from_database(&auth_user.id, limit.into(), offset.into(), &db_client)
        .await
        .map_err(Error::DatabaseClient)?;
    debug!("page fetched: {page:?}");
    let resp: PageResponse<BaseResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}
