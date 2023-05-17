use actix_web::{
    body::BoxBody,
    delete, get, post,
    web::{Data, Json, Path, Query as ActixQuery},
    HttpRequest, HttpResponse, Responder,
};
use chrono::Utc;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::{
    db::{
        base, delete_query as delete_query_from_database, insert_base, insert_query,
        list_queries as list_queries_from_database, query, query_by_id,
    },
    domain::{Base, Query},
    dto::{
        CreateQueryRequest, PageQuery, PageResponse, QueryResponse, DEFAULT_PAGE_LIMIT,
        DEFAULT_PAGE_OFFSET,
    },
    handlers::{current_user, Error},
    Components,
};

// Functions - Handlers

#[post("/query")]
async fn create_query(
    req: HttpRequest,
    payload: Json<CreateQueryRequest>,
    cmpts: Data<Components>,
) -> impl Responder {
    handle!(async {
        trace!("getting database client from pool");
        let mut db_client = cmpts
            .db_pool
            .get()
            .await
            .map_err(Error::DatabasePoolFailed)?;
        let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
        if payload.grouping.is_none() {
            return Err(Error::EmptyQuery);
        }
        trace!("opening database transaction");
        let tx = db_client
            .transaction()
            .await
            .map_err(Error::DatabaseClientFailed)?;
        let now = Utc::now();
        let query = transactional!(tx, async {
            let base = base(
                &auth_user.id,
                &payload.base.kind,
                &payload.base.platform,
                tx.client(),
            )
            .await
            .map_err(Error::DatabaseClientFailed)?;
            debug!("base fetched: {base:?}");
            let base = match base {
                Some(base) => {
                    let query = query(
                        &base.id,
                        payload.name_prefix.as_ref(),
                        payload.grouping.as_ref(),
                        tx.client(),
                    )
                    .await
                    .map_err(Error::DatabaseClientFailed)?;
                    debug!("query fetched: {query:?}");
                    if let Some(query) = query {
                        return Err(Error::QueryAlreadyExists(query.id));
                    }
                    base
                }
                None => {
                    let base = Base {
                        creation_date: now,
                        id: Uuid::new_v4(),
                        user_id: auth_user.id,
                        kind: payload.base.kind.clone(),
                        platform: payload.base.platform,
                    };
                    insert_base(&base, tx.client())
                        .await
                        .map_err(Error::DatabaseClientFailed)?;
                    base
                }
            };
            let query = Query {
                base,
                creation_date: now,
                grouping: payload.grouping,
                id: Uuid::new_v4(),
                name_prefix: payload.name_prefix.clone(),
                user_id: auth_user.id,
            };
            insert_query(&query, tx.client())
                .await
                .map_err(Error::DatabaseClientFailed)?;
            Ok::<Query, Error>(query)
        })?;
        info!("new query created");
        let resp: QueryResponse = query.into();
        Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::Created().json(resp))
    })
}

#[delete("/query/{id}")]
async fn delete_query(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> impl Responder {
    handle!(async {
        trace!("getting database client from pool");
        let db_client = cmpts
            .db_pool
            .get()
            .await
            .map_err(Error::DatabasePoolFailed)?;
        let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
        let query = query_by_id(&path, &db_client)
            .await
            .map_err(Error::DatabaseClientFailed)?;
        debug!("query fetched: {query:?}");
        let query = match query {
            Some(query) => query,
            None => {
                return Err(Error::QueryNotFound(*path));
            }
        };
        if query.user_id != auth_user.id {
            return Err(Error::QueryNotOwnedByAuthenticatedUser(query.id));
        }
        delete_query_from_database(&query.id, &db_client)
            .await
            .map_err(Error::DatabaseClientFailed)?;
        info!("query {} deleted", query.id);
        Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::NoContent().into())
    })
}

#[get("/query")]
async fn list_queries(
    req: HttpRequest,
    page: ActixQuery<PageQuery>,
    cmpts: Data<Components>,
) -> impl Responder {
    handle!(async {
        trace!("getting database client from pool");
        let db_client = cmpts
            .db_pool
            .get()
            .await
            .map_err(Error::DatabasePoolFailed)?;
        let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
        let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
        let page =
            list_queries_from_database(&auth_user.id, limit.into(), offset.into(), &db_client)
                .await
                .map_err(Error::DatabaseClientFailed)?;
        debug!("page fetched: {page:?}");
        let resp: PageResponse<QueryResponse> = page.into();
        Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::Ok().json(resp))
    })
}
