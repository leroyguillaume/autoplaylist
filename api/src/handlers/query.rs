use actix_web::{
    body::BoxBody,
    delete, get, post,
    web::{Data, Json, Path, Query as ActixQuery},
    HttpRequest, HttpResponse, Responder,
};
use autoplaylist_core::{
    broker::{send_base_event, BaseEvent, BaseEventKind},
    db::{
        base, client_from_pool, delete_query as delete_query_from_database, in_transaction,
        insert_base, insert_query, list_queries as list_queries_from_database, query, query_by_id,
    },
    domain::{Base, Query},
};
use chrono::Utc;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    dto::{
        CreateQueryRequest, PageQuery, PageResponse, QueryResponse, DEFAULT_PAGE_LIMIT,
        DEFAULT_PAGE_OFFSET,
    },
    handlers::{current_user, Error, Result},
    Components,
};

// Functions - Handlers

#[post("/query")]
async fn create_query(
    req: HttpRequest,
    payload: Json<CreateQueryRequest>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let mut db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    if payload.grouping.is_none() {
        return Err(Error::EmptyQuery);
    }
    let now = Utc::now();
    let (query, base_created) = in_transaction(&mut db_client, move |tx| {
        Box::pin(async move {
            let base = base(
                &auth_user.id,
                &payload.base.kind,
                &payload.base.platform,
                tx.client(),
            )
            .await
            .map_err(Error::DatabaseClient)?;
            debug!("base fetched: {base:?}");
            let (base, base_created) = match base {
                Some(base) => {
                    let query = query(
                        &base.id,
                        payload.name_prefix.as_ref(),
                        payload.grouping.as_ref(),
                        tx.client(),
                    )
                    .await
                    .map_err(Error::DatabaseClient)?;
                    debug!("query fetched: {query:?}");
                    if let Some(query) = query {
                        return Err(Error::QueryAlreadyExists(query.id));
                    }
                    (base, false)
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
                        .map_err(Error::DatabaseClient)?;
                    (base, true)
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
                .map_err(Error::DatabaseClient)?;
            Ok::<(Query, bool), Error>((query, base_created))
        })
    })
    .await
    .map_err(Error::from)?;
    info!("new query created");
    if base_created {
        let event = BaseEvent {
            id: query.base.id,
            kind: BaseEventKind::Created,
        };
        send_base_event(&event, &cmpts.channels.base_event)
            .await
            .map_err(Error::BrokerClient)?;
    }
    let resp: QueryResponse = query.into();
    Ok(HttpResponse::Created().json(resp))
}

#[delete("/query/{id}")]
async fn delete_query(
    req: HttpRequest,
    path: Path<Uuid>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    let query = query_by_id(&path, &db_client)
        .await
        .map_err(Error::DatabaseClient)?;
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
        .map_err(Error::DatabaseClient)?;
    info!("query {} deleted", query.id);
    let resp: HttpResponse<BoxBody> = HttpResponse::NoContent().into();
    Ok(resp)
}

#[get("/query")]
async fn list_queries(
    req: HttpRequest,
    page: ActixQuery<PageQuery>,
    cmpts: Data<Components>,
) -> Result<impl Responder> {
    let db_client = client_from_pool(&cmpts.db_pool)
        .await
        .map_err(Error::DatabasePool)?;
    let auth_user = current_user(&req, &cmpts.jwt_cfg, &db_client).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    let offset = page.offset.unwrap_or(DEFAULT_PAGE_OFFSET);
    let page = list_queries_from_database(&auth_user.id, limit.into(), offset.into(), &db_client)
        .await
        .map_err(Error::DatabaseClient)?;
    debug!("page fetched: {page:?}");
    let resp: PageResponse<QueryResponse> = page.into();
    Ok(HttpResponse::Ok().json(resp))
}
