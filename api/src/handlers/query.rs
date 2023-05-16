use actix_web::{
    body::BoxBody,
    post,
    web::{Data, Json},
    HttpRequest, HttpResponse, Responder,
};
use chrono::Utc;
use tracing::{debug, info, trace};
use uuid::Uuid;

use crate::{
    db::{base, insert_base, insert_query, query},
    domain::{Base, Query},
    dto::{CreateQueryRequest, QueryResponse},
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
        let (query, base) = transactional!(tx, async {
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
                base_id: base.id,
                creation_date: now,
                grouping: payload.grouping,
                id: Uuid::new_v4(),
                name_prefix: payload.name_prefix.clone(),
            };
            insert_query(&query, tx.client())
                .await
                .map_err(Error::DatabaseClientFailed)?;
            Ok::<(Query, Base), Error>((query, base))
        })?;
        info!("new query created");
        let resp = QueryResponse::from_query(query, base);
        Ok::<HttpResponse<BoxBody>, Error>(HttpResponse::Created().json(resp))
    })
}
