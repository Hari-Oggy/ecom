use async_graphql::{
    dynamic::Schema,
    http::{playground_source, GraphQLPlaygroundConfig},
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use sea_orm::DatabaseConnection;
use seaography::Builder;
use seaography::lazy_static::lazy_static;

use crate::{entities::*, handlers::users::AppState};

lazy_static! {
    static ref CONTEXT: seaography::BuilderContext = seaography::BuilderContext::default();
}

pub fn build_graphql_schema(
    db: DatabaseConnection,
) -> Result<Schema, async_graphql::dynamic::SchemaError> {
    let mut builder = Builder::new(&CONTEXT, db.clone());
    seaography::register_entities!(builder, [users, super_admins]);

    builder.schema_builder().data(db).finish()
}

pub async fn graphql_playground() -> impl IntoResponse {
    let config = GraphQLPlaygroundConfig::new("/api/graphql")
        .with_header("Authorization", "AUTO_TOKEN");

    let res = playground_source(config).replace(
        r#""Authorization":"AUTO_TOKEN""#,
        r#""Authorization":`Bearer ${localStorage.getItem('token')}`"#,
    );

    Html(res)
}

pub async fn graphql_handler(
    State(state): State<AppState>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    state.graphql_schema.execute(req.into_inner()).await.into()
}
