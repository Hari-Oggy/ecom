use axum::{
    middleware,
    routing::get,
    Router,
};

use crate::handlers::{self, users::AppState};

pub fn protected_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/me", get(handlers::users::me))
        .route_layer(middleware::from_fn_with_state(
            state,
            handlers::middleware::auth_guard,
        ))
}
