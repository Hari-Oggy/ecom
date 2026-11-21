use axum::{
    routing::{get, post},
    Router,
};

use crate::handlers::{self, users::AppState};

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/signup", post(handlers::users::signup))
        .route("/signin", post(handlers::users::signin))
        .route("/logout", post(handlers::users::logout))
        .route("/google", get(handlers::users::google_login))
        .route("/google/callback", get(handlers::users::google_callback))
}
