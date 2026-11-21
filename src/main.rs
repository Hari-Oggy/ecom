mod dtos;
mod entities;
mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use handlers::users::{create_oauth_client, AppState};
use migration::MigratorTrait;
use sea_orm::Database;
use std::env;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // TRACING
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloth_ecom_matrial=debug,tower_http=debug".into()),
        )
        .init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = Database::connect(db_url)
        .await
        .expect("failed to connect to postgres");
    info!("Database connection established");

    // Run database migrations automatically
    migration::Migrator::up(&db, None)
        .await
        .expect("Failed to run database migrations");
    info!("Database migrations applied successfully");

    let oauth_client = Arc::new(create_oauth_client());
    let state = AppState { db, oauth_client };

    // Build api routes
    let app = Router::new()
        .route("/api/auth-user", post(handlers::users::auth_user))
        .route("/api/auth/google", get(handlers::users::google_login))
        .route(
            "/api/auth/google/callback",
            get(handlers::users::google_callback),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind port 3000");
    info!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.expect("Server error");
}
