mod dtos;
mod entities;
mod handlers;
mod routes;

use axum::Router;
use handlers::users::{create_oauth_client, AppState};
use migration::MigratorTrait;
use sea_orm::Database;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    ExpiredDeletion, Expiry, SessionManagerLayer,
};
use tower_sessions_sqlx_store::{sqlx::PgPool, PostgresStore};
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

    // 1. SeaORM Database Connection
    let db = Database::connect(&db_url)
        .await
        .expect("Failed to connect to postgres");
    info!("Database connection established");

    // 2. Run Database Migrations Automatically
    migration::Migrator::up(&db, None)
        .await
        .expect("Failed to run database migrations");
    info!("Database migrations applied successfully");

    // 3. Setup PostgreSQL Session Store for tower-sessions (like django_session)
    let pg_pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect SQLx pool for sessions");

    let session_store = PostgresStore::new(pg_pool);
    session_store
        .migrate()
        .await
        .expect("Failed to auto-migrate session table in PostgreSQL");

    // Spawn background task to delete expired sessions every 10 minutes
    tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(600)),
    );

    // 4. Hardened Security Session Layer (HttpOnly, SameSite, Inactivity Expiry)
    let is_production = env::var("APP_ENV").unwrap_or_default() == "production";
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("ecommerce_session")
        .with_http_only(true) // Protects from XSS
        .with_same_site(SameSite::Lax) // Protects from CSRF
        .with_secure(is_production) // HTTPS in production, works on localhost in dev
        .with_expiry(Expiry::OnInactivity(Duration::days(14))); // Auto-login alive for 14 days of activity

    let oauth_client = Arc::new(create_oauth_client());
    let jwt_secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "super-secret-jwt-key-change-in-production-123456".to_string());

    let state = AppState {
        db,
        oauth_client,
        jwt_secret,
    };

    // Assemble modular routes with session layer
    let app = Router::new()
        .nest("/api/auth", routes::auth_routes())
        .nest("/api/auth", routes::protected_routes(state.clone()))
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind port 3000");
    info!("Server running on http://localhost:3000");

    // Axum serve with ConnectInfo enabled for client IP resolution
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}
