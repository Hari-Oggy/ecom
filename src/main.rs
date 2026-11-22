mod dtos;
mod entities;
mod handlers;
mod routes;

use axum::{
    routing::{get, post},
    Extension, Router,
};
use handlers::users::{create_oauth_client, AppState};
use migration::MigratorTrait;
use sea_orm::Database;
use sea_orm_pro::ConfigParser;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
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

    // Seed default SuperAdmin if table is empty
    {
        use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
        let admin_count = entities::prelude::SuperAdmins::find()
            .count(&db)
            .await
            .unwrap_or(0);
        if admin_count == 0 {
            let hashed_pw = handlers::auth_utils::hash_password("admin123")
                .expect("Failed to hash default admin password");
            let default_admin = entities::super_admins::ActiveModel {
                username: Set("admin".to_string()),
                email: Set("admin@clothstore.com".to_string()),
                password: Set(hashed_pw.clone()),
                created_at: Set(chrono::Utc::now().into()),
                updated_at: Set(chrono::Utc::now().into()),
                ..Default::default()
            };
            let _ = default_admin.insert(&db).await;

            let hareesh_admin = entities::super_admins::ActiveModel {
                username: Set("hareesh".to_string()),
                email: Set("hareesh@gmail.com".to_string()),
                password: Set(hashed_pw),
                created_at: Set(chrono::Utc::now().into()),
                updated_at: Set(chrono::Utc::now().into()),
                ..Default::default()
            };
            let _ = hareesh_admin.insert(&db).await;
            info!("Default SuperAdmins initialized (admin and hareesh)");
        }
    }

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

    // 5. Build Seaography GraphQL Schema for SeaORM Pro Admin
    let graphql_schema = handlers::graphql::build_graphql_schema(db.clone())
        .expect("Failed to build Seaography GraphQL schema");
    let graphql_schema = Arc::new(graphql_schema);

    let state = AppState {
        db,
        oauth_client,
        jwt_secret,
        graphql_schema,
    };

    // Load SeaORM Pro Admin Configuration from pro_admin/
    let pro_config = ConfigParser::new()
        .load_config("pro_admin")
        .expect("Failed to load SeaORM Pro admin configuration");
    let mut pro_config_json = serde_json::to_value(&pro_config)
        .expect("Failed to serialize SeaORM Pro config");

    // Explicitly set rbac.enable = false so SeaORM Pro React frontend does not filter out tables
    if let Some(site) = pro_config_json.get_mut("site").and_then(|s| s.as_object_mut()) {
        site.insert(
            "rbac".to_string(),
            serde_json::json!({
                "enable": false
            }),
        );
    }

    let shared_pro_config = Arc::new(pro_config_json);

    // Static service for SeaORM Pro Admin SPA frontend
    let admin_spa = ServeDir::new("assets/admin")
        .fallback(ServeFile::new("assets/admin/index.html"));

    // Assemble modular routes with session layer & SeaORM Pro admin routes
    let app = Router::new()
        .nest("/api/auth", routes::auth_routes())
        .nest("/api/auth", routes::protected_routes(state.clone()))
        // SeaORM Pro Admin API endpoints
        .route("/api/admin/config", get(handlers::admin::admin_config))
        .route("/api/auth/login", post(handlers::admin::admin_login))
        .route(
            "/api/user/current",
            get(handlers::admin::current_admin).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                handlers::middleware::auth_guard,
            )),
        )
        // Seaography GraphQL endpoint queried by SeaORM Pro Admin panel
        .route(
            "/api/graphql",
            get(handlers::graphql::graphql_playground).post(handlers::graphql::graphql_handler),
        )
        // Serve SeaORM Pro frontend at /admin
        .nest_service("/admin", admin_spa)
        .layer(Extension(shared_pro_config))
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
