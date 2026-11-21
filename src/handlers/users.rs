use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use chrono::Utc;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    dtos::serial::{AuthForm, AuthResponse, GoogleUserInfo},
    entities::{user, User},
    handlers::auth_utils::{hash_password, verify_password},
};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub oauth_client: Arc<BasicClient>,
}

pub fn create_oauth_client() -> BasicClient {
    let client_id = ClientId::new(
        std::env::var("GOOGLE_CLIENT_ID").unwrap_or_else(|_| "your-google-client-id".to_string()),
    );
    let client_secret = ClientSecret::new(
        std::env::var("GOOGLE_CLIENT_SECRET")
            .unwrap_or_else(|_| "your-google-client-secret".to_string()),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid token endpoint URL");

    let redirect_url = std::env::var("GOOGLE_REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:3000/api/auth/google/callback".to_string());

    BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Invalid redirect URL"))
}

/// POST /api/auth-user: Authenticates or registers a user via email & password
pub async fn auth_user(
    State(state): State<AppState>, // appstate is automcatically injected by Axum!
    Json(payload): Json<AuthForm>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let raw_password = match &payload.password {
        Some(pwd) if !pwd.trim().is_empty() => pwd,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    success: false,
                    message: "Password is required".into(),
                    user_id: None,
                    email: None,
                }),
            ));
        }
    };

    // Check if user already exists
    let existing_user = User::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error finding user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Internal server error".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;

    if let Some(user_model) = existing_user {
        // Authenticate existing user
        if let Some(hashed_pwd) = &user_model.password {
            match verify_password(raw_password, hashed_pwd) {
                Ok(true) => {
                    info!("User authenticated successfully: {}", user_model.email);
                    return Ok(Json(AuthResponse {
                        success: true,
                        message: "Login successful".into(),
                        user_id: Some(user_model.id),
                        email: Some(user_model.email),
                    }));
                }
                _ => {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(AuthResponse {
                            success: false,
                            message: "Invalid email or password".into(),
                            user_id: None,
                            email: None,
                        }),
                    ));
                }
            }
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    success: false,
                    message: "Account was created with Google OAuth. Please sign in with Google."
                        .into(),
                    user_id: None,
                    email: None,
                }),
            ));
        }
    }

    // Register new user with Argon2 hashed password
    let hashed_pwd = hash_password(raw_password).map_err(|e| {
        error!("Error hashing password with Argon2: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                message: "Failed to securely hash password".into(),
                user_id: None,
                email: None,
            }),
        )
    })?;

    let now = Utc::now();
    let username = payload
        .username
        .unwrap_or_else(|| payload.email.split('@').next().unwrap_or("user").to_string());

    let new_user = user::ActiveModel {
        username: Set(username),
        email: Set(payload.email.clone()),
        password: Set(Some(hashed_pwd)),
        phone: Set(payload.phone),
        google_id: Set(None),
        avatar_url: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let inserted = new_user.insert(&state.db).await.map_err(|e| {
        error!("Failed to create user in DB: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                message: "Failed to register user in database".into(),
                user_id: None,
                email: None,
            }),
        )
    })?;

    info!("New user registered with Argon2 hash: {}", inserted.email);

    Ok(Json(AuthResponse {
        success: true,
        message: "User registered and authenticated successfully".into(),
        user_id: Some(inserted.id),
        email: Some(inserted.email),
    }))
}

/// GET /api/auth/google: Redirects client to Google OAuth login URL
pub async fn google_login(State(state): State<AppState>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    Redirect::to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    pub code: String,
    pub state: Option<String>,
}

/// GET /api/auth/google/callback: Handles Google OAuth exchange & user creation/login
pub async fn google_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let token_res = state
        .oauth_client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!("Failed to exchange Google OAuth code: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to exchange OAuth token with Google".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;

    let access_token = token_res.access_token().secret();

    let client = reqwest::Client::new();
    let google_user: GoogleUserInfo = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to fetch userinfo from Google: {:?}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to fetch user information from Google".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            error!("Failed to parse Google userinfo response: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to parse Google profile".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;

    // Find user by Google ID or by Email
    let existing_user = User::find()
        .filter(
            user::Column::GoogleId
                .eq(&google_user.id)
                .or(user::Column::Email.eq(&google_user.email)),
        )
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error finding user during OAuth callback: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Database error".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;

    let now = Utc::now();

    let user_id = if let Some(existing) = existing_user {
        let mut active: user::ActiveModel = existing.into();
        active.google_id = Set(Some(google_user.id));
        if google_user.picture.is_some() {
            active.avatar_url = Set(google_user.picture);
        }
        active.updated_at = Set(now);
        let updated = active.update(&state.db).await.map_err(|e| {
            error!("Database error updating Google OAuth user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to update OAuth user".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;
        updated.id
    } else {
        let username = google_user
            .name
            .clone()
            .unwrap_or_else(|| google_user.email.split('@').next().unwrap_or("user").to_string());

        let new_user = user::ActiveModel {
            username: Set(username),
            email: Set(google_user.email.clone()),
            password: Set(None),
            phone: Set(None),
            google_id: Set(Some(google_user.id)),
            avatar_url: Set(google_user.picture),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let inserted = new_user.insert(&state.db).await.map_err(|e| {
            error!("Database error inserting Google OAuth user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to create new user for OAuth account".into(),
                    user_id: None,
                    email: None,
                }),
            )
        })?;
        inserted.id
    };

    info!("Google OAuth sign-in successful for {}", google_user.email);

    Ok(Json(AuthResponse {
        success: true,
        message: "Google OAuth authentication successful".into(),
        user_id: Some(user_id),
        email: Some(google_user.email),
    }))
}
