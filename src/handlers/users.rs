use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
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
use std::net::SocketAddr;
use std::sync::Arc;
use tower_sessions::Session;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    dtos::serial::{AuthResponse, GoogleUserInfo, SignInDto, SignUpDto, UserResponseDto},
    entities::{prelude::Users as User, users as user},
    handlers::{
        auth_utils::{hash_password, verify_password},
        jwt_utils::generate_jwt,
        middleware::{SESSION_IP_KEY, SESSION_USER_AGENT_KEY, SESSION_USER_ID_KEY},
    },
};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub oauth_client: Arc<BasicClient>,
    pub jwt_secret: String,
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

/// Helper function to initialize or cycle a secure session with anti-hijack fingerprints
async fn setup_user_session(
    session: &Session,
    user_id: Uuid,
    addr: &SocketAddr,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    // Prevent Session Fixation: rotate the session identifier on login
    session.cycle_id().await.map_err(|e| {
        error!("Failed to cycle session ID: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    session
        .insert(SESSION_USER_ID_KEY, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    session
        .insert(SESSION_IP_KEY, addr.ip().to_string())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    session
        .insert(SESSION_USER_AGENT_KEY, user_agent)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

/// POST /api/auth/signup: Registers a new user with Argon2 password, initializes session & JWT
pub async fn signup(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<SignUpDto>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let email = payload.email.trim().to_lowercase();
    let username = payload.username.trim().to_string();

    if email.is_empty() || payload.password.trim().is_empty() || username.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                message: "Username, email, and password are required".into(),
                token: None,
                user: None,
            }),
        ));
    }

    if payload.password.len() < 6 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                message: "Password must be at least 6 characters long".into(),
                token: None,
                user: None,
            }),
        ));
    }

    // Check if user already exists
    let existing_user = User::find()
        .filter(user::Column::Email.eq(&email).or(user::Column::Username.eq(&username)))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error checking existing user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Database error occurred".into(),
                    token: None,
                    user: None,
                }),
            )
        })?;

    if let Some(user) = existing_user {
        let msg = if user.email == email {
            "An account with this email already exists"
        } else {
            "Username is already taken"
        };
        return Err((
            StatusCode::CONFLICT,
            Json(AuthResponse {
                success: false,
                message: msg.into(),
                token: None,
                user: None,
            }),
        ));
    }

    // Hash password with Argon2
    let hashed_password = hash_password(&payload.password).map_err(|e| {
        error!("Error hashing password: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                message: "Failed to securely hash password".into(),
                token: None,
                user: None,
            }),
        )
    })?;

    let user_id = Uuid::new_v4();
    let now = Utc::now().into();

    let new_user = user::ActiveModel {
        id: Set(user_id),
        username: Set(username.clone()),
        email: Set(email.clone()),
        password: Set(Some(hashed_password)),
        phone: Set(payload.phone.clone()),
        google_id: Set(None),
        avatar_url: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let inserted = new_user.insert(&state.db).await.map_err(|e| {
        error!("Database error creating user: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                message: "Failed to register user in database".into(),
                token: None,
                user: None,
            }),
        )
    })?;

    // 1. Establish Stateful Session (for Next.js / Admin panel cookie)
    let _ = setup_user_session(&session, inserted.id, &addr, &headers).await;

    // 2. Also generate JWT Token (for API / Mobile clients)
    let token = generate_jwt(inserted.id, &inserted.email, &state.jwt_secret).ok();

    info!("New user registered successfully: {}", inserted.email);

    Ok(Json(AuthResponse {
        success: true,
        message: "User registered successfully".into(),
        token,
        user: Some(UserResponseDto {
            id: inserted.id,
            username: inserted.username,
            email: inserted.email,
            phone: inserted.phone,
            avatar_url: inserted.avatar_url,
            auth_provider: "email".into(),
        }),
    }))
}

/// POST /api/auth/signin: Validates credentials, creates server session & returns JWT
pub async fn signin(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<SignInDto>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let email = payload.email.trim().to_lowercase();

    if email.is_empty() || payload.password.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                message: "Email and password are required".into(),
                token: None,
                user: None,
            }),
        ));
    }

    let user_model = User::find()
        .filter(user::Column::Email.eq(&email))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error finding user on signin: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Database error occurred".into(),
                    token: None,
                    user: None,
                }),
            )
        })?;

    let user = match user_model {
        Some(u) => u,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    success: false,
                    message: "Invalid email or password".into(),
                    token: None,
                    user: None,
                }),
            ));
        }
    };

    let hashed_pwd = match &user.password {
        Some(pwd) => pwd,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    success: false,
                    message: "This account was registered using Google. Please sign in with Google."
                        .into(),
                    token: None,
                    user: None,
                }),
            ));
        }
    };

    match verify_password(&payload.password, hashed_pwd) {
        Ok(true) => {
            // 1. Establish Stateful Session (for Next.js / Admin panel cookie)
            if let Err(e) = setup_user_session(&session, user.id, &addr, &headers).await {
                error!("Failed to set up user session: {:?}", e);
            }

            // 2. Generate JWT Token
            let token = generate_jwt(user.id, &user.email, &state.jwt_secret).ok();

            info!("User logged in successfully: {}", user.email);

            Ok(Json(AuthResponse {
                success: true,
                message: "Login successful".into(),
                token,
                user: Some(UserResponseDto {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    phone: user.phone,
                    avatar_url: user.avatar_url,
                    auth_provider: if user.google_id.is_some() {
                        "google+password".into()
                    } else {
                        "email".into()
                    },
                }),
            }))
        }
        Ok(false) => {
            warn!("Password verification failed for: {}", user.email);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    success: false,
                    message: "Invalid email or password".into(),
                    token: None,
                    user: None,
                }),
            ))
        }
        Err(err) => {
            error!("Argon2 hash parsing/verification error for {}: {:?}", user.email, err);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    success: false,
                    message: "Invalid email or password".into(),
                    token: None,
                    user: None,
                }),
            ))
        }
    }
}

/// POST /api/auth/logout: Flushes the session in Postgres and unsets the cookie
pub async fn logout(session: Session) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    session.flush().await.map_err(|e| {
        error!("Error clearing session on logout: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                message: "Failed to log out session".into(),
                token: None,
                user: None,
            }),
        )
    })?;

    Ok(Json(AuthResponse {
        success: true,
        message: "Logged out successfully".into(),
        token: None,
        user: None,
    }))
}

/// GET /api/auth/google: Redirects client to Google OAuth consent screen
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

/// GET /api/auth/google/callback: Handles Google OAuth exchange, creates/links user, establishes session & JWT
pub async fn google_callback(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
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
                    token: None,
                    user: None,
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
                    token: None,
                    user: None,
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
                    token: None,
                    user: None,
                }),
            )
        })?;

    let email = google_user.email.to_lowercase();

    let existing_user = User::find()
        .filter(
            user::Column::GoogleId
                .eq(&google_user.id)
                .or(user::Column::Email.eq(&email)),
        )
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error finding user during OAuth: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Database error occurred".into(),
                    token: None,
                    user: None,
                }),
            )
        })?;

    let now = Utc::now().into();

    let user_record = if let Some(existing) = existing_user {
        let mut active: user::ActiveModel = existing.into();
        active.google_id = Set(Some(google_user.id));
        if google_user.picture.is_some() {
            active.avatar_url = Set(google_user.picture);
        }
        active.updated_at = Set(now);
        active.update(&state.db).await.map_err(|e| {
            error!("Database error updating OAuth user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to update user profile".into(),
                    token: None,
                    user: None,
                }),
            )
        })?
    } else {
        let username = google_user.name.unwrap_or_else(|| {
            email.split('@').next().unwrap_or("user").to_string()
        });

        let new_user = user::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username),
            email: Set(email.clone()),
            password: Set(None),
            phone: Set(None),
            google_id: Set(Some(google_user.id)),
            avatar_url: Set(google_user.picture),
            created_at: Set(now),
            updated_at: Set(now),
        };

        new_user.insert(&state.db).await.map_err(|e| {
            error!("Database error inserting OAuth user: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Failed to create account for Google user".into(),
                    token: None,
                    user: None,
                }),
            )
        })?
    };

    // 1. Establish Stateful Session
    let _ = setup_user_session(&session, user_record.id, &addr, &headers).await;

    // 2. Generate JWT Token
    let token = generate_jwt(user_record.id, &user_record.email, &state.jwt_secret).ok();

    info!("Google OAuth sign-in completed for: {}", user_record.email);

    Ok(Json(AuthResponse {
        success: true,
        message: "Google OAuth sign-in successful".into(),
        token,
        user: Some(UserResponseDto {
            id: user_record.id,
            username: user_record.username,
            email: user_record.email,
            phone: user_record.phone,
            avatar_url: user_record.avatar_url,
            auth_provider: "google".into(),
        }),
    }))
}

/// GET /api/auth/me: Protected endpoint returning currently authenticated user's profile
pub async fn me(
    axum::extract::Extension(claims): axum::extract::Extension<crate::handlers::jwt_utils::Claims>,
    State(state): State<AppState>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let user = User::find_by_id(claims.user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error fetching /me: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    message: "Database error occurred".into(),
                    token: None,
                    user: None,
                }),
            )
        })?;

    match user {
        Some(u) => Ok(Json(AuthResponse {
            success: true,
            message: "User profile retrieved".into(),
            token: None,
            user: Some(UserResponseDto {
                id: u.id,
                username: u.username,
                email: u.email,
                phone: u.phone,
                avatar_url: u.avatar_url,
                auth_provider: if u.google_id.is_some() {
                    "google".into()
                } else {
                    "email".into()
                },
            }),
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(AuthResponse {
                success: false,
                message: "User not found".into(),
                token: None,
                user: None,
            }),
        )),
    }
}
