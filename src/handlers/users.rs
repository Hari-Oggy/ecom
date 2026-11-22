use std::sync::Arc;
use async_graphql::dynamic::Schema;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use tower_sessions::Session;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    dtos::serial::{AuthResponse, GoogleUserInfo, SignInDto, SignUpDto, UserResponseDto},
    entities::users as user,
    handlers::{
        auth_utils::{hash_password, verify_password},
        jwt_utils::generate_jwt,
        middleware::SESSION_USER_ID_KEY,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub oauth_client: Arc<BasicClient>,
    pub jwt_secret: String,
    pub graphql_schema: Arc<Schema>,
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

pub async fn signup(
    session: Session,
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(payload): axum::Json<SignUpDto>,
) -> (
    axum::http::StatusCode,
    axum::Json<AuthResponse>,
) {
    if payload.email.trim().is_empty()
        || payload.password.trim().is_empty()
        || payload.username.trim().is_empty()
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(AuthResponse {
                success: false,
                message: "Username, email, and password cannot be empty".to_string(),
                token: None,
                user: None,
            }),
        );
    }

    let existing_user = user::Entity::find()
        .filter(
            user::Column::Email
                .eq(&payload.email)
                .or(user::Column::Username.eq(&payload.username)),
        )
        .one(&state.db)
        .await;

    match existing_user {
        Ok(Some(u)) => {
            let msg = if u.email == payload.email {
                "User with this email already exists"
            } else {
                "User with this username already exists"
            };
            return (
                axum::http::StatusCode::CONFLICT,
                axum::Json(AuthResponse {
                    success: false,
                    message: msg.to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
        Err(err) => {
            error!("Database error while checking user existence: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Database error".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
        Ok(None) => {}
    }

    let hashed_pw = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(err) => {
            error!("Failed to hash password: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Failed to secure password".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let new_user = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        username: Set(payload.username),
        email: Set(payload.email),
        password: Set(Some(hashed_pw)),
        phone: Set(payload.phone),
        google_id: Set(None),
        avatar_url: Set(None),
        created_at: Set(chrono::Utc::now().into()),
        updated_at: Set(chrono::Utc::now().into()),
    };

    let inserted = match new_user.insert(&state.db).await {
        Ok(u) => u,
        Err(err) => {
            error!("Failed to insert new user: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Could not create user".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let _ = session.insert(SESSION_USER_ID_KEY, inserted.id).await;

    let token = match generate_jwt(inserted.id, &inserted.email, &state.jwt_secret) {
        Ok(t) => t,
        Err(err) => {
            error!("Failed to generate JWT: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Could not create auth token".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let user_dto = UserResponseDto {
        id: inserted.id,
        username: inserted.username,
        email: inserted.email,
        phone: inserted.phone,
        avatar_url: inserted.avatar_url,
        auth_provider: "email".to_string(),
    };

    info!("User signed up successfully: {}", user_dto.email);
    (
        axum::http::StatusCode::CREATED,
        axum::Json(AuthResponse {
            success: true,
            message: "User registered successfully".to_string(),
            token: Some(token),
            user: Some(user_dto),
        }),
    )
}

pub async fn signin(
    session: Session,
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(payload): axum::Json<SignInDto>,
) -> (
    axum::http::StatusCode,
    axum::Json<AuthResponse>,
) {
    if payload.email.trim().is_empty() || payload.password.trim().is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(AuthResponse {
                success: false,
                message: "Email and password cannot be empty".to_string(),
                token: None,
                user: None,
            }),
        );
    }

    let user_record = match user::Entity::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            warn!("Signin failed: User not found with email {}", payload.email);
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Invalid email or password".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
        Err(err) => {
            error!("Database error during signin: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Internal server error".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let password_hash = match &user_record.password {
        Some(hash) => hash,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(AuthResponse {
                    success: false,
                    message: "This account was registered using Google Sign-In. Please sign in with Google.".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let is_valid = match verify_password(&payload.password, password_hash) {
        Ok(valid) => valid,
        Err(err) => {
            error!("Password verification internal error: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Authentication verification error".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    if !is_valid {
        warn!("Signin failed: Password mismatch for user {}", payload.email);
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(AuthResponse {
                success: false,
                message: "Invalid email or password".to_string(),
                token: None,
                user: None,
            }),
        );
    }

    let _ = session.insert(SESSION_USER_ID_KEY, user_record.id).await;

    let token = match generate_jwt(user_record.id, &user_record.email, &state.jwt_secret) {
        Ok(t) => t,
        Err(err) => {
            error!("Failed to generate JWT: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Failed to generate token".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let user_dto = UserResponseDto {
        id: user_record.id,
        username: user_record.username,
        email: user_record.email,
        phone: user_record.phone,
        avatar_url: user_record.avatar_url,
        auth_provider: if user_record.google_id.is_some() {
            "google".to_string()
        } else {
            "email".to_string()
        },
    };

    info!("User logged in successfully: {}", user_dto.email);
    (
        axum::http::StatusCode::OK,
        axum::Json(AuthResponse {
            success: true,
            message: "Login successful".to_string(),
            token: Some(token),
            user: Some(user_dto),
        }),
    )
}

pub async fn logout(session: Session) -> (
    axum::http::StatusCode,
    axum::Json<AuthResponse>,
) {
    if let Err(err) = session.flush().await {
        error!("Failed to flush session during logout: {:?}", err);
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(AuthResponse {
            success: true,
            message: "Logged out successfully".to_string(),
            token: None,
            user: None,
        }),
    )
}

pub async fn google_login(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::response::Redirect {
    let (auth_url, _csrf_token) = state
        .oauth_client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .add_scope(oauth2::Scope::new("email".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .url();

    axum::response::Redirect::temporary(auth_url.as_str())
}

#[derive(serde::Deserialize)]
pub struct AuthCallbackQuery {
    pub code: String,
    #[allow(dead_code)]
    pub state: Option<String>,
}

pub async fn google_callback(
    session: Session,
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AuthCallbackQuery>,
) -> (
    axum::http::StatusCode,
    axum::Json<AuthResponse>,
) {
    let token_result = match state
        .oauth_client
        .exchange_code(oauth2::AuthorizationCode::new(query.code))
        .request_async(oauth2::reqwest::async_http_client)
        .await
    {
        Ok(tr) => tr,
        Err(err) => {
            error!("Failed to exchange Google OAuth code: {:?}", err);
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Failed to exchange OAuth token with Google".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    use oauth2::TokenResponse;
    let access_token = token_result.access_token().secret();

    let client = reqwest::Client::new();
    let user_info_resp = match client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!("Failed to fetch userinfo from Google: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Failed to fetch user profile from Google".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let google_user = match user_info_resp.json::<GoogleUserInfo>().await {
        Ok(info) => info,
        Err(err) => {
            error!("Failed to parse Google userinfo response: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Invalid response from Google".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let existing_user = user::Entity::find()
        .filter(
            user::Column::GoogleId
                .eq(&google_user.id)
                .or(user::Column::Email.eq(&google_user.email)),
        )
        .one(&state.db)
        .await;

    let target_user = match existing_user {
        Ok(Some(u)) => {
            let mut active: user::ActiveModel = u.clone().into();
            let mut changed = false;

            if u.google_id.is_none() {
                active.google_id = Set(Some(google_user.id.clone()));
                changed = true;
            }
            if u.avatar_url.is_none() && google_user.picture.is_some() {
                active.avatar_url = Set(google_user.picture.clone());
                changed = true;
            }

            if changed {
                active.updated_at = Set(chrono::Utc::now().into());
                match active.update(&state.db).await {
                    Ok(updated) => updated,
                    Err(err) => {
                        error!("Failed to update existing user with Google info: {:?}", err);
                        u
                    }
                }
            } else {
                u
            }
        }
        Ok(None) => {
            let preferred_username = google_user
                .name
                .unwrap_or_else(|| google_user.email.split('@').next().unwrap_or("user").to_string())
                .replace(' ', "_")
                .to_lowercase();

            let final_username = format!("{}_{}", preferred_username, &google_user.id[..4]);

            let new_user = user::ActiveModel {
                id: Set(Uuid::new_v4()),
                username: Set(final_username),
                email: Set(google_user.email),
                password: Set(None),
                phone: Set(None),
                google_id: Set(Some(google_user.id)),
                avatar_url: Set(google_user.picture),
                created_at: Set(chrono::Utc::now().into()),
                updated_at: Set(chrono::Utc::now().into()),
            };

            match new_user.insert(&state.db).await {
                Ok(inserted) => inserted,
                Err(err) => {
                    error!("Failed to register Google OAuth user in database: {:?}", err);
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(AuthResponse {
                            success: false,
                            message: "Failed to persist user profile".to_string(),
                            token: None,
                            user: None,
                        }),
                    );
                }
            }
        }
        Err(err) => {
            error!("Database error while checking Google OAuth user: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Database error during OAuth login".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let _ = session.insert(SESSION_USER_ID_KEY, target_user.id).await;

    let token = match generate_jwt(target_user.id, &target_user.email, &state.jwt_secret) {
        Ok(t) => t,
        Err(err) => {
            error!("Failed to generate JWT: {:?}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Failed to sign authentication token".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let user_dto = UserResponseDto {
        id: target_user.id,
        username: target_user.username,
        email: target_user.email,
        phone: target_user.phone,
        avatar_url: target_user.avatar_url,
        auth_provider: "google".to_string(),
    };

    (
        axum::http::StatusCode::OK,
        axum::Json(AuthResponse {
            success: true,
            message: "Google login successful".to_string(),
            token: Some(token),
            user: Some(user_dto),
        }),
    )
}

pub async fn me(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Extension(claims): axum::Extension<crate::handlers::jwt_utils::Claims>,
) -> (
    axum::http::StatusCode,
    axum::Json<AuthResponse>,
) {
    let user_record = match user::Entity::find_by_id(claims.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(AuthResponse {
                    success: false,
                    message: "User not found".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
        Err(err) => {
            error!("Database error fetching user {}: {:?}", claims.user_id, err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(AuthResponse {
                    success: false,
                    message: "Internal server error".to_string(),
                    token: None,
                    user: None,
                }),
            );
        }
    };

    let user_dto = UserResponseDto {
        id: user_record.id,
        username: user_record.username,
        email: user_record.email,
        phone: user_record.phone,
        avatar_url: user_record.avatar_url,
        auth_provider: if user_record.google_id.is_some() {
            "google".to_string()
        } else {
            "email".to_string()
        },
    };

    (
        axum::http::StatusCode::OK,
        axum::Json(AuthResponse {
            success: true,
            message: "Current user profile fetched successfully".to_string(),
            token: None,
            user: Some(user_dto),
        }),
    )
}
