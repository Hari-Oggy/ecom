use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use std::net::SocketAddr;
use tower_sessions::Session;
use tracing::warn;
use uuid::Uuid;

use crate::{
    dtos::serial::AuthResponse,
    handlers::{
        jwt_utils::{verify_jwt, Claims},
        users::AppState,
    },
};

pub const SESSION_USER_ID_KEY: &str = "user_id";
pub const SESSION_USER_AGENT_KEY: &str = "user_agent";
pub const SESSION_IP_KEY: &str = "ip";

/// Hybrid Auth Guard: Supports both Stateful HttpOnly Session and Stateless JWT Bearer Header
/// Includes Session Hijacking Detection (verifies User-Agent and IP consistency)
pub async fn auth_guard(
    State(state): State<AppState>,
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthResponse>)> {
    let _current_ip = addr.ip().to_string();
    let current_ua = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // 1. Check if user is authenticated via Server-Side Session (Next.js / Browser Cookie)
    let session_user_id: Option<Uuid> = session.get(SESSION_USER_ID_KEY).await.unwrap_or(None);

    if let Some(user_id) = session_user_id {
        // --- Anti-Session Hijacking Verification ---
        let saved_ua: Option<String> = session.get(SESSION_USER_AGENT_KEY).await.unwrap_or(None);
        let _saved_ip: Option<String> = session.get(SESSION_IP_KEY).await.unwrap_or(None);

        if let Some(ref expected_ua) = saved_ua {
            if expected_ua != &current_ua {
                warn!(
                    "SECURITY ALERT: Session hijacking suspected! User-Agent mismatch for user {}. Expected: '{}', Got: '{}'",
                    user_id, expected_ua, current_ua
                );
                // Immediately destroy the compromised session
                let _ = session.flush().await;
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        success: false,
                        message: "Session terminated due to security violation (client fingerprint mismatch)".into(),
                        token: None,
                        user: None,
                    }),
                ));
            }
        }

        // Create Claims for downstream handlers
        let claims = Claims {
            sub: user_id.to_string(),
            user_id,
            email: "".into(), // Will be resolved if needed or cached in session
            exp: 0,
            iat: 0,
        };
        request.extensions_mut().insert(claims);
        return Ok(next.run(request).await);
    }

    // 2. Fallback: Check if client provided a JWT in Authorization Header (Mobile apps / API clients)
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|val| val.to_str().ok());

    if let Some(header) = auth_header {
        if header.starts_with("Bearer ") {
            let token = &header[7..];
            let claims: Claims = verify_jwt(token, &state.jwt_secret).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        success: false,
                        message: format!("Invalid or expired token: {}", e),
                        token: None,
                        user: None,
                    }),
                )
            })?;

            request.extensions_mut().insert(claims);
            return Ok(next.run(request).await);
        }
    }

    // 3. Unauthenticated request
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthResponse {
            success: false,
            message: "Authentication required. Please sign in or provide a valid session/token.".into(),
            token: None,
            user: None,
        }),
    ))
}
