use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;

use crate::{
    dtos::serial::SignInDto,
    entities::{prelude::SuperAdmins, super_admins},
    handlers::{
        auth_utils::verify_password,
        jwt_utils::{generate_jwt, Claims},
        users::AppState,
    },
};

#[derive(Serialize)]
pub struct AdminLoginResponse {
    pub status: String,
    pub r#type: String,
    pub current_authority: String,
    pub token: Option<String>,
}

#[derive(Serialize)]
pub struct CurrentAdminResponse {
    pub success: bool,
    pub data: CurrentAdminData,
}

#[derive(Serialize)]
pub struct CurrentAdminData {
    pub name: String,
    pub email: String,
    pub avatar: String,
    pub userid: String,
    pub access: String,
}

/// GET /api/admin/config: Serves SeaORM Pro frontend configuration
pub async fn admin_config(
    Extension(cfg): Extension<std::sync::Arc<serde_json::Value>>,
) -> Json<serde_json::Value> {
    Json((*cfg).clone())
}

/// POST /api/auth/login: SeaORM Pro Admin login authenticating against the `super_admins` table ONLY
pub async fn admin_login(
    State(state): State<AppState>,
    Json(payload): Json<SignInDto>,
) -> Result<Json<AdminLoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let identifier = payload.email.trim();
    let lower_identifier = identifier.to_lowercase();

    // Authenticate exclusively from the super_admins table
    let admin_model = SuperAdmins::find()
        .filter(
            super_admins::Column::Email
                .eq(&lower_identifier)
                .or(super_admins::Column::Username.eq(identifier))
                .or(super_admins::Column::Username.eq(&lower_identifier)),
        )
        .one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "type": "account",
                    "currentAuthority": "guest"
                })),
            )
        })?;

    let admin = match admin_model {
        Some(a) => a,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "status": "error",
                    "type": "account",
                    "currentAuthority": "guest"
                })),
            ));
        }
    };

    if verify_password(&payload.password, &admin.password).unwrap_or(false) {
        // Map i32 primary key to UUID for JWT claims
        let admin_uuid = uuid::Uuid::from_u128(admin.id as u128);
        let token = generate_jwt(admin_uuid, &admin.email, &state.jwt_secret).ok();

        Ok(Json(AdminLoginResponse {
            status: "ok".into(),
            r#type: "account".into(),
            current_authority: "admin".into(),
            token,
        }))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "status": "error",
                "type": "account",
                "currentAuthority": "guest"
            })),
        ))
    }
}

/// GET /api/user/current: Returns currently logged-in SuperAdmin user to SeaORM Pro
pub async fn current_admin(
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    State(state): State<AppState>,
) -> Result<Json<CurrentAdminResponse>, (StatusCode, &'static str)> {
    let admin_id = claims.user_id.as_u128() as i32;
    let admin = SuperAdmins::find_by_id(admin_id)
        .one(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    match admin {
        Some(a) => Ok(Json(CurrentAdminResponse {
            success: true,
            data: CurrentAdminData {
                name: a.username,
                email: a.email,
                avatar: "https://gw.alipayobjects.com/zos/antfincdn/XAosXuNZyF/BiazfanxmamNRoxxVxka.png".into(),
                userid: a.id.to_string(),
                access: "admin".into(),
            },
        })),
        None => Err((StatusCode::NOT_FOUND, "SuperAdmin not found")),
    }
}
