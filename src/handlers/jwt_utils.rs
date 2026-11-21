use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user_id as string)
    pub user_id: Uuid,      // Explicit user_id
    pub email: String,      // User email
    pub exp: usize,         // Expiration timestamp
    pub iat: usize,         // Issued at
}

pub fn generate_jwt(user_id: Uuid, email: &str, secret: &str) -> Result<String, String> {
    let now = Utc::now();
    // 7 days token validity
    let expiration = (now + Duration::days(7)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        user_id,
        email: email.to_string(),
        exp: expiration,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| e.to_string())
}
