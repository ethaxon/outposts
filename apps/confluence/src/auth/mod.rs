use crate::config::AuthConfig;
use crate::error::AppError;
use crate::services::AppState;
use axum::{
    extract::{Request, State},
    http,
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose};
use securitydept_core::oauth_resource_server::VerifiedToken;
use std::sync::Arc;

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
}

const BEARER_TOKEN_PREFIX: &str = "Bearer ";
const BASIC_AUTH_PREFIX: &str = "Basic ";

pub async fn auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let current_user = authorize_current_user(auth_header, state).await?;
    req.extensions_mut().insert(current_user);
    Ok(next.run(req).await)
}

pub async fn authorize_current_user(
    auth_header: Option<&str>,
    state: Arc<AppState>,
) -> Result<CurrentUser, AppError> {
    let auth_header =
        auth_header.ok_or_else(|| AppError::unauthorized_str("missing authorization header"))?;

    match state.config.auth {
        AuthConfig::OIDC { ref user_claim, .. } => {
            let auth_token = auth_header
                .strip_prefix(BEARER_TOKEN_PREFIX)
                .ok_or_else(|| {
                    AppError::unauthorized_str("missing authorization header prefix Bearer")
                })?;
            let verifier = state
                .oidc_verifier
                .as_ref()
                .ok_or_else(|| AppError::internal_str("OIDC verifier not configured"))?;
            let principal =
                VerifiedToken::from(verifier.verify_rfc9068_access_token(auth_token).await?)
                    .to_resource_token_principal();
            let user_id = if user_claim == "sub" {
                principal
                    .subject
                    .ok_or_else(|| AppError::unauthorized_str("auth payload subject missing"))?
            } else {
                principal
                    .claims
                    .get(user_claim)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        AppError::unauthorized_str(format!(
                            "auth payload user claim '{}' missing or not a string",
                            user_claim
                        ))
                    })?
            };

            Ok(CurrentUser { user_id })
        }
        AuthConfig::BASIC {
            ref username,
            ref password,
        } => {
            // Extract Basic authentication credentials
            let basic_auth = auth_header.strip_prefix(BASIC_AUTH_PREFIX).ok_or_else(|| {
                AppError::unauthorized_str("missing authorization header prefix Basic")
            })?;

            // Decode base64 encoded credentials
            let decoded = general_purpose::STANDARD
                .decode(basic_auth)
                .map_err(|_| AppError::unauthorized_str("invalid base64 encoding in Basic auth"))?;

            let credentials = String::from_utf8(decoded)
                .map_err(|_| AppError::unauthorized_str("invalid UTF-8 in Basic auth"))?;

            // Parse username and password (format: username:password)
            let mut parts = credentials.splitn(2, ':');
            let provided_username = parts
                .next()
                .ok_or_else(|| AppError::unauthorized_str("missing username in Basic auth"))?;
            let provided_password = parts
                .next()
                .ok_or_else(|| AppError::unauthorized_str("missing password in Basic auth"))?;

            // Validate username and password
            if provided_username != username.as_str() || provided_password != password.as_str() {
                return Err(AppError::unauthorized_str("invalid username or password"));
            }

            Ok(CurrentUser {
                user_id: username.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
