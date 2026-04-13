use crate::config::AuthConfig;
use crate::error::AppError;
use crate::services::AppState;
use axum::{
    extract::{Request, State},
    http,
    middleware::Next,
    response::Response,
};
use securitydept_core::creds::basic::parse_basic_auth_header;
use std::sync::Arc;

pub mod config_projection;

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
        AuthConfig::OIDC {
            ref user_claim,
            ref required_scopes,
            ..
        } => {
            // Use the access-token substrate resource service for bearer verification.
            // This aligns the backend with the frontend-oidc-mode contract: the
            // frontend produces OIDC access tokens; the substrate layer verifies them.
            let resource_service = state
                .access_token_resource_service()
                .ok_or_else(|| AppError::internal_str("OIDC verifier not configured"))?;

            let principal = resource_service
                .authenticate_authorization_header(Some(auth_header))
                .await
                .map_err(AppError::from)?
                .ok_or_else(|| {
                    AppError::unauthorized_str(
                        "missing or invalid bearer token in Authorization header",
                    )
                })?;

            // Application-level scope policy: the substrate service validates
            // the JWT structure and signature but delegates scope enforcement to
            // the application so that each resource can declare its own policy.
            for scope in required_scopes {
                if !principal.scopes.contains(scope) {
                    return Err(AppError::unauthorized_str(format!(
                        "Access token is missing one or more required scopes: {}",
                        required_scopes.join(", ")
                    )));
                }
            }

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
            let (provided_username, provided_password) =
                parse_basic_auth_header(auth_header).map_err(AppError::unauthorized)?;

            if provided_username != username.as_str() || provided_password != password.as_str() {
                return Err(AppError::unauthorized_str("invalid username or password"));
            }

            Ok(CurrentUser {
                user_id: username.clone(),
            })
        }
    }
}

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
}

#[cfg(test)]
mod tests;
