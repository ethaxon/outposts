use crate::config::AuthConfig;
use crate::error::AppError;
use crate::services::{AppState, JwksConfig};
use axum::{
    extract::{Request, State},
    http,
    middleware::Next,
    response::Response,
};
use biscuit::{JWT, Validation, ValidationOptions, jwk};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub async fn get_jwks_cached(
    state: &AppState,
    jwks_uri: &str,
) -> Result<Arc<jwk::JWKSet<biscuit::Empty>>, AppError> {
    let jwks_conf = {
        let jwks_conf = state.jwks.read().await;
        jwks_conf
            .as_ref()
            .map(|conf| (conf.jwks_expiry, conf.jwks_set.clone()))
    };
    if let Some((jwks_expiry, jwks_set)) = jwks_conf
        && jwks_expiry > std::time::Instant::now()
    {
        return Ok(jwks_set);
    }
    let mut jwks = state.jwks.write().await;
    let jwks_res = reqwest::get(jwks_uri).await?.text().await?;

    let jwk_set: jwk::JWKSet<biscuit::Empty> =
        serde_json::from_str(&jwks_res).map_err(AppError::unauthorized)?;

    let jwk_set = Arc::new(jwk_set);

    let _ = jwks.insert(JwksConfig {
        jwks_expiry: std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(300))
            .ok_or_else(|| anyhow::anyhow!("get_jwks_cached failed to add 5 mins"))?,
        jwks_set: jwk_set.clone(),
    });

    Ok(jwk_set)
}

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ScopedClaims {
    pub scope: String,
}

const BEARER_TOKEN_PREFIX: &str = "Bearer";
const READ_SCOPE: &str = "read:confluence";
const WRITE_SCOPE: &str = "write:confluence";

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
    match state.config.auth {
        AuthConfig::JWT {
            ref jwks_uri,
            ref issuer,
            ref audience,
        } => {
            let auth_header = if let Some(auth_header) = auth_header {
                auth_header
            } else {
                return Err(AppError::unauthorized_str("missing authorization header"));
            };

            if !auth_header.starts_with(BEARER_TOKEN_PREFIX) {
                return Err(AppError::unauthorized_str(
                    "missing authorization header prefix Bearer",
                ));
            }
            let auth_token = &auth_header[(BEARER_TOKEN_PREFIX.len() + 1)..];

            let jwk_set = get_jwks_cached(&state, jwks_uri).await?;

            let token = JWT::<ScopedClaims, biscuit::Empty>::new_encoded(auth_token);
            let algorithm = token
                .unverified_header()
                .map_err(AppError::unauthorized)?
                .registered
                .algorithm;

            let claims = token
                .decode_with_jwks(jwk_set.as_ref(), Some(algorithm))
                .map_err(AppError::unauthorized)?;

            claims
                .validate({
                    ValidationOptions {
                        issuer: Validation::Validate(issuer.clone()),
                        audience: Validation::Validate(audience.clone()),
                        issued_at: Validation::Ignored,
                        ..ValidationOptions::default()
                    }
                })
                .map_err(AppError::unauthorized)?;

            let payload = claims.payload().map_err(AppError::unauthorized)?;

            let sub = payload
                .registered
                .subject
                .clone()
                .ok_or_else(|| AppError::unauthorized_str("auth payload claims sub missing"))?;

            if !payload.private.scope.contains(READ_SCOPE)
                || !payload.private.scope.contains(WRITE_SCOPE)
            {
                return Err(AppError::unauthorized_str(format!(
                    "missing required scopes {} {}",
                    READ_SCOPE, WRITE_SCOPE
                )));
            }

            Ok(CurrentUser { user_id: sub })
        }
        AuthConfig::DevNoAuth { ref user_id } => Ok(CurrentUser {
            user_id: user_id.clone(),
        }),
    }
}
