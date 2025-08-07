use crate::config::AuthConfig;
use crate::error::AppError;
use crate::services::{AppState, JwksConfig};
use axum::{
    extract::{Request, State},
    http,
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose};
use biscuit::{JWT, Validation, ValidationOptions, jwk};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata, reqwest::async_http_client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct OidcProviderConfig {
    pub jwks_uri: String,
    pub issuer: String,
    pub expiry: std::time::Instant,
}

pub async fn get_jwks_from_oidc_discovery(
    state: &AppState,
    issuer: &str,
) -> Result<Arc<jwk::JWKSet<biscuit::Empty>>, AppError> {
    // Check OIDC provider configuration cache
    let should_discover = {
        let oidc_config = state.oidc_provider.read().await;
        oidc_config
            .as_ref()
            .map(|config| config.issuer != issuer || config.expiry <= std::time::Instant::now())
            .unwrap_or(true)
    };

    let jwks_uri = if should_discover {
        // Discover OIDC provider configuration
        let issuer_url = IssuerUrl::new(issuer.to_string())
            .map_err(|e| AppError::unauthorized(anyhow::anyhow!("Invalid issuer URL: {}", e)))?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
            .await
            .map_err(|e| {
                AppError::unauthorized(anyhow::anyhow!("Failed to discover OIDC provider: {}", e))
            })?;

        let jwks_uri = provider_metadata.jwks_uri().url().to_string();

        // Update OIDC provider configuration cache
        let mut oidc_config = state.oidc_provider.write().await;
        *oidc_config = Some(OidcProviderConfig {
            jwks_uri: jwks_uri.clone(),
            issuer: issuer.to_string(),
            expiry: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(3600)) // Cache for 1 hour
                .ok_or_else(|| AppError::unauthorized_str("Failed to calculate expiry time"))?,
        });

        jwks_uri
    } else {
        // Use cached jwks_uri
        state
            .oidc_provider
            .read()
            .await
            .as_ref()
            .map(|config| config.jwks_uri.clone())
            .ok_or_else(|| AppError::unauthorized_str("OIDC provider config not found"))?
    };

    // Check JWKS cache
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

    // Fetch JWKS
    let jwks_res: String = reqwest::get(&jwks_uri).await?.text().await?;

    let jwk_set: jwk::JWKSet<biscuit::Empty> =
        serde_json::from_str(&jwks_res).map_err(AppError::unauthorized)?;

    let jwk_set = Arc::new(jwk_set);

    // Update JWKS cache
    let mut jwks = state.jwks.write().await;
    *jwks = Some(JwksConfig {
        jwks_expiry: std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(300)) // Cache for 5 minutes
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

const BEARER_TOKEN_PREFIX: &str = "Bearer ";
const BASIC_AUTH_PREFIX: &str = "Basic ";
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
    let auth_header =
        auth_header.ok_or_else(|| AppError::unauthorized_str("missing authorization header"))?;

    match state.config.auth {
        AuthConfig::OIDC {
            ref issuer,
            ref audience,
        } => {
            let auth_token = auth_header
                .strip_prefix(BEARER_TOKEN_PREFIX)
                .ok_or_else(|| {
                    AppError::unauthorized_str("missing authorization header prefix Bearer")
                })?;

            // Get JWKS through OIDC discovery
            let jwk_set = get_jwks_from_oidc_discovery(&state, issuer).await?;

            // Verify JWT token
            let token = JWT::<ScopedClaims, biscuit::Empty>::new_encoded(auth_token);
            let algorithm = token
                .unverified_header()
                .map_err(AppError::unauthorized)?
                .registered
                .algorithm;

            let claims = token
                .decode_with_jwks(jwk_set.as_ref(), Some(algorithm))
                .map_err(AppError::unauthorized)?;

            // Validate claims
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

            // Validate scope
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
