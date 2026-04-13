//! Config projection endpoint for the frontend OIDC client.
//!
//! `GET /api/auth/config?redirect_uri=<uri>` returns a
//! `FrontendOidcModeConfigProjection` that the browser client uses to
//! bootstrap its authorization code + PKCE flow without needing any
//! compile-time OIDC credentials baked into the frontend bundle.
//!
//! This endpoint is intentionally **unauthenticated** — it only exposes
//! public parameters needed to initiate an OAuth flow (issuer URL,
//! client_id, scopes, PKCE flag). No secrets or user data are returned.

use axum::{
    Json,
    extract::{Query, State},
};
use securitydept_core::token_set_context::frontend_oidc_mode::contracts::FrontendOidcModeConfigProjection;
use std::sync::Arc;

use crate::{config::AuthConfig, error::AppError, services::AppState};

/// Query parameters for the OIDC config projection endpoint.
#[derive(serde::Deserialize)]
pub struct OidcConfigQuery {
    /// The OIDC callback redirect URI used by the frontend application.
    ///
    /// The backend echoes this back in the projection so the browser client
    /// can register it without being hard-coded in the server config.
    /// The frontend knows its own origin and constructs the full callback URL.
    pub redirect_uri: String,
}

/// Return the OIDC client configuration projection for the frontend.
///
/// Only available when `AUTH_TYPE=OIDC`. Returns 400 when the server is
/// running in BASIC auth mode (the frontend config projection is an OIDC
/// concept with no counterpart in BASIC auth).
pub async fn get_oidc_config(
    Query(query): Query<OidcConfigQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<FrontendOidcModeConfigProjection>, AppError> {
    let AuthConfig::OIDC {
        ref issuer,
        ref required_scopes,
        ref frontend_client_id,
        ..
    } = state.config.auth
    else {
        return Err(AppError::BadRequest {
            message:
                "OIDC config projection is not available: server is running in BASIC auth mode"
                    .to_string(),
        });
    };

    // Derive the well-known discovery URL from the issuer so the backend only
    // needs to configure the issuer (same value used for token verification).
    let well_known_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let projection = FrontendOidcModeConfigProjection {
        // Provider connectivity — derived from the backend's own OIDC config.
        well_known_url: Some(well_known_url),
        issuer_url: Some(issuer.clone()),
        jwks_uri: None,
        // Zero duration → skipped in serialization (skip_serializing_if = is_zero).
        metadata_refresh_interval: std::time::Duration::ZERO,
        jwks_refresh_interval: std::time::Duration::ZERO,
        // Endpoint overrides — rely on provider discovery.
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        revocation_endpoint: None,
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: None,
        userinfo_signing_alg_values_supported: None,
        // Client identity. The `frontend_client_id` is the OAuth client the
        // *browser* uses; the backend is a pure resource server with no client role.
        client_id: frontend_client_id.clone(),
        client_secret: None,
        // Scopes: the backend's resource-level required_scopes become the
        // frontend's requested scope set. "openid", "profile", "email" are
        // typically already included in CONFLUENCE_OIDC_SCOPES.
        scopes: required_scopes.clone(),
        required_scopes: required_scopes.clone(),
        // Redirect URI comes from the caller (the frontend knows its own origin).
        redirect_url: query.redirect_uri,
        // Frontend OIDC mode always uses PKCE (Authorization Code + PKCE).
        pkce_enabled: true,
        claims_check_script: None,
        // Authoritative freshness signal — epoch-ms at projection generation.
        generated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    };

    Ok(Json(projection))
}
