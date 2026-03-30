use super::authorize_current_user;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::services::AppState;
use axum::{Json, Router, routing::get};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sea_orm::{DatabaseBackend, MockDatabase};
use securitydept_core::oauth_resource_server::{
    OAuthResourceServerConfig, OAuthResourceServerVerifier,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

#[derive(Debug, Clone, serde::Serialize)]
struct ScopedClaims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: usize,
    iat: usize,
    jti: String,
    // client_id is optional per real-world providers (e.g. Authentik)
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    scope: String,
}

fn mock_state(
    auth: AuthConfig,
    oidc_verifier: Option<Arc<OAuthResourceServerVerifier>>,
) -> Arc<AppState> {
    let conn = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
    Arc::new(AppState::new(
        conn,
        AppConfig {
            listen: "127.0.0.1:4001".to_string(),
            auth,
            database_url: "postgres://example".to_string(),
        },
        oidc_verifier,
    ))
}

fn bearer_header(token: &str) -> String {
    format!("Bearer {}", token)
}

fn basic_header(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", general_purpose::STANDARD.encode(credentials))
}

fn future_exp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_secs() as usize
        + 3600
}

fn issued_at() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_secs() as usize
}

/// Build an OIDC verifier state. When `audience` is `None`, audience validation is disabled.
async fn oidc_state(
    jwks_json: &str,
    issuer: &str,
    audience: Option<&str>,
    required_scopes: &[&str],
) -> Arc<AppState> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr should resolve");
    let jwks_uri = format!("http://{addr}/jwks");
    let jwks_value =
        serde_json::from_str::<serde_json::Value>(jwks_json).expect("jwks json should parse");
    let app = Router::new().route(
        "/jwks",
        get({
            let jwks_value = jwks_value.clone();
            move || async move { Json(jwks_value.clone()) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("oidc test server should run");
    });

    let mut verifier_config = OAuthResourceServerConfig::default();
    verifier_config.remote.issuer_url = Some(issuer.to_string());
    verifier_config.remote.jwks_uri = Some(jwks_uri);
    if let Some(aud) = audience {
        verifier_config.audiences = vec![aud.to_string()];
    }
    verifier_config.required_scopes = required_scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect();
    let verifier = Arc::new(
        OAuthResourceServerVerifier::from_config(verifier_config)
            .await
            .expect("oidc verifier should initialize"),
    );

    mock_state(
        AuthConfig::OIDC {
            issuer: issuer.to_string(),
            audience: audience.unwrap_or_default().to_string(),
            required_scopes: required_scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
            user_claim: "sub".to_string(),
        },
        Some(verifier),
    )
}

#[tokio::test]
async fn authorize_current_user_accepts_basic_credentials() {
    let state = mock_state(
        AuthConfig::BASIC {
            username: "demo".to_string(),
            password: "secret".to_string(),
        },
        None,
    );
    let auth_header = basic_header("demo", "secret");

    let current_user = authorize_current_user(Some(&auth_header), state)
        .await
        .expect("basic auth should succeed");

    assert_eq!(current_user.user_id, "demo");
}

#[tokio::test]
async fn authorize_current_user_rejects_invalid_basic_credentials() {
    let state = mock_state(
        AuthConfig::BASIC {
            username: "demo".to_string(),
            password: "secret".to_string(),
        },
        None,
    );
    let auth_header = basic_header("demo", "wrong");

    let err = authorize_current_user(Some(&auth_header), state)
        .await
        .err()
        .expect("invalid password should be rejected");

    assert!(err.to_string().contains("invalid username or password"));
}

#[tokio::test]
async fn authorize_current_user_accepts_oidc_token_via_oauth_resource_server() {
    let issuer = "https://issuer.example.test";
    let audience = "demo-api";
    let required_scopes = ["openid", "profile", "email", "confluence", "offline_access"];
    let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
    let state = oidc_state(jwks_json, issuer, Some(audience), &required_scopes).await;

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key".to_string());
    let token = encode(
        &header,
        &ScopedClaims {
            sub: "user-123".to_string(),
            iss: issuer.to_string(),
            aud: vec![audience.to_string(), "other-api".to_string()],
            exp: future_exp(),
            iat: issued_at(),
            jti: "token-accept".to_string(),
            client_id: Some("outposts-web".to_string()),
            scope: required_scopes.join(" "),
        },
        &EncodingKey::from_secret(b"super-secret"),
    )
    .expect("token should be created");
    let auth_header = bearer_header(&token);

    let current_user = authorize_current_user(Some(&auth_header), state)
        .await
        .expect("cached oidc auth should succeed");

    assert_eq!(current_user.user_id, "user-123");
}

#[tokio::test]
async fn authorize_current_user_accepts_oidc_token_without_client_id() {
    // Some OIDC providers (e.g. Authentik) do not include client_id in the access token.
    // The verifier must accept such tokens after rfc9068.rs made client_id optional.
    let issuer = "https://issuer.example.test";
    let audience = "demo-api";
    let required_scopes = ["openid", "profile", "email", "confluence", "offline_access"];
    let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
    let state = oidc_state(jwks_json, issuer, Some(audience), &required_scopes).await;

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key".to_string());
    let token = encode(
        &header,
        &ScopedClaims {
            sub: "user-no-client-id".to_string(),
            iss: issuer.to_string(),
            aud: vec![audience.to_string()],
            exp: future_exp(),
            iat: issued_at(),
            jti: "token-no-client-id".to_string(),
            client_id: None,
            scope: required_scopes.join(" "),
        },
        &EncodingKey::from_secret(b"super-secret"),
    )
    .expect("token should be created");
    let auth_header = bearer_header(&token);

    let current_user = authorize_current_user(Some(&auth_header), state)
        .await
        .expect("token without client_id should be accepted");

    assert_eq!(current_user.user_id, "user-no-client-id");
}

#[tokio::test]
async fn authorize_current_user_accepts_oidc_token_when_audience_validation_disabled() {
    // When CONFLUENCE_OIDC_AUDIENCE is absent, audiences is empty and validation is skipped.
    // Tokens with any (or no) aud claim should be accepted as long as scopes match.
    let issuer = "https://issuer.example.test";
    let required_scopes = ["openid", "profile", "email", "confluence", "offline_access"];
    let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
    let state = oidc_state(jwks_json, issuer, None, &required_scopes).await;

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key".to_string());
    let token = encode(
        &header,
        &ScopedClaims {
            sub: "user-any-aud".to_string(),
            iss: issuer.to_string(),
            aud: vec!["some-other-resource".to_string()],
            exp: future_exp(),
            iat: issued_at(),
            jti: "token-no-aud-check".to_string(),
            client_id: None,
            scope: required_scopes.join(" "),
        },
        &EncodingKey::from_secret(b"super-secret"),
    )
    .expect("token should be created");
    let auth_header = bearer_header(&token);

    let current_user = authorize_current_user(Some(&auth_header), state)
        .await
        .expect("token should be accepted when audience validation is disabled");

    assert_eq!(current_user.user_id, "user-any-aud");
}

#[tokio::test]
async fn authorize_current_user_rejects_oidc_audience_mismatch() {
    let issuer = "https://issuer.example.test";
    let audience = "demo-api";
    let required_scopes = ["openid", "profile", "email", "confluence", "offline_access"];
    let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
    let state = oidc_state(jwks_json, issuer, Some(audience), &required_scopes).await;

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key".to_string());
    let token = encode(
        &header,
        &ScopedClaims {
            sub: "user-123".to_string(),
            iss: issuer.to_string(),
            aud: vec!["other-api".to_string()],
            exp: future_exp(),
            iat: issued_at(),
            jti: "token-audience-mismatch".to_string(),
            client_id: Some("outposts-web".to_string()),
            scope: required_scopes.join(" "),
        },
        &EncodingKey::from_secret(b"super-secret"),
    )
    .expect("token should be created");
    let auth_header = bearer_header(&token);

    let err = authorize_current_user(Some(&auth_header), state)
        .await
        .err()
        .expect("audience mismatch should be rejected");

    assert!(matches!(err, AppError::Unauthorized { .. }));
}

#[tokio::test]
async fn authorize_current_user_rejects_missing_oidc_scope() {
    let issuer = "https://issuer.example.test";
    let audience = "demo-api";
    let required_scopes = ["openid", "profile", "email", "confluence", "offline_access"];
    let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
    let state = oidc_state(jwks_json, issuer, Some(audience), &required_scopes).await;

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key".to_string());
    let token = encode(
        &header,
        &ScopedClaims {
            sub: "user-123".to_string(),
            iss: issuer.to_string(),
            aud: vec![audience.to_string()],
            exp: future_exp(),
            iat: issued_at(),
            jti: "token-missing-scope".to_string(),
            client_id: Some("outposts-web".to_string()),
            scope: "openid profile confluence".to_string(),
        },
        &EncodingKey::from_secret(b"super-secret"),
    )
    .expect("token should be created");
    let auth_header = bearer_header(&token);

    let err = authorize_current_user(Some(&auth_header), state)
        .await
        .err()
        .expect("missing scope should be rejected");

    assert!(err.to_string().contains("required scopes"));
}
