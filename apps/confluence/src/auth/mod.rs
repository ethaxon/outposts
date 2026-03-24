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
use jsonwebtoken::{
    DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata};
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
) -> Result<Arc<JwkSet>, AppError> {
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
            .map_err(|e| AppError::unauthorized(format!("Invalid issuer URL: {}", e)))?;

        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                AppError::unauthorized(format!(
                    "Failed to build OIDC discovery HTTP client: {}",
                    e
                ))
            })?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| {
                AppError::unauthorized(format!("Failed to discover OIDC provider: {}", e))
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

    let jwk_set: JwkSet =
        serde_json::from_str(&jwks_res).map_err(AppError::unauthorized)?;

    let jwk_set = Arc::new(jwk_set);

    // Update JWKS cache
    let mut jwks = state.jwks.write().await;
    *jwks = Some(JwksConfig {
        jwks_expiry: std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(300)) // Cache for 5 minutes
            .ok_or_else(|| AppError::internal_str("get_jwks_cached failed to add 5 mins"))?,
        jwks_set: jwk_set.clone(),
    });

    Ok(jwk_set)
}

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(value) => value == audience,
            Self::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ScopedClaims {
    pub sub: String,
    pub iss: String,
    pub aud: AudienceClaim,
    pub exp: usize,
    pub scope: String,
}

fn find_matching_jwk<'a>(jwk_set: &'a JwkSet, kid: Option<&str>) -> Result<&'a Jwk, AppError> {
    match kid {
        Some(kid) => jwk_set
            .find(kid)
            .ok_or_else(|| AppError::unauthorized_str(format!("no jwk found for kid {}", kid))),
        None if jwk_set.keys.len() == 1 => jwk_set
            .keys
            .first()
            .ok_or_else(|| AppError::unauthorized_str("jwks is empty")),
        None => Err(AppError::unauthorized_str(
            "auth token missing kid header while jwks contains multiple keys",
        )),
    }
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
            let header = decode_header(auth_token).map_err(AppError::unauthorized)?;
            let jwk = find_matching_jwk(jwk_set.as_ref(), header.kid.as_deref())?;
            let decoding_key = DecodingKey::try_from(jwk).map_err(AppError::unauthorized)?;
            let mut validation = Validation::new(header.alg);
            validation.validate_nbf = false;
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["exp", "iss", "sub"]);

            let claims = decode::<ScopedClaims>(auth_token, &decoding_key, &validation)
                .map_err(AppError::unauthorized)?;

            if claims.claims.iss != *issuer {
                return Err(AppError::unauthorized_str("auth payload issuer mismatch"));
            }

            if !claims.claims.aud.contains(audience) {
                return Err(AppError::unauthorized_str("auth payload audience mismatch"));
            }

            // Validate scope
            if !claims.claims.scope.contains(READ_SCOPE)
                || !claims.claims.scope.contains(WRITE_SCOPE)
            {
                return Err(AppError::unauthorized_str(format!(
                    "missing required scopes {} {}",
                    READ_SCOPE, WRITE_SCOPE
                )));
            }

            Ok(CurrentUser {
                user_id: claims.claims.sub,
            })
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
mod tests {
    use super::{
        AudienceClaim, OidcProviderConfig, READ_SCOPE, ScopedClaims, WRITE_SCOPE,
        authorize_current_user, find_matching_jwk,
    };
    use crate::config::{AppConfig, AuthConfig};
    use crate::services::{AppState, JwksConfig};
    use base64::Engine as _;
    use jsonwebtoken::{
        Algorithm, EncodingKey, Header, encode,
        jwk::JwkSet,
    };
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn mock_state(auth: AuthConfig) -> Arc<AppState> {
        let conn = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        Arc::new(AppState::new(
            conn,
            AppConfig {
                listen: "127.0.0.1:4001".to_string(),
                auth,
                database_url: "postgres://example".to_string(),
            },
        ))
    }

    fn bearer_header(token: &str) -> String {
        format!("Bearer {}", token)
    }

    fn basic_header(username: &str, password: &str) -> String {
        let credentials = format!("{}:{}", username, password);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )
    }

    fn future_exp() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs() as usize
            + 3600
    }

    async fn cached_oidc_state(jwks_json: &str, issuer: &str, audience: &str) -> Arc<AppState> {
        let state = mock_state(AuthConfig::OIDC {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        });
        let jwks_set: JwkSet = serde_json::from_str(jwks_json).expect("jwks should be valid");

        {
            let mut oidc_provider = state.oidc_provider.write().await;
            *oidc_provider = Some(OidcProviderConfig {
                jwks_uri: "https://issuer.example.test/jwks".to_string(),
                issuer: issuer.to_string(),
                expiry: Instant::now() + Duration::from_secs(60),
            });
        }

        {
            let mut jwks = state.jwks.write().await;
            *jwks = Some(JwksConfig {
                jwks_set: Arc::new(jwks_set),
                jwks_expiry: Instant::now() + Duration::from_secs(60),
            });
        }

        state
    }

    #[test]
    fn audience_claim_contains_expected_values() {
        assert!(AudienceClaim::One("demo-api".to_string()).contains("demo-api"));
        assert!(!AudienceClaim::One("other-api".to_string()).contains("demo-api"));
        assert!(AudienceClaim::Many(vec!["other-api".to_string(), "demo-api".to_string()])
            .contains("demo-api"));
    }

    #[tokio::test]
    async fn authorize_current_user_accepts_basic_credentials() {
        let state = mock_state(AuthConfig::BASIC {
            username: "demo".to_string(),
            password: "secret".to_string(),
        });
        let auth_header = basic_header("demo", "secret");

        let current_user = authorize_current_user(Some(&auth_header), state)
            .await
            .expect("basic auth should succeed");

        assert_eq!(current_user.user_id, "demo");
    }

    #[tokio::test]
    async fn authorize_current_user_rejects_invalid_basic_credentials() {
        let state = mock_state(AuthConfig::BASIC {
            username: "demo".to_string(),
            password: "secret".to_string(),
        });
        let auth_header = basic_header("demo", "wrong");

        let err = authorize_current_user(Some(&auth_header), state)
            .await
            .err()
            .expect("invalid password should be rejected");

        assert!(err.to_string().contains("invalid username or password"));
    }

    #[tokio::test]
    async fn authorize_current_user_accepts_cached_oidc_token() {
        let issuer = "https://issuer.example.test";
        let audience = "demo-api";
        let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
        let state = cached_oidc_state(jwks_json, issuer, audience).await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(
            &header,
            &ScopedClaims {
                sub: "user-123".to_string(),
                iss: issuer.to_string(),
                aud: AudienceClaim::Many(vec![audience.to_string(), "other-api".to_string()]),
                exp: future_exp(),
                scope: format!("{} {}", READ_SCOPE, WRITE_SCOPE),
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
    async fn authorize_current_user_accepts_single_jwk_without_kid() {
        let issuer = "https://issuer.example.test";
        let audience = "demo-api";
        let jwks_json = r#"{"keys":[{"kty":"oct","kid":"only-key","k":"c3VwZXItc2VjcmV0"}]}"#;
        let state = cached_oidc_state(jwks_json, issuer, audience).await;

        let header = Header::new(Algorithm::HS256);
        let token = encode(
            &header,
            &ScopedClaims {
                sub: "solo-user".to_string(),
                iss: issuer.to_string(),
                aud: AudienceClaim::One(audience.to_string()),
                exp: future_exp(),
                scope: format!("{} {}", READ_SCOPE, WRITE_SCOPE),
            },
            &EncodingKey::from_secret(b"super-secret"),
        )
        .expect("token should be created");
        let auth_header = bearer_header(&token);

        let current_user = authorize_current_user(Some(&auth_header), state)
            .await
            .expect("single jwk without kid should still succeed");

        assert_eq!(current_user.user_id, "solo-user");
    }

    #[tokio::test]
    async fn authorize_current_user_rejects_oidc_issuer_mismatch() {
        let issuer = "https://issuer.example.test";
        let audience = "demo-api";
        let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
        let state = cached_oidc_state(jwks_json, issuer, audience).await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(
            &header,
            &ScopedClaims {
                sub: "user-123".to_string(),
                iss: "https://wrong-issuer.example.test".to_string(),
                aud: AudienceClaim::One(audience.to_string()),
                exp: future_exp(),
                scope: format!("{} {}", READ_SCOPE, WRITE_SCOPE),
            },
            &EncodingKey::from_secret(b"super-secret"),
        )
        .expect("token should be created");
        let auth_header = bearer_header(&token);

        let err = authorize_current_user(Some(&auth_header), state)
            .await
            .err()
            .expect("issuer mismatch should be rejected");

        assert!(err.to_string().contains("auth payload issuer mismatch"));
    }

    #[tokio::test]
    async fn authorize_current_user_rejects_oidc_audience_mismatch() {
        let issuer = "https://issuer.example.test";
        let audience = "demo-api";
        let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
        let state = cached_oidc_state(jwks_json, issuer, audience).await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(
            &header,
            &ScopedClaims {
                sub: "user-123".to_string(),
                iss: issuer.to_string(),
                aud: AudienceClaim::Many(vec!["other-api".to_string()]),
                exp: future_exp(),
                scope: format!("{} {}", READ_SCOPE, WRITE_SCOPE),
            },
            &EncodingKey::from_secret(b"super-secret"),
        )
        .expect("token should be created");
        let auth_header = bearer_header(&token);

        let err = authorize_current_user(Some(&auth_header), state)
            .await
            .err()
            .expect("audience mismatch should be rejected");

        assert!(err.to_string().contains("auth payload audience mismatch"));
    }

    #[tokio::test]
    async fn authorize_current_user_rejects_missing_oidc_scope() {
        let issuer = "https://issuer.example.test";
        let audience = "demo-api";
        let jwks_json = r#"{"keys":[{"kty":"oct","kid":"test-key","k":"c3VwZXItc2VjcmV0"}]}"#;
        let state = cached_oidc_state(jwks_json, issuer, audience).await;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        let token = encode(
            &header,
            &ScopedClaims {
                sub: "user-123".to_string(),
                iss: issuer.to_string(),
                aud: AudienceClaim::One(audience.to_string()),
                exp: future_exp(),
                scope: READ_SCOPE.to_string(),
            },
            &EncodingKey::from_secret(b"super-secret"),
        )
        .expect("token should be created");
        let auth_header = bearer_header(&token);

        let err = authorize_current_user(Some(&auth_header), state)
            .await
            .err()
            .expect("missing scope should be rejected");

        assert!(err
            .to_string()
            .contains("missing required scopes read:confluence write:confluence"));
    }

    #[test]
    fn find_matching_jwk_requires_kid_when_multiple_keys_exist() {
        let jwks: JwkSet = serde_json::from_str(
            r#"{
                "keys":[
                    {"kty":"oct","kid":"key-1","k":"c2VjcmV0LTE"},
                    {"kty":"oct","kid":"key-2","k":"c2VjcmV0LTI"}
                ]
            }"#,
        )
        .expect("jwks should be valid");

        let err = find_matching_jwk(&jwks, None).expect_err("kid should be required");

        assert!(err
            .to_string()
            .contains("auth token missing kid header while jwks contains multiple keys"));
    }
}
