#[derive(Clone, Debug)]
pub enum AuthConfig {
    OIDC {
        issuer: String,
        audience: String,
        required_scopes: Vec<String>,
        user_claim: String,
        /// OIDC client_id for the frontend web application.
        ///
        /// Served via `/api/auth/config` so the browser client can bootstrap
        /// its authorization code + PKCE flow without baking credentials into
        /// the frontend bundle. The backend itself is a resource server and
        /// does not perform its own OIDC flows.
        frontend_client_id: String,
    },
    /// Local development only (debug builds): all requests are accepted without credentials.
    DEV { user_id: String },
}

/// DEV auth is only permitted in development (debug) builds.
pub fn assert_dev_auth_allowed() -> Result<(), String> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err(
            "AUTH_TYPE=DEV is only permitted in development builds (compile with debug profile)"
                .to_string(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen: String,
    pub auth: AuthConfig,
    pub database_url: String,
}

pub fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .fold(Vec::new(), |mut scopes, scope| {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.to_string());
            }
            scopes
        })
}

#[cfg(test)]
mod tests {
    use super::{assert_dev_auth_allowed, parse_scopes};

    #[test]
    fn assert_dev_auth_allowed_matches_build_profile() {
        let result = assert_dev_auth_allowed();
        if cfg!(debug_assertions) {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn parse_scopes_accepts_space_and_comma_separated_values() {
        assert_eq!(
            parse_scopes("openid profile,email  confluence offline_access,confluence"),
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "confluence".to_string(),
                "offline_access".to_string(),
            ]
        );
    }
}
