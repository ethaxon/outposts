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
    BASIC { username: String, password: String },
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
    use super::parse_scopes;

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
