#[derive(Clone, Debug)]
pub enum AuthConfig {
    JWT {
        jwks_uri: String,
        issuer: String,
        audience: String,
    },
    DevNoAuth {
        user_id: String,
    },
}

impl AuthConfig {
    pub fn get_jwks_uri(&self) -> Option<&str> {
        if let AuthConfig::JWT { jwks_uri, .. } = &self {
            Some(jwks_uri as &str)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
    pub auth: AuthConfig,
    pub database_url: String,
}
