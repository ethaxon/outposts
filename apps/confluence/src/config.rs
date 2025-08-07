#[derive(Clone, Debug)]
pub enum AuthConfig {
    OIDC { issuer: String, audience: String },
    BASIC { username: String, password: String },
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen: String,
    pub auth: AuthConfig,
    pub database_url: String,
}
