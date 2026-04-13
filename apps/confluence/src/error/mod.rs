use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use reqwest::Error as FetchError;
use sea_orm::DbErr;
use securitydept_core::oauth_resource_server::OAuthResourceServerError;
use securitydept_core::token_set_context::access_token_substrate::AccessTokenSubstrateResourceServiceError;
use snafu::Snafu;
use std::fmt::Debug;
use std::net::AddrParseError;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)))]
pub enum ConfigError {
    #[snafu(display(
        "invalid server format {server} from source config {config_name}, caused by {source_kind:?}"
    ))]
    ProxyServerInvalid {
        config_name: String,
        server: String,
        source_kind: addr::error::Kind,
    },
    #[snafu(display(
        "invalid server format {server} from source config {config_name}, caused by {source}"
    ))]
    ProxyServerIpInvalid {
        config_name: String,
        server: String,
        source: AddrParseError,
    },
    #[snafu(display("format error: {source}"))]
    Format { source: serde_yaml::Error },
    #[snafu(display(
        "subscribe source {subscribe_source_name} empty or not sync, please sync first"
    ))]
    NotSync { subscribe_source_name: String },
    #[snafu(display("other config error: {message}"))]
    Other { message: String },
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(source: serde_yaml::Error) -> Self {
        Self::Format { source }
    }
}

#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)))]
pub enum AppError {
    #[snafu(display("database error: {source}"))]
    Db { source: DbErr },
    #[snafu(display("{message}"))]
    DbNotFound { message: String },
    #[snafu(display("config error: {source}"))]
    Config { source: ConfigError },
    #[snafu(display("fetch error: {source}"))]
    Fetch { source: FetchError },
    #[snafu(display("UNAUTHORIZED: caused by {message}"))]
    Unauthorized { message: String },
    #[snafu(display("{message}"))]
    BadRequest { message: String },
    #[snafu(display("Invalid proxy auth header"))]
    InvalidProxyAuthHeader,
    #[snafu(display("internal error: {message}"))]
    Internal { message: String },
}

impl From<DbErr> for AppError {
    fn from(source: DbErr) -> Self {
        Self::Db { source }
    }
}

impl From<ConfigError> for AppError {
    fn from(source: ConfigError) -> Self {
        Self::Config { source }
    }
}

impl From<FetchError> for AppError {
    fn from(source: FetchError) -> Self {
        Self::Fetch { source }
    }
}

impl From<AccessTokenSubstrateResourceServiceError> for AppError {
    fn from(err: AccessTokenSubstrateResourceServiceError) -> Self {
        match err {
            // Delegate OAuth resource server errors to the existing mapping.
            AccessTokenSubstrateResourceServiceError::OAuthResourceServer { source } => {
                AppError::from(source)
            }
            // Bearer token missing or not in Bearer scheme.
            AccessTokenSubstrateResourceServiceError::BearerTokenRequired => {
                AppError::unauthorized_str("bearer token required")
            }
            // Propagation errors — confluence does not enable propagation, map to internal.
            AccessTokenSubstrateResourceServiceError::PropagationNotEnabled
            | AccessTokenSubstrateResourceServiceError::PropagationDirectiveRequired
            | AccessTokenSubstrateResourceServiceError::PropagationDirectiveInvalid { .. }
            | AccessTokenSubstrateResourceServiceError::Propagation { .. } => {
                AppError::internal_str("unexpected token propagation error")
            }
        }
    }
}

impl From<OAuthResourceServerError> for AppError {
    fn from(source: OAuthResourceServerError) -> Self {
        match source {
            OAuthResourceServerError::InvalidConfig { message }
            | OAuthResourceServerError::Metadata { message }
            | OAuthResourceServerError::HttpClient { message } => Self::Internal { message },
            OAuthResourceServerError::Introspection { message }
            | OAuthResourceServerError::PolicyViolation { message } => {
                Self::Unauthorized { message }
            }
            OAuthResourceServerError::TokenValidation { source } => Self::Unauthorized {
                message: source.to_string(),
            },
            OAuthResourceServerError::UnsupportedTokenFormat { token_format } => {
                Self::Unauthorized {
                    message: format!(
                        "OAuth resource server does not support {token_format:?} access tokens in this verifier"
                    ),
                }
            }
        }
    }
}

impl AppError {
    pub fn unauthorized<E>(source: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Unauthorized {
            message: source.to_string(),
        }
    }

    pub fn unauthorized_str<E>(source: E) -> Self
    where
        E: Into<String>,
    {
        Self::Unauthorized {
            message: source.into(),
        }
    }

    pub fn internal_str<E>(source: E) -> Self
    where
        E: Into<String>,
    {
        Self::Internal {
            message: source.into(),
        }
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error_code = match &self {
            Self::Db { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DbNotFound { .. } => StatusCode::NOT_FOUND,
            Self::Config { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Fetch { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::InvalidProxyAuthHeader => StatusCode::BAD_REQUEST,
        };
        let error_msg = self.to_string();

        if error_code.is_server_error() {
            tracing::error!("Internal server error response: {:?}", self);
        } else if error_code.is_client_error() {
            tracing::warn!("Client error response: {:?}", self);
        }

        let error_body = serde_json::json!({ "error_msg": error_msg });
        (error_code, Json(error_body)).into_response()
    }
}
