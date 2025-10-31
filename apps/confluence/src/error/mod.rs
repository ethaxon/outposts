use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use reqwest::Error as FetchError;
use sea_orm::DbErr;
use std::fmt::Debug;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid server format {server} from source config {config_name}, caused by {source_kind:?}")]
    ProxyServerInvalid {
        config_name: String,
        server: String,
        source_kind: addr::error::Kind,
    },
    #[error(
        "invalid server format {server} from source config {config_name}, caused by {source:?}"
    )]
    ProxyServerIpInvalid {
        config_name: String,
        server: String,
        source: AddrParseError,
    },
    #[error(transparent)]
    Format(#[from] serde_yaml::Error),
    #[error("subscribe source {subscribe_source_name} empty or not sync, please sync first")]
    NotSync { subscribe_source_name: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("{0}")]
    DbNotFound(String),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("UNAUTHORIZED: caused by {0:#?}")]
    Unauthorized(anyhow::Error),
    #[error("{message}")]
    BadRequest { message: String },
    #[error("Invalid proxy auth header")]
    InvalidProxyAuthHeader,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    pub fn unauthorized<E>(source: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Unauthorized(source.into())
    }

    pub fn unauthorized_str<E>(source: E) -> Self
    where
        E: Into<String>,
    {
        Self::Unauthorized(anyhow::anyhow!(source.into()))
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error_code = match &self {
            Self::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DbNotFound(_) => StatusCode::NOT_FOUND,
            Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Fetch(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::InvalidProxyAuthHeader => StatusCode::BAD_REQUEST,
        };
        let error_msg = self.to_string();
        let error_body = serde_json::json!({ "error_msg": error_msg });
        (error_code, Json(error_body)).into_response()
    }
}
