use crate::clash::http::{SUB_DOWNLOAD, SUB_EXPIRE, SUB_TOTAL, SUB_UPLOAD};
use crate::clash::{ClashConfig, parse_subscription_userinfo_in_header};
use crate::error::AppError;
use crate::models::subscribe_source::{
    self, SubscribeSourceSyncError, SubscribeSourceSyncErrorKind,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use sea_orm::prelude::*;
use sea_orm::{IntoActiveModel, QuerySelect, Set, TransactionTrait};
use serde_yaml::Value;

const ERROR_BODY_LIMIT: usize = 64 * 1024;

impl SubscribeSourceSyncError {
    fn new(kind: SubscribeSourceSyncErrorKind, message: impl AsRef<str>) -> Self {
        let mut message = message.as_ref().replace('\0', "\u{FFFD}");
        message.truncate(message.floor_char_boundary(1024));
        Self {
            kind,
            message,
            occurred_at: chrono::Utc::now().timestamp_millis(),
            status: None,
            headers: Vec::new(),
            body: None,
            body_truncated: false,
        }
    }

    fn from_request_error(error: reqwest::Error) -> Self {
        Self::new(
            SubscribeSourceSyncErrorKind::Request,
            error.without_url().to_string(),
        )
    }

    fn with_response(
        mut self,
        status: StatusCode,
        headers: &HeaderMap,
        body: Option<&str>,
    ) -> Self {
        self.status = Some(status.as_u16());
        self.headers = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        if let Some(body) = body {
            // PostgreSQL JSONB rejects NUL even in escaped strings.
            let mut body = body.replace('\0', "\u{FFFD}");
            self.body_truncated = body.len() > ERROR_BODY_LIMIT;
            body.truncate(body.floor_char_boundary(ERROR_BODY_LIMIT));
            self.body = Some(body);
        }
        self
    }
}

fn source_client(
    sm: &subscribe_source::Model,
    ua: &str,
) -> Result<Client, SubscribeSourceSyncError> {
    let mut builder = Client::builder().user_agent(ua);
    if let Some(proxy_server) = &sm.proxy_server
        && !proxy_server.is_empty()
    {
        let mut proxy = reqwest::Proxy::all(proxy_server)
            .map_err(SubscribeSourceSyncError::from_request_error)?;
        if let Some(proxy_auth) = &sm.proxy_auth
            && !proxy_auth.is_empty()
        {
            let value = HeaderValue::from_str(proxy_auth).map_err(|_| {
                SubscribeSourceSyncError::new(
                    SubscribeSourceSyncErrorKind::Request,
                    "Invalid proxy auth header",
                )
            })?;
            proxy = proxy.custom_http_auth(value);
        }
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(SubscribeSourceSyncError::from_request_error)
}

fn validate_source_content(content: &str) -> Result<(), SubscribeSourceSyncError> {
    use SubscribeSourceSyncErrorKind::{InvalidConfig, InvalidYaml, MissingProxies};

    let document: Value = serde_yaml::from_str(content)
        .map_err(|error| SubscribeSourceSyncError::new(InvalidYaml, error.to_string()))?;
    if !document
        .get("proxies")
        .and_then(Value::as_sequence)
        .is_some_and(|proxies| !proxies.is_empty())
    {
        return Err(SubscribeSourceSyncError::new(
            MissingProxies,
            "Expected a non-empty proxies list",
        ));
    }
    ClashConfig::from_source_document(document)
        .map_err(|error| SubscribeSourceSyncError::new(InvalidConfig, error.to_string()))?;
    Ok(())
}

async fn fetch_source(
    sm: &subscribe_source::Model,
    ua: &str,
) -> Result<(String, HeaderMap), SubscribeSourceSyncError> {
    let response = source_client(sm, ua)?
        .get(&sm.url)
        .send()
        .await
        .map_err(SubscribeSourceSyncError::from_request_error)?;
    let status = response.status();
    let headers = response.headers().clone();
    let content = response.text().await.map_err(|error| {
        SubscribeSourceSyncError::new(
            SubscribeSourceSyncErrorKind::ReadBody,
            error.without_url().to_string(),
        )
        .with_response(status, &headers, None)
    })?;
    if !status.is_success() {
        return Err(SubscribeSourceSyncError::new(
            SubscribeSourceSyncErrorKind::HttpStatus,
            format!("HTTP {status}"),
        )
        .with_response(status, &headers, Some(&content)));
    }
    validate_source_content(&content)
        .map_err(|error| error.with_response(status, &headers, Some(&content)))?;
    Ok((content, headers))
}

pub async fn sync_one_subscribe_source_with_url(
    sm: subscribe_source::Model,
    ua: &str,
    db: &DatabaseConnection,
) -> Result<subscribe_source::Model, AppError> {
    let (content, headers) = match fetch_source(&sm, ua).await {
        Ok(result) => result,
        Err(error) => {
            // A failed fetch must not overwrite a successful concurrent update or its metadata.
            let mut rows = subscribe_source::Entity::update_many()
                .set(subscribe_source::ActiveModel {
                    last_sync_error: Set(Some(error)),
                    ..Default::default()
                })
                .filter(subscribe_source::Column::Id.eq(sm.id))
                .exec_with_returning(db)
                .await?;
            return rows.pop().ok_or_else(|| {
                AppError::not_found("Subscription source was deleted during refresh")
            });
        }
    };

    let tx = db.begin().await?;
    let mut sm = subscribe_source::Entity::find_by_id(sm.id)
        .lock_exclusive()
        .one(&tx)
        .await?
        .ok_or_else(|| AppError::not_found("Subscription source was deleted during refresh"))?
        .into_active_model();
    if let Some(userinfo) = parse_subscription_userinfo_in_header(&headers) {
        if let Some(v) = userinfo.get(SUB_DOWNLOAD) {
            sm.sub_download = Set(Some(*v));
        }
        if let Some(v) = userinfo.get(SUB_UPLOAD) {
            sm.sub_upload = Set(Some(*v));
        }
        if let Some(v) = userinfo.get(SUB_TOTAL) {
            sm.sub_total = Set(Some(*v));
        }
        if let Some(v) = userinfo.get(SUB_EXPIRE)
            && let Some(ts) = chrono::DateTime::from_timestamp(*v, 0)
        {
            sm.sub_expire = Set(Some(ts.naive_utc()));
        }
    }
    sm.content = Set(content);
    sm.last_sync_error = Set(None);
    let sm = sm.update(&tx).await?;
    tx.commit().await?;
    Ok(sm)
}
