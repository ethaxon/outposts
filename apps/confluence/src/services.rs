use crate::auth::CurrentUser;
use crate::clash::http::{
    SUB_DOWNLOAD, SUB_EXPIRE, SUB_TOTAL, SUB_UPLOAD, SUBSCRIPTION_USERINFO_HEADER,
};
use crate::clash::{ClashConfig, parse_subscription_userinfo_in_header};
use crate::config::AppConfig;
use crate::dto::{
    ConfluenceUpdateCronDto, SubscribeSourceCreationDto, SubscribeSourceDto,
    SubscribeSourceUpdateDto,
};
use crate::error::ConfigError;
use crate::models::subscribe_source;
use crate::mux::mux_configs;
use crate::{
    dto::ProfileCreationDto,
    error::AppError,
    models::profile,
    {
        dto::{ConfluenceDto, ConfluenceUpdateDto, ProfileDto},
        models,
        models::confluence,
    },
};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::{Extension, Json};
use chrono_tz::Tz;
use cron::Schedule;
use futures::future::try_join_all;
use itertools::izip;
use sea_orm::ActiveValue::Set;
use sea_orm::prelude::*;
use sea_orm::{IntoActiveModel, QuerySelect, TryIntoModel};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct JwksConfig {
    pub jwks_set: Arc<biscuit::jwk::JWKSet<biscuit::Empty>>,
    pub jwks_expiry: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub conn: DatabaseConnection,
    pub config: AppConfig,
    pub names_generator: Arc<rnglib::RNG>,
    pub jwks: Arc<RwLock<Option<JwksConfig>>>,
}

impl AppState {
    pub fn new(conn: DatabaseConnection, config: AppConfig) -> Self {
        Self {
            conn,
            config,
            names_generator: Arc::new(rnglib::RNG::from(&rnglib::Language::Elven)),
            jwks: Arc::new(RwLock::new(None)),
        }
    }
}

pub async fn find_one_confluence_in_db(
    db: &DatabaseConnection,
    id: i32,
    current_user: &CurrentUser,
) -> Result<confluence::Model, AppError> {
    confluence::Entity::find_by_id(id)
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .one(db)
        .await?
        .ok_or_else(|| AppError::DbNotFound(format!("cannot find post id = {} for you", id)))
}

pub async fn find_certain_confluence_profiles_and_subscribe_sources(
    db: &DatabaseConnection,
    id: i32,
) -> Result<(Vec<profile::Model>, Vec<subscribe_source::Model>), AppError> {
    tokio::try_join!(
        profile::Entity::find()
            .filter(profile::Column::ConfluenceId.eq(id))
            .all(db),
        subscribe_source::Entity::find()
            .filter(subscribe_source::Column::ConfluenceId.eq(id))
            .all(db)
    )
    .map_err(AppError::from)
}

pub(crate) async fn passive_sync_one_subscribe_source_with_url(
    sm: subscribe_source::Model,
    ua: &str,
    db: &DatabaseConnection,
) -> Result<subscribe_source::Model, AppError> {
    if sm.passive_sync.is_some_and(|ps| ps) {
        return Ok(sm);
    }
    sync_one_subscribe_source_with_url(sm, ua, db).await
}

pub async fn sync_one_subscribe_source_with_url(
    sm: subscribe_source::Model,
    ua: &str,
    db: &DatabaseConnection,
) -> Result<subscribe_source::Model, AppError> {
    let mut client_builder = reqwest::ClientBuilder::new().user_agent(ua);

    if let Some(proxy_server) = &sm.proxy_server
        && !proxy_server.is_empty()
    {
        let mut proxy = reqwest::Proxy::all(proxy_server)?;
        if let Some(proxy_auth) = &sm.proxy_auth
            && !proxy_auth.is_empty()
        {
            proxy = proxy.custom_http_auth(
                HeaderValue::from_str(proxy_auth).map_err(|_| AppError::InvalidProxyAuthHeader)?,
            );
        }
        client_builder = client_builder.proxy(proxy);
    }

    let client = client_builder.build()?;
    let res = client.get(&sm.url).send().await?;
    let mut sm = sm.into_active_model();
    if let Some(sub_userinfo) = parse_subscription_userinfo_in_header(res.headers()) {
        if let Some(v) = sub_userinfo.get(SUB_DOWNLOAD) {
            sm.sub_download = Set(Some(*v));
        };
        if let Some(v) = sub_userinfo.get(SUB_UPLOAD) {
            sm.sub_upload = Set(Some(*v));
        };
        if let Some(v) = sub_userinfo.get(SUB_TOTAL) {
            sm.sub_total = Set(Some(*v));
        };
        if let Some(v) = sub_userinfo.get(SUB_EXPIRE)
            && let Some(ts) = chrono::DateTime::from_timestamp(*v, 0)
        {
            sm.sub_expire = Set(Some(ts.naive_utc()));
        };
    };
    let content = res.text().await?;
    sm.content = Set(content);
    let sm = sm.update(db).await?;
    Ok(sm)
}

pub async fn find_one_confluence(
    Path(id): Path<i32>,
    Extension(current_user): Extension<CurrentUser>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ConfluenceDto>, AppError> {
    let db = &state.conn;

    let cm = find_one_confluence_in_db(db, id, &current_user).await?;

    let (pms, sms) = find_certain_confluence_profiles_and_subscribe_sources(db, id).await?;

    let confluence_dto = ConfluenceDto::from_orm(cm, sms, pms);
    Ok(Json(confluence_dto))
}

pub async fn find_many_confluences(
    Extension(current_user): Extension<CurrentUser>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ConfluenceDto>>, AppError> {
    let db = &state.conn;
    let cms = confluence::Entity::find()
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .all(db)
        .await;

    let cms = cms?;

    let (pms, sms) = tokio::try_join!(
        cms.load_many(models::profile::Entity, db),
        cms.load_many(models::subscribe_source::Entity, db)
    )?;

    let confluences_dto = izip!(cms.into_iter(), pms.into_iter(), sms.into_iter())
        .map(|(cm, pms, sms)| ConfluenceDto::from_orm(cm, sms, pms))
        .collect::<Vec<_>>();

    Ok(Json(confluences_dto))
}

pub async fn create_one_confluence(
    Extension(current_user): Extension<CurrentUser>,
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<ConfluenceDto>), AppError> {
    let db = &state.conn;

    let name = state.names_generator.generate_name();

    let confluence_model = confluence::ActiveModel {
        mux_content: Set("".into()),
        template: Set("".into()),
        creator: Set(current_user.user_id),
        name: Set(name),
        ..Default::default()
    };

    let confluence_model = confluence_model.insert(db).await?;

    Ok((
        StatusCode::CREATED,
        Json(ConfluenceDto::from_orm(confluence_model, vec![], vec![])),
    ))
}

pub async fn update_one_confluence(
    Path(id): Path<i32>,
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Json(confluence_update_dto): Json<ConfluenceUpdateDto>,
) -> Result<Json<ConfluenceDto>, AppError> {
    let db = &state.conn;
    let cm = find_one_confluence_in_db(db, id, &current_user).await?;
    let mut cm = cm.into_active_model();
    if let Some(template) = confluence_update_dto.template {
        cm.template = Set(template);
    }
    if let Some(user_agent) = confluence_update_dto.user_agent {
        cm.user_agent = Set(user_agent);
    }
    if let Some(name) = confluence_update_dto.name {
        cm.name = Set(name);
    }
    cm = cm.save(db).await?;
    let cm = cm.try_into_model()?;

    let (pms, sms) = find_certain_confluence_profiles_and_subscribe_sources(db, id).await?;

    let confluence_dto = ConfluenceDto::from_orm(cm, sms, pms);

    Ok(Json(confluence_dto))
}

pub async fn update_one_confluence_cron(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<i32>,
    Json(confluence_update_cron_dto): Json<ConfluenceUpdateCronDto>,
) -> Result<(), AppError> {
    let db = &state.conn;
    let cm = find_one_confluence_in_db(db, id, &current_user).await?;
    let mut cm = cm.into_active_model();

    let schedule = Schedule::from_str(&confluence_update_cron_dto.cron_expr)
        .map_err(|e| anyhow::anyhow!(e))?;
    let tz = confluence_update_cron_dto
        .cron_expr_tz
        .parse::<Tz>()
        .map_err(|_| AppError::BadRequest {
            message: format!("bad timezone {}", &confluence_update_cron_dto.cron_expr_tz),
        })?;

    if let Some(next_time) = schedule.upcoming(tz).take(1).next() {
        cm.cron_expr = Set(Some(confluence_update_cron_dto.cron_expr));
        cm.cron_expr_tz = Set(Some(confluence_update_cron_dto.cron_expr_tz));
        cm.cron_next_at = Set(Some(
            chrono::DateTime::from_timestamp_millis(next_time.timestamp_millis())
                .map(|d| d.naive_utc())
                .ok_or_else(|| anyhow::anyhow!("failed to get next upcoming time"))?,
        ));
        cm.cron_prev_at = Set(None);
        cm.cron_err = Set(None);
    } else {
        return Err(anyhow::anyhow!("failed to get next upcoming time").into());
    }

    cm.update(db).await?;
    Ok(())
}

pub async fn sync_one_confluence(
    Path(id): Path<i32>,
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ConfluenceDto>, AppError> {
    let db = &state.conn;

    let cm = find_one_confluence_in_db(db, id, &current_user).await?;

    let ua = cm.user_agent_or_default();

    let (pms, sms) = find_certain_confluence_profiles_and_subscribe_sources(db, id).await?;

    let sms = try_join_all(
        sms.into_iter()
            .map(|sm| passive_sync_one_subscribe_source_with_url(sm, ua, db)),
    )
    .await?;

    let confluence_dto = ConfluenceDto::from_orm(cm, sms, pms);

    Ok(Json(confluence_dto))
}

pub async fn mux_one_confluence_impl(
    db: &DatabaseConnection,
    cm: confluence::Model,
    sms: Vec<subscribe_source::Model>,
    pms: Vec<profile::Model>,
) -> Result<
    (
        confluence::Model,
        Vec<subscribe_source::Model>,
        Vec<profile::Model>,
    ),
    AppError,
> {
    let template = serde_yaml::from_str::<ClashConfig>(&cm.template).map_err(ConfigError::from)?;
    let mut sources = vec![];
    let mut sub_upload: Option<i64> = None;
    let mut sub_download: Option<i64> = None;
    let mut sub_expire: Option<DateTime> = None;
    let mut sub_total: Option<i64> = None;
    for sm in &sms {
        let source = &sm.content as &str;
        let name = &sm.name as &str;
        if source.is_empty() {
            return Err(ConfigError::NotSync {
                subscribe_source_name: name.to_string(),
            }
            .into());
        }
        let config: ClashConfig = serde_yaml::from_str(source).map_err(ConfigError::from)?;
        sub_upload = match (sub_upload, sm.sub_upload) {
            (None, None) => None,
            (acc, curr) => Some(acc.unwrap_or_default() + curr.unwrap_or_default()),
        };
        sub_download = match (sub_download, sm.sub_download) {
            (None, None) => None,
            (acc, curr) => Some(acc.unwrap_or_default() + curr.unwrap_or_default()),
        };
        sub_total = match (sub_total, sm.sub_total) {
            (None, None) => None,
            (acc, curr) => Some(acc.unwrap_or_default() + curr.unwrap_or_default()),
        };
        sub_expire = match (sub_expire, sm.sub_expire) {
            (None, curr) => curr,
            (last_min, None) => last_min,
            (Some(last_min), Some(curr)) => {
                if last_min < curr {
                    Some(last_min)
                } else {
                    Some(curr)
                }
            }
        };
        sources.push((name, config));
    }
    let mux_config = mux_configs(cm.name.as_str(), &template, &sources)?;
    let mux_content = serde_yaml::to_string(&mux_config).map_err(ConfigError::from)?;
    let mut cm = cm.into_active_model();
    cm.mux_content = Set(mux_content);
    cm.sub_download = Set(sub_upload);
    cm.sub_expire = Set(sub_expire);
    cm.sub_total = Set(sub_total);
    cm.sub_upload = Set(sub_download);
    let cm = cm.update(db).await?;
    Ok((cm, sms, pms))
}

pub async fn mux_one_confluence(
    Path(id): Path<i32>,
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ConfluenceDto>, AppError> {
    let db = &state.conn;

    let cm = find_one_confluence_in_db(db, id, &current_user).await?;

    let (pms, sms) = find_certain_confluence_profiles_and_subscribe_sources(db, id).await?;

    let (cm, sms, pms) = mux_one_confluence_impl(db, cm, sms, pms).await?;

    let confluence_dto = ConfluenceDto::from_orm(cm, sms, pms);

    Ok(Json(confluence_dto))
}

pub async fn delete_one_confluence(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<i32>,
) -> Result<StatusCode, AppError> {
    let db = &state.conn;
    let cm = find_one_confluence_in_db(db, id, &current_user).await?;
    let cm = cm.into_active_model();
    cm.delete(db).await?;
    Ok(StatusCode::OK)
}

pub async fn find_one_profile_as_subscription_by_token(
    Path(token): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<(HeaderMap, String), AppError> {
    let db = &state.conn;
    let mut pms = profile::Entity::find()
        .filter(profile::Column::ResourceToken.eq(&token))
        .find_with_related(confluence::Entity)
        .limit(1)
        .all(db)
        .await?;
    if let Some((_, mut cms)) = pms.pop() {
        let cm = cms.pop().ok_or_else(|| {
            AppError::DbNotFound(format!("cannot find profile token = {}", token))
        })?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream; charset=utf-8"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("attachment; filename=Confluence.yaml"),
        );
        let sub_expr_to_part = |a: DateTime| {
            let ts = a.and_utc().timestamp();
            format!("{SUB_EXPIRE}={ts}")
        };
        match [
            cm.sub_upload.map(|a| format!("{SUB_UPLOAD}={a}")),
            cm.sub_download.map(|a| format!("{SUB_DOWNLOAD}={a}")),
            cm.sub_total.map(|a| format!("{SUB_TOTAL}={a}")),
            cm.sub_expire.map(sub_expr_to_part),
        ] {
            [None, None, None, None] => {}
            parts => {
                headers.insert(
                    HeaderName::from_str(SUBSCRIPTION_USERINFO_HEADER).unwrap(),
                    HeaderValue::from_str(
                        &parts
                            .into_iter()
                            .flatten()
                            .intersperse(String::from("; "))
                            .collect::<String>(),
                    )
                    .map_err(|err| AppError::Other(err.into()))?,
                );
            }
        };
        let mux_content = cm.mux_content;
        Ok((headers, mux_content))
    } else {
        Err(AppError::DbNotFound(format!(
            "cannot find profile token = {}",
            token
        )))
    }
}

pub async fn create_one_profile(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Json(profile_creation_dto): Json<ProfileCreationDto>,
) -> Result<Json<ProfileDto>, AppError> {
    let db = &state.conn;
    find_one_confluence_in_db(db, profile_creation_dto.confluence_id, &current_user).await?;
    let mut pms = profile::ActiveModel {
        resource_token: Set(Uuid::new_v4().to_string()),
        confluence_id: Set(profile_creation_dto.confluence_id),
        ..Default::default()
    };
    pms = pms.save(db).await?;
    let pms = pms.try_into_model()?;
    Ok(Json(pms.into()))
}

pub async fn delete_one_profile(
    Path(id): Path<i32>,
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<(), AppError> {
    let db = &state.conn;
    let mut pm = profile::Entity::find_by_id(id)
        .find_with_related(confluence::Entity)
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .limit(1)
        .all(db)
        .await?;
    if let Some((pm, _)) = pm.pop() {
        let pam = pm.into_active_model();
        pam.delete(db).await?;
        Ok(())
    } else {
        Err(AppError::DbNotFound(format!(
            "cannot find profile id = {}",
            id
        )))
    }
}

pub async fn create_one_subscribe_source(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Json(subscribe_creation_dto): Json<SubscribeSourceCreationDto>,
) -> Result<Json<SubscribeSourceDto>, AppError> {
    let db = &state.conn;
    find_one_confluence_in_db(db, subscribe_creation_dto.confluence_id, &current_user).await?;
    let mut pms = subscribe_source::ActiveModel {
        confluence_id: Set(subscribe_creation_dto.confluence_id),
        url: Set(subscribe_creation_dto.url),
        name: Set(subscribe_creation_dto.name),
        content: Set(String::new()),
        passive_sync: Set(subscribe_creation_dto.passive_sync),
        proxy_auth: Set(subscribe_creation_dto.proxy_auth),
        proxy_server: Set(subscribe_creation_dto.proxy_server),
        ..Default::default()
    };
    pms = pms.save(db).await?;
    let pms = pms.try_into_model()?;
    Ok(Json(pms.into()))
}

pub async fn update_one_subscribe_source(
    Path(id): Path<i32>,
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Json(subscribe_update_dto): Json<SubscribeSourceUpdateDto>,
) -> Result<Json<SubscribeSourceDto>, AppError> {
    let db = &state.conn;
    let mut pm = subscribe_source::Entity::find_by_id(id)
        .find_with_related(confluence::Entity)
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .limit(1)
        .all(db)
        .await?;
    if let Some(pm) = pm.pop() {
        let mut pam = pm.0.into_active_model();
        if let Some(name) = subscribe_update_dto.name {
            pam.name = Set(name);
        }
        if let Some(url) = subscribe_update_dto.url {
            pam.url = Set(url);
        };
        if let Some(content) = subscribe_update_dto.content {
            pam.content = Set(content);
        }
        if let Some(passive_sync) = subscribe_update_dto.passive_sync {
            pam.passive_sync = Set(Some(passive_sync));
        };
        if let Some(proxy_auth) = subscribe_update_dto.proxy_auth {
            pam.proxy_auth = Set(Some(proxy_auth));
        };
        if let Some(proxy_server) = subscribe_update_dto.proxy_server {
            pam.proxy_server = Set(Some(proxy_server));
        };
        let pam = pam.save(db).await?;
        let pm = pam.try_into_model()?;
        Ok(Json(pm.into()))
    } else {
        Err(AppError::DbNotFound(format!(
            "cannot find subscribe source id = {}",
            id
        )))
    }
}

pub async fn delete_one_subscribe_source(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<i32>,
) -> Result<(), AppError> {
    let db = &state.conn;
    let mut pm = subscribe_source::Entity::find_by_id(id)
        .find_with_related(confluence::Entity)
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .limit(1)
        .all(db)
        .await?;
    if let Some(pm) = pm.pop() {
        let pam = pm.0.into_active_model();
        pam.delete(db).await?;
        Ok(())
    } else {
        Err(AppError::DbNotFound(format!(
            "cannot find subscribe source id = {}",
            id
        )))
    }
}

pub async fn sync_one_subscribe_source(
    State(state): State<Arc<AppState>>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<i32>,
) -> Result<(), AppError> {
    let db = &state.conn;
    let mut pm = subscribe_source::Entity::find_by_id(id)
        .find_with_related(confluence::Entity)
        .filter(confluence::Column::Creator.eq(&current_user.user_id))
        .limit(1)
        .all(db)
        .await?;

    if let Some((sm, cm)) = pm.pop() {
        let cm = &cm[0];
        sync_one_subscribe_source_with_url(sm, &cm.user_agent, db).await?;
        Ok(())
    } else {
        Err(AppError::DbNotFound(format!(
            "cannot find subscribe source id = {}",
            id
        )))
    }
}
