use crate::clash::ProxyServerNameserverPolicySource;
use crate::models;
use crate::traffic_reset::SubscribeSourceTrafficResetPolicy;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ProfileDto {
    pub id: i32,
    pub confluence_id: i32,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
    pub resource_token: String,
    #[ts(optional)]
    pub transform_script: Option<String>,
    #[ts(optional)]
    pub transform_script_transpiled: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SubscribeSourceDto {
    pub id: i32,
    pub url: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
    pub confluence_id: i32,
    pub name: String,
    pub content: String,
    #[ts(type = "number", optional)]
    pub sub_upload: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_download: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_total: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_expire: Option<i64>,
    pub passive_sync: Option<bool>,
    pub proxy_server: Option<String>,
    pub proxy_auth: Option<String>,
    pub proxy_server_nameserver_policy_source: ProxyServerNameserverPolicySource,
    pub traffic_reset_policy: SubscribeSourceTrafficResetPolicy,
    #[ts(type = "number", optional)]
    pub traffic_next_reset_at: Option<i64>,
}

impl From<models::subscribe_source::Model> for SubscribeSourceDto {
    fn from(value: models::subscribe_source::Model) -> Self {
        let traffic_reset_policy =
            SubscribeSourceTrafficResetPolicy::from(Some(value.traffic_reset_policy.as_str()));
        let sub_expire_at = value.sub_expire.map(|s| s.and_utc());
        let traffic_next_reset_at = value
            .traffic_next_reset_at
            .map(|s| s.and_utc())
            .or_else(|| traffic_reset_policy.next_reset_at(sub_expire_at));
        Self {
            id: value.id,
            url: value.url,
            confluence_id: value.confluence_id,
            created_at: value.created_at.and_utc().timestamp_millis(),
            updated_at: value.updated_at.and_utc().timestamp_millis(),
            name: value.name,
            content: value.content,
            sub_download: value.sub_download,
            sub_expire: sub_expire_at.map(|s| s.timestamp_millis()),
            sub_total: value.sub_total,
            sub_upload: value.sub_upload,
            passive_sync: value.passive_sync,
            proxy_auth: value.proxy_auth,
            proxy_server: value.proxy_server,
            proxy_server_nameserver_policy_source: value
                .proxy_server_nameserver_policy_source
                .as_deref()
                .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
                .unwrap_or_default(),
            traffic_reset_policy,
            traffic_next_reset_at: traffic_next_reset_at.map(|s| s.timestamp_millis()),
        }
    }
}

impl From<models::profile::Model> for ProfileDto {
    fn from(value: models::profile::Model) -> Self {
        Self {
            id: value.id,
            confluence_id: value.confluence_id,
            created_at: value.created_at.and_utc().timestamp_millis(),
            updated_at: value.updated_at.and_utc().timestamp_millis(),
            resource_token: value.resource_token,
            transform_script: value.transform_script,
            transform_script_transpiled: value.transform_script_transpiled,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ConfluenceDto {
    pub id: i32,
    pub template: String,
    pub creator: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
    pub mux_content: String,
    pub subscribe_sources: Vec<SubscribeSourceDto>,
    pub profiles: Vec<ProfileDto>,
    pub name: String,
    #[ts(type = "number", optional)]
    pub sub_upload: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_download: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_total: Option<i64>,
    #[ts(type = "number", optional)]
    pub sub_expire: Option<i64>,
    #[ts(optional)]
    pub cron_expr: Option<String>,
    #[ts(optional)]
    pub cron_expr_tz: Option<String>,
    #[ts(type = "number", optional)]
    pub cron_prev_at: Option<i64>,
    #[ts(optional)]
    pub cron_err: Option<String>,
    #[ts(type = "number", optional)]
    pub cron_next_at: Option<i64>,
    pub user_agent: String,
}

impl ConfluenceDto {
    pub fn from_orm(
        confluence: models::confluence::Model,
        sms: Vec<models::subscribe_source::Model>,
        pms: Vec<models::profile::Model>,
    ) -> Self {
        Self {
            id: confluence.id,
            template: confluence.template,
            created_at: confluence.created_at.and_utc().timestamp_millis(),
            updated_at: confluence.updated_at.and_utc().timestamp_millis(),
            creator: confluence.creator,
            mux_content: confluence.mux_content,
            subscribe_sources: sms.into_iter().map(|s| s.into()).collect(),
            profiles: pms.into_iter().map(|s| s.into()).collect(),
            name: confluence.name,
            sub_download: confluence.sub_download,
            sub_expire: confluence
                .sub_expire
                .map(|s| s.and_utc().timestamp_millis()),
            sub_total: confluence.sub_total,
            sub_upload: confluence.sub_upload,
            cron_expr: confluence.cron_expr,
            cron_expr_tz: confluence.cron_expr_tz,
            cron_prev_at: confluence
                .cron_prev_at
                .map(|s| s.and_utc().timestamp_millis()),
            cron_err: confluence.cron_err,
            cron_next_at: confluence
                .cron_next_at
                .map(|s| s.and_utc().timestamp_millis()),
            user_agent: confluence.user_agent,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ProfileCreationDto {
    pub confluence_id: i32,
    #[ts(optional)]
    pub transform_script: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ProfileUpdateDto {
    #[ts(optional)]
    pub transform_script: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SubscribeSourceCreationDto {
    pub confluence_id: i32,
    pub url: String,
    pub name: String,
    pub passive_sync: Option<bool>,
    pub proxy_server: Option<String>,
    pub proxy_auth: Option<String>,
    pub proxy_server_nameserver_policy_source: Option<ProxyServerNameserverPolicySource>,
    pub traffic_reset_policy: Option<SubscribeSourceTrafficResetPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SubscribeSourceUpdateDto {
    pub url: Option<String>,
    pub name: Option<String>,
    pub content: Option<String>,
    pub passive_sync: Option<bool>,
    pub proxy_server: Option<String>,
    pub proxy_auth: Option<String>,
    pub proxy_server_nameserver_policy_source: Option<ProxyServerNameserverPolicySource>,
    pub traffic_reset_policy: Option<SubscribeSourceTrafficResetPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ConfluenceUpdateDto {
    #[ts(optional)]
    pub template: Option<String>,
    #[ts(optional)]
    pub user_agent: Option<String>,
    #[ts(optional)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ConfluenceUpdateCronDto {
    pub cron_expr: String,
    pub cron_expr_tz: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime as ChronoDateTime, TimeZone, Utc};
    use sea_orm::prelude::DateTime;

    fn subscribe_source_model_with_policy(
        policy: &str,
        expire_at: Option<ChronoDateTime<Utc>>,
        cached_next_reset_at: Option<ChronoDateTime<Utc>>,
    ) -> models::subscribe_source::Model {
        models::subscribe_source::Model {
            id: 1,
            url: "https://example.com/sub".to_string(),
            created_at: DateTime::default(),
            updated_at: DateTime::default(),
            confluence_id: 1,
            name: "example".to_string(),
            content: String::new(),
            sub_upload: None,
            sub_download: None,
            sub_total: None,
            sub_expire: expire_at.map(|dt| dt.naive_utc()),
            passive_sync: None,
            proxy_server: None,
            proxy_auth: None,
            proxy_server_nameserver_policy_source: None,
            traffic_reset_policy: policy.to_string(),
            traffic_next_reset_at: cached_next_reset_at.map(|dt| dt.naive_utc()),
        }
    }

    #[test]
    fn subscribe_source_dto_default_policy_has_next_reset_at_when_expire_exists() {
        let expire_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).single().unwrap();
        let dto = SubscribeSourceDto::from(subscribe_source_model_with_policy(
            "default",
            Some(expire_at),
            None,
        ));

        assert_eq!(
            dto.traffic_reset_policy,
            SubscribeSourceTrafficResetPolicy::Default
        );
        assert!(dto.traffic_next_reset_at.is_some());
    }

    #[test]
    fn subscribe_source_dto_empty_policy_falls_back_to_default_next_reset_at() {
        let expire_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).single().unwrap();
        let dto = SubscribeSourceDto::from(subscribe_source_model_with_policy(
            "",
            Some(expire_at),
            None,
        ));

        assert_eq!(
            dto.traffic_reset_policy,
            SubscribeSourceTrafficResetPolicy::Default
        );
        assert!(dto.traffic_next_reset_at.is_some());
    }

    #[test]
    fn subscribe_source_dto_one_time_policy_has_no_next_reset_at() {
        let expire_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).single().unwrap();
        let dto = SubscribeSourceDto::from(subscribe_source_model_with_policy(
            "one_time",
            Some(expire_at),
            None,
        ));

        assert_eq!(
            dto.traffic_reset_policy,
            SubscribeSourceTrafficResetPolicy::OneTime
        );
        assert_eq!(dto.traffic_next_reset_at, None);
    }

    #[test]
    fn subscribe_source_dto_default_policy_without_expire_has_no_next_reset_at() {
        let dto =
            SubscribeSourceDto::from(subscribe_source_model_with_policy("default", None, None));

        assert_eq!(
            dto.traffic_reset_policy,
            SubscribeSourceTrafficResetPolicy::Default
        );
        assert_eq!(dto.traffic_next_reset_at, None);
    }

    #[test]
    fn monthly_next_reset_is_back_calculated_from_expire() {
        let now = Utc
            .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
            .single()
            .unwrap();
        let expire_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).single().unwrap();

        let next_reset = SubscribeSourceTrafficResetPolicy::Monthly
            .next_reset_at_after(Some(expire_at), now)
            .unwrap();

        assert_eq!(
            next_reset,
            Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 0).single().unwrap()
        );
    }

    #[test]
    fn subscribe_source_dto_prefers_cached_next_reset_at() {
        let expire_at = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).single().unwrap();
        let cached_next_reset_at = Utc.with_ymd_and_hms(2026, 6, 15, 0, 0, 0).single().unwrap();

        let dto = SubscribeSourceDto::from(subscribe_source_model_with_policy(
            "monthly",
            Some(expire_at),
            Some(cached_next_reset_at),
        ));

        assert_eq!(
            dto.traffic_next_reset_at,
            Some(cached_next_reset_at.timestamp_millis())
        );
    }

    #[test]
    fn quarterly_next_reset_is_back_calculated_from_expire() {
        let now = Utc
            .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
            .single()
            .unwrap();
        let expire_at = Utc.with_ymd_and_hms(2027, 2, 15, 0, 0, 0).single().unwrap();

        let next_reset = SubscribeSourceTrafficResetPolicy::Quarterly
            .next_reset_at_after(Some(expire_at), now)
            .unwrap();

        assert_eq!(
            next_reset,
            Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 0).single().unwrap()
        );
    }

    #[test]
    fn yearly_next_reset_uses_calendar_years_not_fixed_days() {
        let now = Utc
            .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
            .single()
            .unwrap();
        let expire_at = Utc.with_ymd_and_hms(2028, 2, 29, 0, 0, 0).single().unwrap();

        let next_reset = SubscribeSourceTrafficResetPolicy::Yearly
            .next_reset_at_after(Some(expire_at), now)
            .unwrap();

        assert_eq!(
            next_reset,
            Utc.with_ymd_and_hms(2027, 2, 28, 0, 0, 0).single().unwrap()
        );
    }
}
