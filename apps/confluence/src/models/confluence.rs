use sea_orm::LoaderTrait;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use super::{confluence_vlan, vlan_network};
use crate::error::AppError;
use crate::vlan::VlanNetwork;

#[sea_orm::model]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "confluence")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub template: String,
    pub creator: String,
    #[sea_orm(column_type = "Timestamp")]
    pub created_at: DateTime,
    #[sea_orm(column_type = "Timestamp")]
    pub updated_at: DateTime,
    #[sea_orm(column_type = "Text")]
    pub mux_content: String,
    pub sub_upload: Option<i64>,
    pub sub_download: Option<i64>,
    pub sub_total: Option<i64>,
    pub sub_expire: Option<DateTime>,
    pub cron_expr: Option<String>,
    pub cron_expr_tz: Option<String>,
    #[sea_orm(column_type = "Timestamp")]
    pub cron_prev_at: Option<DateTime>,
    #[sea_orm(column_type = "Text")]
    pub cron_err: Option<String>,
    #[sea_orm(column_type = "Timestamp")]
    pub cron_next_at: Option<DateTime>,
    #[sea_orm(column_type = "Text")]
    pub user_agent: String,
    #[sea_orm(has_many)]
    pub profiles: HasMany<super::profile::Entity>,
    #[sea_orm(has_many)]
    #[serde(skip)]
    pub vlan_links: HasMany<super::confluence_vlan::Entity>,
    #[sea_orm(has_many, via = "confluence_vlan")]
    #[serde(skip)]
    pub vlan_networks: HasMany<super::vlan_network::Entity>,
    #[sea_orm(has_many)]
    pub subscribe_sources: HasMany<super::subscribe_source::Entity>,
}

impl Model {
    pub fn user_agent_or_default(&self) -> &str {
        if self.user_agent.is_empty() {
            "clash-verge/v2.0.3"
        } else {
            &self.user_agent
        }
    }

    pub(crate) async fn load_vlan_subscription(
        &self,
        db: &impl ConnectionTrait,
    ) -> Result<Vec<VlanNetwork>, AppError> {
        let networks = std::slice::from_ref(self)
            .load_many_to_many(
                vlan_network::Entity::find()
                    .filter(vlan_network::Column::Creator.eq(&self.creator)),
                confluence_vlan::Entity,
                db,
            )
            .await?
            .pop()
            .unwrap_or_default();
        vlan_network::Entity::load_details(db, networks).await
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::Model;
    use chrono::NaiveDate;

    fn sample_model(user_agent: &str) -> Model {
        let now = NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("date should be valid")
            .and_hms_opt(0, 0, 0)
            .expect("time should be valid");

        Model {
            id: uuid::Uuid::from_u128(1),
            name: "demo".to_string(),
            template: String::new(),
            creator: "user-1".to_string(),
            created_at: now,
            updated_at: now,
            mux_content: String::new(),
            sub_upload: None,
            sub_download: None,
            sub_total: None,
            sub_expire: None,
            cron_expr: None,
            cron_expr_tz: None,
            cron_prev_at: None,
            cron_err: None,
            cron_next_at: None,
            user_agent: user_agent.to_string(),
        }
    }

    #[test]
    fn user_agent_or_default_returns_default_when_empty() {
        let model = sample_model("");

        assert_eq!(model.user_agent_or_default(), "clash-verge/v2.0.3");
    }

    #[test]
    fn user_agent_or_default_returns_explicit_value() {
        let model = sample_model("custom-agent/1.0");

        assert_eq!(model.user_agent_or_default(), "custom-agent/1.0");
    }
}
