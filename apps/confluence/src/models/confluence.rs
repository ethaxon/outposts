use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "confluence")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
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
}

impl Model {
    pub fn user_agent_or_default(&self) -> &str {
        if self.user_agent.is_empty() {
            "clash-verge/v2.0.3"
        } else {
            &self.user_agent
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::profile::Entity")]
    Profile,
    #[sea_orm(has_many = "super::subscribe_source::Entity")]
    SubscribeSource,
}

impl Related<super::profile::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Profile.def()
    }
}

impl Related<super::subscribe_source::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SubscribeSource.def()
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
            id: 1,
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
