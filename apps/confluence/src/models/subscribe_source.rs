use crate::traffic_reset::SubscribeSourceTrafficResetPolicy;
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue, ConnectionTrait, DbErr, Value};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "subscribe_source")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    #[sea_orm(column_type = "Timestamp")]
    pub created_at: DateTime,
    #[sea_orm(column_type = "Timestamp")]
    pub updated_at: DateTime,
    pub confluence_id: i32,
    pub name: String,
    pub content: String,
    pub sub_upload: Option<i64>,
    pub sub_download: Option<i64>,
    pub sub_total: Option<i64>,
    pub sub_expire: Option<DateTime>,
    // disable auto sync and sync all
    pub passive_sync: Option<bool>,
    pub proxy_server: Option<String>,
    pub proxy_auth: Option<String>,
    pub proxy_server_nameserver_policy_source: Option<String>,
    pub traffic_reset_policy: String,
    pub traffic_next_reset_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::confluence::Entity",
        from = "Column::ConfluenceId",
        to = "super::confluence::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Confluence,
}

impl Related<super::confluence::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Confluence.def()
    }
}

fn active_value_ref<T>(value: &ActiveValue<T>) -> Option<&T>
where
    T: Into<Value>,
{
    match value {
        ActiveValue::Set(value) | ActiveValue::Unchanged(value) => Some(value),
        ActiveValue::NotSet => None,
    }
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, _insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        let policy = SubscribeSourceTrafficResetPolicy::from(
            active_value_ref(&self.traffic_reset_policy).map(String::as_str),
        );
        let expire_at = active_value_ref(&self.sub_expire)
            .and_then(|expire_at| expire_at.map(|dt| dt.and_utc()));
        self.traffic_next_reset_at = ActiveValue::Set(
            policy
                .next_reset_at(expire_at)
                .map(|next_reset_at| next_reset_at.naive_utc()),
        );
        Ok(self)
    }
}
