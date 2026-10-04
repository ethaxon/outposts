use crate::traffic_reset::SubscribeSourceTrafficResetPolicy;
use sea_orm::entity::prelude::*;
use sea_orm::{
    ActiveValue, ConnectionTrait, DbErr, FromJsonQueryResult, QueryOrder, Select, Value,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SubscribeSourceSyncErrorKind {
    Request,
    HttpStatus,
    ReadBody,
    InvalidYaml,
    MissingProxies,
    InvalidConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, FromJsonQueryResult, TS)]
#[ts(export)]
pub struct SubscribeSourceSyncError {
    pub kind: SubscribeSourceSyncErrorKind,
    pub message: String,
    #[ts(type = "number")]
    pub occurred_at: i64,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_truncated: bool,
}

#[sea_orm::model]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "subscribe_source")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    #[sea_orm(column_type = "Timestamp")]
    pub created_at: DateTime,
    #[sea_orm(column_type = "Timestamp")]
    pub updated_at: DateTime,
    pub confluence_id: Uuid,
    pub name: String,
    pub content: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub last_sync_error: Option<SubscribeSourceSyncError>,
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
    #[sea_orm(
        belongs_to,
        from = "confluence_id",
        to = "id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    pub confluence: HasOne<super::confluence::Entity>,
}

impl Entity {
    pub(crate) fn in_creation_order() -> Select<Self> {
        Self::find()
            .order_by_asc(Column::CreatedAt)
            .order_by_asc(Column::Id)
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
