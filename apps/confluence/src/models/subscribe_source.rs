use sea_orm::entity::prelude::*;
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

impl ActiveModelBehavior for ActiveModel {}
