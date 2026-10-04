use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub confluence_id: Uuid,
    #[sea_orm(column_type = "Timestamp")]
    pub created_at: DateTime,
    #[sea_orm(column_type = "Timestamp")]
    pub updated_at: DateTime,
    #[sea_orm(unique)]
    pub resource_token: String,
    pub transform_script: Option<String>,
    pub transform_script_transpiled: Option<String>,
    pub allow_unsafe_age_private_key: bool,
    #[sea_orm(
        belongs_to,
        from = "confluence_id",
        to = "id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    pub confluence: HasOne<super::confluence::Entity>,
    #[sea_orm(has_many)]
    #[serde(skip)]
    pub recipient_links: HasMany<super::profile_supplicant::Entity>,
    #[sea_orm(has_many, via = "profile_supplicant")]
    #[serde(skip)]
    pub supplicants: HasMany<super::vlan_supplicant::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
