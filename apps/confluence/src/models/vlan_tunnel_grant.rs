use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction};

use super::vlan_tunnel;
use crate::error::AppError;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_tunnel_grant")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub vlan_id: Uuid,
    pub tunnel_id: Uuid,
    pub supplicant_id: Uuid,
    #[sea_orm(belongs_to, from = "tunnel_id", to = "id", on_delete = "Cascade")]
    pub tunnel: HasOne<vlan_tunnel::Entity>,
}

impl Entity {
    pub(super) async fn insert_for_tunnel(
        tx: &DatabaseTransaction,
        tunnel: &vlan_tunnel::Model,
        supplicant_ids: &[String],
    ) -> Result<(), AppError> {
        if supplicant_ids.is_empty() {
            return Ok(());
        }
        let rows = supplicant_ids
            .iter()
            .map(|id| {
                Ok(ActiveModel {
                    creator: Set(tunnel.creator.clone()),
                    vlan_id: Set(tunnel.vlan_id),
                    tunnel_id: Set(tunnel.id),
                    supplicant_id: Set(id
                        .parse()
                        .map_err(|_| AppError::bad_request("Invalid supplicant ID"))?),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        Self::insert_many(rows)
            .exec(tx)
            .await
            .map_err(AppError::vlan_write)?;
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
