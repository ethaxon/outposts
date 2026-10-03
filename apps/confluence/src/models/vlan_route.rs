use std::collections::BTreeSet;

use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction};

use crate::error::AppError;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_route")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub vlan_id: Uuid,
    #[sea_orm(column_type = "Cidr")]
    pub cidr: IpNetwork,
    #[sea_orm(belongs_to, from = "vlan_id", to = "id", on_delete = "Cascade")]
    pub network: HasOne<super::vlan_network::Entity>,
}

impl Entity {
    pub(super) async fn replace_for_vlan(
        tx: &DatabaseTransaction,
        id: Uuid,
        routes: &[String],
    ) -> Result<(), AppError> {
        Self::delete_many()
            .filter(Column::VlanId.eq(id))
            .exec(tx)
            .await?;
        let routes = routes
            .iter()
            .map(|route| {
                route
                    .parse::<IpNetwork>()
                    .map(|route| format!("{}/{}", route.network(), route.prefix()))
                    .map_err(|_| AppError::bad_request("Invalid VLAN route CIDR"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        for route in routes {
            ActiveModel {
                vlan_id: Set(id),
                cidr: Set(route
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid VLAN route CIDR"))?),
                ..Default::default()
            }
            .insert(tx)
            .await
            .map_err(AppError::vlan_write)?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
