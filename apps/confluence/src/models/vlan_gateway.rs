use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction};

use crate::error::AppError;
use crate::vlan::VlanGateway;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_gateway")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub vlan_id: Uuid,
    pub name: String,
    pub server: String,
    pub port: i32,
    #[sea_orm(column_type = "Cidr")]
    pub subnet: IpNetwork,
    pub private_key: String,
    #[sea_orm(belongs_to, from = "vlan_id", to = "id", on_delete = "Cascade")]
    pub network: HasOne<super::vlan_network::Entity>,
}

impl From<Model> for VlanGateway {
    fn from(row: Model) -> Self {
        Self {
            name: row.name,
            server: row.server,
            port: row.port as u16,
            subnet: row.subnet.to_string(),
            private_key: Some(row.private_key),
            has_private_key: true,
        }
    }
}

impl Entity {
    pub(super) async fn replace_for_vlan(
        tx: &DatabaseTransaction,
        id: Uuid,
        gateways: &[VlanGateway],
    ) -> Result<(), AppError> {
        Self::delete_many()
            .filter(Column::VlanId.eq(id))
            .exec(tx)
            .await?;
        for gateway in gateways {
            ActiveModel {
                vlan_id: Set(id),
                name: Set(gateway.name.clone()),
                server: Set(gateway.server.clone()),
                port: Set(i32::from(gateway.port)),
                subnet: Set(gateway
                    .subnet
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid Portal subnet"))?),
                private_key: Set(gateway
                    .private_key
                    .clone()
                    .ok_or_else(|| AppError::bad_request("Missing Portal private key"))?),
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
