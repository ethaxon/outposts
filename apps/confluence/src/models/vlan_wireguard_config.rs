use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction, LoaderTrait, QueryOrder};

use super::{vlan_tunnel, vlan_wireguard_peer};
use crate::error::AppError;
use crate::vlan::WireGuardClientConfig;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_wireguard_config")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub tunnel_id: Uuid,
    pub addresses: Vec<String>,
    pub mtu: Option<i32>,
    pub persistent_keepalive: Option<i32>,
    pub private_key: String,
    #[sea_orm(belongs_to, from = "tunnel_id", to = "id", on_delete = "Cascade")]
    pub tunnel: HasOne<vlan_tunnel::Entity>,
    #[sea_orm(has_many)]
    pub peers: HasMany<vlan_wireguard_peer::Entity>,
}

impl Entity {
    pub(super) async fn load_for_tunnels<C: ConnectionTrait>(
        db: &C,
        tunnels: &[vlan_tunnel::Model],
    ) -> Result<Vec<Vec<WireGuardClientConfig>>, AppError> {
        let batches = tunnels
            .load_many(Self::find().order_by_asc(Column::Id), db)
            .await?;
        let rows: Vec<_> = batches.iter().flatten().cloned().collect();
        let peers = rows
            .load_many(
                vlan_wireguard_peer::Entity::find()
                    .order_by_asc(vlan_wireguard_peer::Column::Position),
                db,
            )
            .await?;
        let mut peers = peers.into_iter();
        Ok(batches
            .into_iter()
            .map(|batch| {
                batch
                    .into_iter()
                    .zip(peers.by_ref())
                    .map(|(row, peers)| WireGuardClientConfig {
                        id: row.id,
                        addresses: row.addresses,
                        mtu: row.mtu.map(|value| value as u16),
                        persistent_keepalive: row.persistent_keepalive.map(|value| value as u16),
                        has_private_key: true,
                        private_key: Some(row.private_key),
                        peers: peers.into_iter().map(Into::into).collect(),
                    })
                    .collect()
            })
            .collect())
    }

    pub(super) async fn insert_for_tunnel(
        tx: &DatabaseTransaction,
        tunnel_id: Uuid,
        configs: &[WireGuardClientConfig],
    ) -> Result<(), AppError> {
        for config in configs {
            let row = ActiveModel {
                id: Set(config.id),
                tunnel_id: Set(tunnel_id),
                addresses: Set(config.addresses.clone()),
                mtu: Set(config.mtu.map(i32::from)),
                persistent_keepalive: Set(config.persistent_keepalive.map(i32::from)),
                private_key: Set(config.private_key.clone().ok_or_else(|| {
                    AppError::internal_str("Missing validated WireGuard private key")
                })?),
            };
            row.insert(tx).await.map_err(AppError::vlan_write)?;
            vlan_wireguard_peer::Entity::insert_many(config.peers.iter().enumerate().map(
                |(i, peer)| vlan_wireguard_peer::ActiveModel::from_peer(config.id, i as i32, peer),
            ))
            .exec(tx)
            .await
            .map_err(AppError::vlan_write)?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
