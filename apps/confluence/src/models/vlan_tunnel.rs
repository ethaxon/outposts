use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction, LoaderTrait, QueryOrder};

use super::{vlan_network, vlan_tunnel_grant, vlan_wireguard_peer};
use crate::error::AppError;
use crate::vlan::{VlanTunnel, WireGuardClientConfig};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_tunnel")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub vlan_id: Uuid,
    pub name: String,
    pub addresses: Vec<String>,
    pub mtu: Option<i32>,
    pub persistent_keepalive: Option<i32>,
    pub private_key: String,
    #[sea_orm(
        belongs_to,
        from = "(creator, vlan_id)",
        to = "(creator, id)",
        on_delete = "Cascade"
    )]
    pub network: HasOne<vlan_network::Entity>,
    #[sea_orm(has_many)]
    pub grants: HasMany<vlan_tunnel_grant::Entity>,
    #[sea_orm(has_many)]
    pub peers: HasMany<vlan_wireguard_peer::Entity>,
}

impl Entity {
    pub(super) async fn load_for_networks<C: ConnectionTrait>(
        db: &C,
        networks: &[vlan_network::Model],
    ) -> Result<Vec<Vec<VlanTunnel>>, AppError> {
        let batches = networks
            .load_many(Self::find().order_by_asc(Column::Id), db)
            .await?;
        let rows: Vec<_> = batches.iter().flatten().cloned().collect();
        let (grants, peers) = tokio::try_join!(
            rows.load_many(
                vlan_tunnel_grant::Entity::find()
                    .order_by_asc(vlan_tunnel_grant::Column::SupplicantId),
                db,
            ),
            rows.load_many(
                vlan_wireguard_peer::Entity::find()
                    .order_by_asc(vlan_wireguard_peer::Column::Position),
                db,
            ),
        )?;
        let mut details = grants.into_iter().zip(peers);
        Ok(batches
            .into_iter()
            .map(|batch| {
                batch
                    .into_iter()
                    .zip(details.by_ref())
                    .map(|(row, (grants, peers))| VlanTunnel {
                        id: row.id.to_string(),
                        name: row.name,
                        config: WireGuardClientConfig {
                            addresses: row.addresses,
                            mtu: row.mtu.map(|value| value as u16),
                            persistent_keepalive: row
                                .persistent_keepalive
                                .map(|value| value as u16),
                            has_private_key: true,
                            private_key: Some(row.private_key),
                            peers: peers.into_iter().map(Into::into).collect(),
                        },
                        supplicant_ids: grants
                            .into_iter()
                            .map(|grant| grant.supplicant_id.to_string())
                            .collect(),
                    })
                    .collect()
            })
            .collect())
    }

    pub(super) async fn replace_for_vlan(
        tx: &DatabaseTransaction,
        creator: &str,
        id: Uuid,
        tunnels: &[VlanTunnel],
    ) -> Result<(), AppError> {
        Self::delete_many()
            .filter(Column::VlanId.eq(id))
            .exec(tx)
            .await?;
        for tunnel in tunnels {
            let config = &tunnel.config;
            let mut row = ActiveModel {
                creator: Set(creator.to_owned()),
                vlan_id: Set(id),
                name: Set(tunnel.name.clone()),
                addresses: Set(config.addresses.clone()),
                mtu: Set(config.mtu.map(i32::from)),
                persistent_keepalive: Set(config.persistent_keepalive.map(i32::from)),
                private_key: Set(config.private_key.clone().ok_or_else(|| {
                    AppError::internal_str("Missing validated WireGuard private key")
                })?),
                ..Default::default()
            };
            if !tunnel.id.is_empty() {
                row.id = Set(tunnel
                    .id
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid tunnel ID"))?);
            }
            let saved = row.insert(tx).await.map_err(AppError::vlan_write)?;
            vlan_wireguard_peer::Entity::insert_many(config.peers.iter().enumerate().map(
                |(index, peer)| {
                    vlan_wireguard_peer::ActiveModel::from_peer(saved.id, index as i32, peer)
                },
            ))
            .exec(tx)
            .await
            .map_err(AppError::vlan_write)?;
            vlan_tunnel_grant::Entity::insert_for_tunnel(tx, &saved, &tunnel.supplicant_ids)
                .await?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
