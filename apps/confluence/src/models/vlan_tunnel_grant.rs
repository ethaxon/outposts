use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction, LoaderTrait, QueryOrder};

use super::{vlan_tunnel, vlan_wireguard_peer};
use crate::error::AppError;
use crate::vlan::{EasyTierTunnelGrant, VlanTunnelSource, WireGuardTunnelGrant};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_tunnel_grant")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub vlan_id: Uuid,
    pub tunnel_id: Uuid,
    pub kind: String,
    pub supplicant_id: Uuid,
    pub slots: Option<String>,
    pub addresses: Vec<String>,
    pub mtu: Option<i32>,
    pub persistent_keepalive: Option<i32>,
    pub private_key: Option<String>,
    #[sea_orm(belongs_to, from = "tunnel_id", to = "id", on_delete = "Cascade")]
    pub tunnel: HasOne<vlan_tunnel::Entity>,
    #[sea_orm(has_many)]
    pub peers: HasMany<vlan_wireguard_peer::Entity>,
}

impl Model {
    pub(super) fn into_easytier(self) -> Result<EasyTierTunnelGrant, AppError> {
        Ok(EasyTierTunnelGrant {
            supplicant_id: self.supplicant_id.to_string(),
            slots: self
                .slots
                .ok_or_else(|| AppError::internal_str("Missing EasyTier slot grant"))?,
        })
    }
}

impl Entity {
    pub(super) async fn load_wireguard<C: ConnectionTrait>(
        db: &C,
        grants: Vec<Model>,
    ) -> Result<Vec<WireGuardTunnelGrant>, AppError> {
        let peers = grants
            .load_many(
                vlan_wireguard_peer::Entity::find()
                    .order_by_asc(vlan_wireguard_peer::Column::Position),
                db,
            )
            .await?;
        Ok(grants
            .into_iter()
            .zip(peers)
            .map(|(grant, peers)| WireGuardTunnelGrant {
                supplicant_id: grant.supplicant_id.to_string(),
                addresses: grant.addresses,
                mtu: grant.mtu.map(|mtu| mtu as u16),
                persistent_keepalive: grant.persistent_keepalive.map(|seconds| seconds as u16),
                has_private_key: grant.private_key.is_some(),
                private_key: grant.private_key,
                peers: peers.into_iter().map(Into::into).collect(),
            })
            .collect())
    }

    pub(super) async fn insert_for_tunnel(
        tx: &DatabaseTransaction,
        tunnel: &vlan_tunnel::Model,
        source: &VlanTunnelSource,
    ) -> Result<(), AppError> {
        let active = |supplicant: &str| -> Result<ActiveModel, AppError> {
            Ok(ActiveModel {
                creator: Set(tunnel.creator.clone()),
                vlan_id: Set(tunnel.vlan_id),
                tunnel_id: Set(tunnel.id),
                kind: Set(tunnel.kind.clone()),
                supplicant_id: Set(supplicant
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid supplicant ID"))?),
                addresses: Set(Vec::new()),
                ..Default::default()
            })
        };
        match source {
            VlanTunnelSource::EasytierGateway { grants, .. } => {
                let rows = grants
                    .iter()
                    .map(|grant| {
                        let mut row = active(&grant.supplicant_id)?;
                        row.slots = Set(Some(grant.slots.clone()));
                        Ok(row)
                    })
                    .collect::<Result<Vec<_>, AppError>>()?;
                if !rows.is_empty() {
                    Self::insert_many(rows)
                        .exec(tx)
                        .await
                        .map_err(AppError::vlan_write)?;
                }
            }
            VlanTunnelSource::WireguardCompatible { grants } => {
                for grant in grants {
                    let mut row = active(&grant.supplicant_id)?;
                    row.addresses = Set(grant.addresses.clone());
                    row.mtu = Set(grant.mtu.map(i32::from));
                    row.persistent_keepalive = Set(grant.persistent_keepalive.map(i32::from));
                    row.private_key = Set(grant.private_key.clone());
                    let saved = row.insert(tx).await.map_err(AppError::vlan_write)?;
                    vlan_wireguard_peer::Entity::insert_many(grant.peers.iter().enumerate().map(
                        |(i, peer)| {
                            vlan_wireguard_peer::ActiveModel::from_peer(saved.id, i as i32, peer)
                        },
                    ))
                    .exec(tx)
                    .await
                    .map_err(AppError::vlan_write)?;
                }
            }
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
