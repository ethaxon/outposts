use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction};

use super::vlan_tunnel;
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
    pub config_id: Option<Uuid>,
    #[sea_orm(belongs_to, from = "tunnel_id", to = "id", on_delete = "Cascade")]
    pub tunnel: HasOne<vlan_tunnel::Entity>,
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

    pub(super) fn into_wireguard(self) -> Result<WireGuardTunnelGrant, AppError> {
        Ok(WireGuardTunnelGrant {
            supplicant_id: self.supplicant_id.to_string(),
            config_id: self
                .config_id
                .ok_or_else(|| AppError::internal_str("Missing WireGuard grant configuration"))?,
        })
    }
}

impl Entity {
    pub(super) async fn insert_for_tunnel(
        tx: &DatabaseTransaction,
        tunnel: &vlan_tunnel::Model,
        source: &VlanTunnelSource,
    ) -> Result<(), AppError> {
        let active = |supplicant: &str, slots, config_id| -> Result<ActiveModel, AppError> {
            Ok(ActiveModel {
                creator: Set(tunnel.creator.clone()),
                vlan_id: Set(tunnel.vlan_id),
                tunnel_id: Set(tunnel.id),
                kind: Set(tunnel.kind.clone()),
                supplicant_id: Set(supplicant
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid supplicant ID"))?),
                slots: Set(slots),
                config_id: Set(config_id),
                ..Default::default()
            })
        };
        let rows = match source {
            VlanTunnelSource::EasytierGateway { grants, .. } => grants
                .iter()
                .map(|grant| active(&grant.supplicant_id, Some(grant.slots.clone()), None))
                .collect::<Result<Vec<_>, _>>()?,
            VlanTunnelSource::WireguardCompatible { grants, .. } => grants
                .iter()
                .map(|grant| active(&grant.supplicant_id, None, Some(grant.config_id)))
                .collect::<Result<Vec<_>, _>>()?,
        };
        if !rows.is_empty() {
            Self::insert_many(rows)
                .exec(tx)
                .await
                .map_err(AppError::vlan_write)?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
