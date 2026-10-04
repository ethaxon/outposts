use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction, LoaderTrait, QueryOrder};

use super::{vlan_network, vlan_tunnel_grant, vlan_wireguard_config};
use crate::error::AppError;
use crate::vlan::{VlanTunnel, VlanTunnelSource};

const EASYTIER: &str = "easytier-gateway";
const WIREGUARD: &str = "wireguard-compatible";

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_tunnel")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub vlan_id: Uuid,
    pub name: String,
    pub kind: String,
    pub server: Option<String>,
    pub port: Option<i32>,
    #[sea_orm(column_type = "Cidr", nullable)]
    pub subnet: Option<IpNetwork>,
    pub private_key: Option<String>,
    pub allowed_ips: Vec<String>,
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
    pub wireguard_configs: HasMany<vlan_wireguard_config::Entity>,
}

impl Entity {
    pub(super) async fn load_for_networks<C: ConnectionTrait>(
        db: &C,
        networks: &[vlan_network::Model],
    ) -> Result<Vec<Vec<VlanTunnel>>, AppError> {
        let batches = networks
            .load_many(Self::find().order_by_asc(Column::Id), db)
            .await?;
        let tunnel_rows: Vec<_> = batches.iter().flatten().cloned().collect();
        let grants = tunnel_rows
            .load_many(
                vlan_tunnel_grant::Entity::find()
                    .order_by_asc(vlan_tunnel_grant::Column::SupplicantId),
                db,
            )
            .await?;
        let configs = vlan_wireguard_config::Entity::load_for_tunnels(db, &tunnel_rows).await?;
        let mut details = grants.into_iter().zip(configs);
        let mut output = Vec::with_capacity(batches.len());
        for batch in batches {
            let mut values = Vec::with_capacity(batch.len());
            for (row, (grants, configs)) in batch.into_iter().zip(details.by_ref()) {
                let invalid = || AppError::internal_str("Invalid stored VLAN tunnel");
                let source = match row.kind.as_str() {
                    EASYTIER => VlanTunnelSource::EasytierGateway {
                        server: row.server.ok_or_else(invalid)?,
                        port: row.port.ok_or_else(invalid)? as u16,
                        subnet: row.subnet.ok_or_else(invalid)?.to_string(),
                        allowed_ips: row.allowed_ips,
                        has_private_key: row.private_key.is_some(),
                        private_key: row.private_key,
                        grants: grants
                            .into_iter()
                            .map(vlan_tunnel_grant::Model::into_easytier)
                            .collect::<Result<_, _>>()?,
                    },
                    WIREGUARD => VlanTunnelSource::WireguardCompatible {
                        configs,
                        grants: grants
                            .into_iter()
                            .map(vlan_tunnel_grant::Model::into_wireguard)
                            .collect::<Result<_, _>>()?,
                    },
                    _ => return Err(invalid()),
                };
                values.push(VlanTunnel {
                    id: row.id.to_string(),
                    name: row.name,
                    source,
                });
            }
            output.push(values);
        }
        Ok(output)
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
            let mut row = ActiveModel {
                creator: Set(creator.to_owned()),
                vlan_id: Set(id),
                name: Set(tunnel.name.clone()),
                allowed_ips: Set(Vec::new()),
                ..Default::default()
            };
            if !tunnel.id.is_empty() {
                row.id = Set(tunnel
                    .id
                    .parse()
                    .map_err(|_| AppError::bad_request("Invalid tunnel ID"))?);
            }
            match &tunnel.source {
                VlanTunnelSource::EasytierGateway {
                    server,
                    port,
                    subnet,
                    private_key,
                    allowed_ips,
                    ..
                } => {
                    row.kind = Set(EASYTIER.into());
                    row.server = Set(Some(server.clone()));
                    row.port = Set(Some(i32::from(*port)));
                    row.subnet =
                        Set(Some(subnet.parse().map_err(|_| {
                            AppError::bad_request("Invalid Portal subnet")
                        })?));
                    row.private_key = Set(private_key.clone());
                    row.allowed_ips = Set(allowed_ips.clone());
                }
                VlanTunnelSource::WireguardCompatible { .. } => row.kind = Set(WIREGUARD.into()),
            }
            let saved = row.insert(tx).await.map_err(AppError::vlan_write)?;
            if let VlanTunnelSource::WireguardCompatible { configs, .. } = &tunnel.source {
                vlan_wireguard_config::Entity::insert_for_tunnel(tx, saved.id, configs).await?;
            }
            vlan_tunnel_grant::Entity::insert_for_tunnel(tx, &saved, &tunnel.source).await?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
