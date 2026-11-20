use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

use crate::vlan::WireGuardPeer;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_wireguard_peer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub grant_id: Uuid,
    pub position: i32,
    pub server: String,
    pub port: i32,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[sea_orm(belongs_to, from = "grant_id", to = "id", on_delete = "Cascade")]
    pub grant: HasOne<super::vlan_tunnel_grant::Entity>,
}

impl From<Model> for WireGuardPeer {
    fn from(row: Model) -> Self {
        Self {
            server: row.server,
            port: row.port as u16,
            public_key: row.public_key,
            has_pre_shared_key: row.pre_shared_key.is_some(),
            pre_shared_key: row.pre_shared_key,
            allowed_ips: row.allowed_ips,
        }
    }
}

impl ActiveModel {
    pub(super) fn from_peer(grant_id: Uuid, position: i32, peer: &WireGuardPeer) -> Self {
        Self {
            grant_id: Set(grant_id),
            position: Set(position),
            server: Set(peer.server.clone()),
            port: Set(i32::from(peer.port)),
            public_key: Set(peer.public_key.clone()),
            pre_shared_key: Set(peer.pre_shared_key.clone()),
            allowed_ips: Set(peer.allowed_ips.clone()),
            ..Default::default()
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
