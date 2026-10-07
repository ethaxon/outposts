use std::collections::{BTreeMap, BTreeSet};

use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

use super::defs::{VlanColumn as Col, VlanTable as Vlan};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden, Clone, Copy)]
enum NextTable {
    #[sea_orm(iden = "vlan_tunnel_next")]
    Tunnel,
    #[sea_orm(iden = "vlan_tunnel_grant_next")]
    Grant,
    #[sea_orm(iden = "vlan_wireguard_peer_next")]
    Peer,
}

fn id_column() -> ColumnDef {
    ColumnDef::new(Col::Id)
        .uuid()
        .not_null()
        .default(Func::cust(Alias::new("uuidv7")))
        .primary_key()
        .take()
}

fn nonempty_array(column: Col) -> ColumnDef {
    ColumnDef::new(column)
        .array(ColumnType::Text)
        .not_null()
        .check(Expr::from(Func::cust(Alias::new("cardinality")).arg(Expr::col(column))).gt(0))
        .take()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let tx = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&tx);
        // SeaQuery does not expose LOCK TABLE. Hold configuration and authorization rows stable.
        tx.execute_unprepared(
            "LOCK TABLE vlan_network, vlan_grant, vlan_tunnel, vlan_tunnel_grant, vlan_wireguard_config, vlan_wireguard_peer IN ACCESS EXCLUSIVE MODE",
        )
        .await?;

        let tunnel = NextTable::Tunnel;
        let grant = NextTable::Grant;
        let peer = NextTable::Peer;
        schema
            .create_table(
                Table::create()
                    .table(tunnel)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::Name).text().not_null())
                    .col(nonempty_array(Col::Addresses))
                    .col(
                        ColumnDef::new(Col::Mtu)
                            .integer()
                            .check(Expr::col(Col::Mtu).between(1, 65535)),
                    )
                    .col(
                        ColumnDef::new(Col::PersistentKeepalive)
                            .integer()
                            .check(Expr::col(Col::PersistentKeepalive).between(0, 65535)),
                    )
                    .col(ColumnDef::new(Col::PrivateKey).text().not_null())
                    .index(
                        Index::create()
                            .unique()
                            .name("vlan_tunnel_vlan_name_unique")
                            .col(Col::VlanId)
                            .col(Col::Name),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .name("vlan_tunnel_owner_id_unique")
                            .col(Col::Creator)
                            .col(Col::VlanId)
                            .col(Col::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_network_fk")
                            .from(tunnel, (Col::Creator, Col::VlanId))
                            .to(Vlan::Network, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(grant)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::TunnelId).uuid().not_null())
                    .col(ColumnDef::new(Col::SupplicantId).uuid().not_null())
                    .index(
                        Index::create()
                            .unique()
                            .name("vlan_tunnel_grant_member_unique")
                            .col(Col::TunnelId)
                            .col(Col::SupplicantId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_grant_tunnel_fk")
                            .from(grant, (Col::Creator, Col::VlanId, Col::TunnelId))
                            .to(tunnel, (Col::Creator, Col::VlanId, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_grant_membership_fk")
                            .from(grant, (Col::Creator, Col::VlanId, Col::SupplicantId))
                            .to(Vlan::Grant, (Col::Creator, Col::VlanId, Col::SupplicantId))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .table(grant)
                    .name("vlan_tunnel_grant_member_idx")
                    .col(Col::Creator)
                    .col(Col::VlanId)
                    .col(Col::SupplicantId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(peer)
                    .col(id_column())
                    .col(ColumnDef::new(Col::TunnelId).uuid().not_null())
                    .col(ColumnDef::new(Col::Position).integer().not_null())
                    .col(ColumnDef::new(Col::Server).text().not_null())
                    .col(
                        ColumnDef::new(Col::Port)
                            .integer()
                            .not_null()
                            .check(Expr::col(Col::Port).between(1, 65535)),
                    )
                    .col(ColumnDef::new(Col::PublicKey).text().not_null())
                    .col(ColumnDef::new(Col::PreSharedKey).text())
                    .col(nonempty_array(Col::AllowedIps))
                    .index(
                        Index::create()
                            .unique()
                            .name("vlan_wireguard_peer_position_unique")
                            .col(Col::TunnelId)
                            .col(Col::Position),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .name("vlan_wireguard_peer_public_key_unique")
                            .col(Col::TunnelId)
                            .col(Col::PublicKey),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_wireguard_peer_tunnel_fk")
                            .from(peer, Col::TunnelId)
                            .to(tunnel, Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let config_id = Alias::new("config_id");
        let rows = tx
            .query_all(
                &Query::select()
                    .columns(
                        [Col::Id, Col::Creator, Col::VlanId, Col::Name]
                            .map(|col| (Vlan::Tunnel, col)),
                    )
                    .expr_as(Expr::col((Vlan::WireguardConfig, Col::Id)), config_id)
                    .columns(
                        [
                            Col::Addresses,
                            Col::Mtu,
                            Col::PersistentKeepalive,
                            Col::PrivateKey,
                        ]
                        .map(|col| (Vlan::WireguardConfig, col)),
                    )
                    .from(Vlan::Tunnel)
                    .inner_join(
                        Vlan::WireguardConfig,
                        Expr::col((Vlan::WireguardConfig, Col::TunnelId))
                            .equals((Vlan::Tunnel, Col::Id)),
                    )
                    .order_by((Vlan::Tunnel, Col::Id), Order::Asc)
                    .order_by((Vlan::WireguardConfig, Col::Id), Order::Asc)
                    .to_owned(),
            )
            .await?;
        let mut names = BTreeMap::<Uuid, BTreeSet<String>>::new();
        for row in &rows {
            names
                .entry(row.try_get("", "vlan_id")?)
                .or_default()
                .insert(row.try_get("", "name")?);
        }
        let mut seen = BTreeSet::new();
        for row in rows {
            let old_id: Uuid = row.try_get("", "id")?;
            let config_id: Uuid = row.try_get("", "config_id")?;
            let creator: String = row.try_get("", "creator")?;
            let vlan_id: Uuid = row.try_get("", "vlan_id")?;
            let original: String = row.try_get("", "name")?;
            let first = seen.insert(old_id);
            let name = if first {
                original
            } else {
                let reserved = names.entry(vlan_id).or_default();
                (2..)
                    .find_map(|index| {
                        let suffix = format!("-{index}");
                        let limit = original.floor_char_boundary(64 - suffix.len());
                        let candidate = format!("{}{suffix}", &original[..limit]);
                        reserved.insert(candidate.clone()).then_some(candidate)
                    })
                    .expect("finite VLAN tunnel names leave a free suffix")
            };
            let mut insert = Query::insert();
            insert.into_table(tunnel);
            let mut columns = vec![
                Col::Creator,
                Col::VlanId,
                Col::Name,
                Col::Addresses,
                Col::Mtu,
                Col::PersistentKeepalive,
                Col::PrivateKey,
            ];
            let mut values = vec![
                Expr::val(creator),
                Expr::val(vlan_id),
                Expr::val(name),
                Expr::val(row.try_get::<Vec<String>>("", "addresses")?),
                Expr::val(row.try_get::<Option<i32>>("", "mtu")?),
                Expr::val(row.try_get::<Option<i32>>("", "persistent_keepalive")?),
                Expr::val(row.try_get::<String>("", "private_key")?),
            ];
            if first {
                columns.push(Col::Id);
                values.push(Expr::val(old_id));
            }
            let new_id: Uuid = tx
                .query_one(
                    insert
                        .columns(columns)
                        .values_panic(values)
                        .returning_col(Col::Id),
                )
                .await?
                .ok_or_else(|| {
                    DbErr::Migration("WireGuard tunnel insert did not return an ID".into())
                })?
                .try_get("", "id")?;

            for (old_table, new_table, fields) in [
                (
                    Vlan::TunnelGrant,
                    grant,
                    &[Col::Id, Col::Creator, Col::VlanId, Col::SupplicantId][..],
                ),
                (
                    Vlan::WireguardPeer,
                    peer,
                    &[
                        Col::Id,
                        Col::Position,
                        Col::Server,
                        Col::Port,
                        Col::PublicKey,
                        Col::PreSharedKey,
                        Col::AllowedIps,
                    ][..],
                ),
            ] {
                let mut columns = fields.to_vec();
                columns.push(Col::TunnelId);
                tx.execute(
                    Query::insert()
                        .into_table(new_table)
                        .columns(columns)
                        .select_from(
                            Query::select()
                                .columns(fields.iter().copied())
                                .expr(Expr::val(new_id))
                                .from(old_table)
                                .and_where(Expr::col(Col::ConfigId).eq(config_id))
                                .to_owned(),
                        )
                        .map_err(|error| DbErr::Migration(error.to_string()))?,
                )
                .await?;
            }
        }

        for table in [
            Vlan::TunnelGrant,
            Vlan::WireguardPeer,
            Vlan::WireguardConfig,
            Vlan::Tunnel,
        ] {
            schema
                .drop_table(Table::drop().table(table).to_owned())
                .await?;
        }
        for (from, to) in [
            (tunnel, Vlan::Tunnel),
            (grant, Vlan::TunnelGrant),
            (peer, Vlan::WireguardPeer),
        ] {
            schema
                .rename_table(Table::rename().table(from, to).to_owned())
                .await?;
        }
        tx.commit().await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Restore the pre-migration backup to recover EasyTier Portal configuration".into(),
        ))
    }
}
