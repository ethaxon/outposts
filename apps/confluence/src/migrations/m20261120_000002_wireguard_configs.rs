use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::prelude::*;

use super::defs::{VlanColumn as Col, VlanTable as Vlan};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let tx = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&tx);
        // SeaQuery does not expose LOCK TABLE. Keep the grants and peers consistent during the move.
        tx.execute_unprepared(
            "LOCK TABLE vlan_tunnel_grant, vlan_tunnel, vlan_wireguard_peer IN ACCESS EXCLUSIVE MODE",
        )
        .await?;
        schema
            .create_index(
                Index::create()
                    .name("vlan_tunnel_id_kind_key")
                    .table(Vlan::Tunnel)
                    .unique()
                    .col(Col::Id)
                    .col(Col::Kind)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::WireguardConfig)
                    .col(
                        ColumnDef::new(Col::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("uuidv7")))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Col::TunnelId).uuid().not_null())
                    .col(
                        ColumnDef::new(Col::Kind)
                            .text()
                            .generated(Expr::val("wireguard-compatible"), true),
                    )
                    .col(
                        ColumnDef::new(Col::Addresses)
                            .array(ColumnType::Text)
                            .not_null()
                            .check(
                                Expr::from(
                                    Func::cust(Alias::new("cardinality"))
                                        .arg(Expr::col(Col::Addresses)),
                                )
                                .gt(0),
                            ),
                    )
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
                            .name("vlan_wireguard_config_tunnel_id_id_key")
                            .unique()
                            .col(Col::TunnelId)
                            .col(Col::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_wireguard_config_tunnel_id_kind_fkey")
                            .from(Vlan::WireguardConfig, (Col::TunnelId, Col::Kind))
                            .to(Vlan::Tunnel, (Col::Id, Col::Kind))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let config_columns = [
            Col::Id,
            Col::TunnelId,
            Col::Addresses,
            Col::Mtu,
            Col::PersistentKeepalive,
            Col::PrivateKey,
        ];
        tx.execute(
            Query::insert()
                .into_table(Vlan::WireguardConfig)
                .columns(config_columns)
                .select_from(
                    Query::select()
                        .columns(config_columns)
                        .from(Vlan::TunnelGrant)
                        .and_where(Expr::col(Col::Kind).eq("wireguard-compatible"))
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?,
        )
        .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::WireguardPeer)
                    .drop_column(Col::Kind)
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::WireguardPeer)
                    .rename_column(Col::GrantId, Col::ConfigId)
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::WireguardPeer)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("vlan_wireguard_peer_config_id_fkey")
                            .from_tbl(Vlan::WireguardPeer)
                            .from_col(Col::ConfigId)
                            .to_tbl(Vlan::WireguardConfig)
                            .to_col(Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::TunnelGrant)
                    .add_column(ColumnDef::new(Col::ConfigId).uuid())
                    .to_owned(),
            )
            .await?;
        tx.execute(
            Query::update()
                .table(Vlan::TunnelGrant)
                .value(Col::ConfigId, Expr::col(Col::Id))
                .and_where(Expr::col(Col::Kind).eq("wireguard-compatible")),
        )
        .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::TunnelGrant)
                    .drop_column(Col::Addresses)
                    .drop_column(Col::Mtu)
                    .drop_column(Col::PersistentKeepalive)
                    .drop_column(Col::PrivateKey)
                    .drop_constraint("vlan_tunnel_grant_id_kind_key")
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("vlan_tunnel_grant_tunnel_id_config_id_fkey")
                            .from_tbl(Vlan::TunnelGrant)
                            .from_col(Col::TunnelId)
                            .from_col(Col::ConfigId)
                            .to_tbl(Vlan::WireguardConfig)
                            .to_col(Col::TunnelId)
                            .to_col(Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .table(Vlan::TunnelGrant)
                    .name("vlan_tunnel_grant_config_id_key")
                    .col(Col::ConfigId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        // SeaQuery supports checks when creating a table or column, but not ADD CHECK on an existing table.
        tx.execute_unprepared(
            "ALTER TABLE vlan_tunnel_grant ADD CHECK (
                (kind = 'easytier-gateway' AND slots IS NOT NULL AND config_id IS NULL)
                OR (kind = 'wireguard-compatible' AND slots IS NULL AND config_id IS NOT NULL)
            )",
        )
        .await?;
        tx.commit().await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Restore the pre-migration backup to return to grant-owned WireGuard configuration"
                .into(),
        ))
    }
}
