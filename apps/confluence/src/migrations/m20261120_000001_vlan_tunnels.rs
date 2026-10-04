use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::prelude::*;

use super::defs::{VlanColumn as Col, VlanTable as Vlan};

#[derive(DeriveMigrationName)]
pub struct Migration;

fn id_column() -> ColumnDef {
    ColumnDef::new(Col::Id)
        .uuid()
        .not_null()
        .default(Func::cust(Alias::new("uuidv7")))
        .primary_key()
        .take()
}

fn text_array(column: Col) -> ColumnDef {
    ColumnDef::new(column)
        .array(ColumnType::Text)
        .not_null()
        .take()
}

fn cardinality(column: Col) -> Expr {
    Func::cust(Alias::new("cardinality"))
        .arg(Expr::col(column))
        .into()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let tx = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&tx);
        // SeaQuery does not expose LOCK TABLE. Hold the source rows stable throughout the copy.
        tx.execute_unprepared(
            "LOCK TABLE vlan_network, vlan_gateway, vlan_grant, vlan_route IN ACCESS EXCLUSIVE MODE",
        )
        .await?;
        schema
            .create_index(
                Index::create()
                    .table(Vlan::Grant)
                    .name("vlan_grant_creator_vlan_id_supplicant_id_key")
                    .unique()
                    .col(Col::Creator)
                    .col(Col::VlanId)
                    .col(Col::SupplicantId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::Tunnel)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::Name).text().not_null())
                    .col(ColumnDef::new(Col::Kind).text().not_null())
                    .col(ColumnDef::new(Col::Server).text())
                    .col(
                        ColumnDef::new(Col::Port)
                            .integer()
                            .check(Expr::col(Col::Port).between(1, 65535)),
                    )
                    .col(ColumnDef::new(Col::Subnet).cidr())
                    .col(ColumnDef::new(Col::PrivateKey).text())
                    .col(text_array(Col::AllowedIps))
                    .index(
                        Index::create()
                            .name("vlan_tunnel_vlan_id_name_key")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::Name),
                    )
                    .index(
                        Index::create()
                            .name("vlan_tunnel_creator_vlan_id_id_kind_key")
                            .unique()
                            .col(Col::Creator)
                            .col(Col::VlanId)
                            .col(Col::Id)
                            .col(Col::Kind),
                    )
                    .index(
                        Index::create()
                            .name("vlan_tunnel_vlan_id_subnet_key")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::Subnet),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_creator_vlan_id_fkey")
                            .from(Vlan::Tunnel, (Col::Creator, Col::VlanId))
                            .to(Vlan::Network, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .check(
                        Condition::any()
                            .add(
                                Condition::all()
                                    .add(Expr::col(Col::Kind).eq("easytier-gateway"))
                                    .add(Expr::col(Col::Server).is_not_null())
                                    .add(Expr::col(Col::Port).is_not_null())
                                    .add(Expr::col(Col::Subnet).is_not_null())
                                    .add(Expr::col(Col::PrivateKey).is_not_null())
                                    .add(cardinality(Col::AllowedIps).gt(0)),
                            )
                            .add(
                                Condition::all()
                                    .add(Expr::col(Col::Kind).eq("wireguard-compatible"))
                                    .add(Expr::col(Col::Server).is_null())
                                    .add(Expr::col(Col::Port).is_null())
                                    .add(Expr::col(Col::Subnet).is_null())
                                    .add(Expr::col(Col::PrivateKey).is_null())
                                    .add(cardinality(Col::AllowedIps).eq(0)),
                            ),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::TunnelGrant)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::TunnelId).uuid().not_null())
                    .col(ColumnDef::new(Col::Kind).text().not_null())
                    .col(ColumnDef::new(Col::SupplicantId).uuid().not_null())
                    .col(ColumnDef::new(Col::Slots).text())
                    .col(text_array(Col::Addresses))
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
                    .col(ColumnDef::new(Col::PrivateKey).text())
                    .index(
                        Index::create()
                            .name("vlan_tunnel_grant_tunnel_id_supplicant_id_key")
                            .unique()
                            .col(Col::TunnelId)
                            .col(Col::SupplicantId),
                    )
                    .index(
                        Index::create()
                            .name("vlan_tunnel_grant_id_kind_key")
                            .unique()
                            .col(Col::Id)
                            .col(Col::Kind),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_grant_creator_vlan_id_tunnel_id_kind_fkey")
                            .from_tbl(Vlan::TunnelGrant)
                            .from_col(Col::Creator)
                            .from_col(Col::VlanId)
                            .from_col(Col::TunnelId)
                            .from_col(Col::Kind)
                            .to_tbl(Vlan::Tunnel)
                            .to_col(Col::Creator)
                            .to_col(Col::VlanId)
                            .to_col(Col::Id)
                            .to_col(Col::Kind)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_grant_creator_vlan_id_supplicant_id_fkey")
                            .from(
                                Vlan::TunnelGrant,
                                (Col::Creator, Col::VlanId, Col::SupplicantId),
                            )
                            .to(Vlan::Grant, (Col::Creator, Col::VlanId, Col::SupplicantId))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .check(
                        Condition::any()
                            .add(
                                Condition::all()
                                    .add(Expr::col(Col::Kind).eq("easytier-gateway"))
                                    .add(Expr::col(Col::Slots).is_not_null())
                                    .add(cardinality(Col::Addresses).eq(0))
                                    .add(Expr::col(Col::PrivateKey).is_null())
                                    .add(Expr::col(Col::Mtu).is_null())
                                    .add(Expr::col(Col::PersistentKeepalive).is_null()),
                            )
                            .add(
                                Condition::all()
                                    .add(Expr::col(Col::Kind).eq("wireguard-compatible"))
                                    .add(Expr::col(Col::Slots).is_null())
                                    .add(cardinality(Col::Addresses).gt(0))
                                    .add(Expr::col(Col::PrivateKey).is_not_null()),
                            ),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("vlan_tunnel_grant_membership_idx")
                    .table(Vlan::TunnelGrant)
                    .col(Col::Creator)
                    .col(Col::VlanId)
                    .col(Col::SupplicantId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::WireguardPeer)
                    .col(id_column())
                    .col(ColumnDef::new(Col::GrantId).uuid().not_null())
                    .col(
                        ColumnDef::new(Col::Kind)
                            .text()
                            .generated(Expr::val("wireguard-compatible"), true),
                    )
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
                    .col(text_array(Col::AllowedIps).check(cardinality(Col::AllowedIps).gt(0)))
                    .index(
                        Index::create()
                            .name("vlan_wireguard_peer_grant_id_position_key")
                            .unique()
                            .col(Col::GrantId)
                            .col(Col::Position),
                    )
                    .index(
                        Index::create()
                            .name("vlan_wireguard_peer_grant_id_public_key_key")
                            .unique()
                            .col(Col::GrantId)
                            .col(Col::PublicKey),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_wireguard_peer_grant_id_kind_fkey")
                            .from(Vlan::WireguardPeer, (Col::GrantId, Col::Kind))
                            .to(Vlan::TunnelGrant, (Col::Id, Col::Kind))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        tx.execute(
            Query::insert()
                .into_table(Vlan::Route)
                .columns([Col::VlanId, Col::Cidr])
                .select_from(
                    Query::select()
                        .columns([Col::VlanId, Col::Subnet])
                        .from(Vlan::Gateway)
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?
                .on_conflict(
                    OnConflict::columns([Col::VlanId, Col::Cidr])
                        .do_nothing()
                        .to_owned(),
                ),
        )
        .await?;
        let route = Expr::col((Vlan::Route, Col::Cidr));
        let allowed_ips = Query::select()
            .expr(Func::cust(Alias::new("concat")).args([
                Func::cust(Alias::new("host")).arg(route.clone()).into(),
                Expr::val("/"),
                Func::cust(Alias::new("masklen")).arg(route).into(),
            ]))
            .from(Vlan::Route)
            .and_where(Expr::col((Vlan::Route, Col::VlanId)).equals((Vlan::Gateway, Col::VlanId)))
            .order_by((Vlan::Route, Col::Cidr), Order::Asc)
            .to_owned();
        tx.execute(
            Query::insert()
                .into_table(Vlan::Tunnel)
                .columns([
                    Col::Id,
                    Col::Creator,
                    Col::VlanId,
                    Col::Name,
                    Col::Kind,
                    Col::Server,
                    Col::Port,
                    Col::Subnet,
                    Col::PrivateKey,
                    Col::AllowedIps,
                ])
                .select_from(
                    Query::select()
                        .columns([
                            (Vlan::Gateway, Col::Id),
                            (Vlan::Network, Col::Creator),
                            (Vlan::Gateway, Col::VlanId),
                            (Vlan::Gateway, Col::Name),
                        ])
                        .expr(Expr::val("easytier-gateway"))
                        .columns(
                            [Col::Server, Col::Port, Col::Subnet, Col::PrivateKey]
                                .map(|col| (Vlan::Gateway, col)),
                        )
                        // SeaQuery has no PostgreSQL ARRAY(subquery) constructor.
                        .expr(Expr::cust_with_expr(
                            "ARRAY $1",
                            Expr::SubQuery(None, Box::new(allowed_ips.into())),
                        ))
                        .from(Vlan::Gateway)
                        .inner_join(
                            Vlan::Network,
                            Expr::col((Vlan::Gateway, Col::VlanId))
                                .equals((Vlan::Network, Col::Id)),
                        )
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?,
        )
        .await?;
        tx.execute(
            Query::insert()
                .into_table(Vlan::TunnelGrant)
                .columns([
                    Col::Creator,
                    Col::VlanId,
                    Col::TunnelId,
                    Col::Kind,
                    Col::SupplicantId,
                    Col::Slots,
                    Col::Addresses,
                ])
                .select_from(
                    Query::select()
                        .columns(
                            [Col::Creator, Col::VlanId, Col::Id, Col::Kind]
                                .map(|col| (Vlan::Tunnel, col)),
                        )
                        .columns([Col::SupplicantId, Col::Slots].map(|col| (Vlan::Grant, col)))
                        .expr(Expr::val(Vec::<String>::new()))
                        .from(Vlan::Tunnel)
                        .inner_join(
                            Vlan::Grant,
                            Condition::all()
                                .add(
                                    Expr::col((Vlan::Tunnel, Col::Creator))
                                        .equals((Vlan::Grant, Col::Creator)),
                                )
                                .add(
                                    Expr::col((Vlan::Tunnel, Col::VlanId))
                                        .equals((Vlan::Grant, Col::VlanId)),
                                ),
                        )
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?,
        )
        .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Vlan::Grant)
                    .drop_column(Col::Slots)
                    .to_owned(),
            )
            .await?;
        schema
            .drop_table(Table::drop().table(Vlan::Gateway).to_owned())
            .await?;
        tx.commit().await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Restore the pre-migration backup to return to VLAN-level slot grants".into(),
        ))
    }
}
