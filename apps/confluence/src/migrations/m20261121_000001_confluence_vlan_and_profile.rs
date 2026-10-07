use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm_migration::prelude::*;

use super::defs::{Confluence, Profile, SubscribeSource, VlanColumn as Col, VlanTable as Vlan};

#[derive(DeriveMigrationName)]
pub struct Migration;

const CONFLUENCE_CREATOR_INDEX: &str = "confluence_creator_id_unique";
const PROFILE_CONFLUENCE_INDEX: &str = "profile_confluence_id_id_key";

#[derive(DeriveIden)]
enum ProfileSupplicant {
    Table,
    ProfileId,
    ConfluenceId,
    Creator,
    SupplicantId,
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
    async fn up(&self, schema: &SchemaManager) -> Result<(), DbErr> {
        // Composite foreign keys enforce same-creator links independently of API checks.
        schema
            .create_index(
                Index::create()
                    .name(CONFLUENCE_CREATOR_INDEX)
                    .unique()
                    .table(Confluence::Table)
                    .col(Confluence::Creator)
                    .col(Confluence::Id)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::Network)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::Name).text().not_null())
                    .col(ColumnDef::new(Col::Enabled).boolean().not_null())
                    .index(
                        Index::create()
                            .name("vlan_network_creator_name_unique")
                            .unique()
                            .col(Col::Creator)
                            .col(Col::Name),
                    )
                    .index(
                        Index::create()
                            .name("vlan_network_creator_id_unique")
                            .unique()
                            .col(Col::Creator)
                            .col(Col::Id),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::Supplicant)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::Name).text().not_null())
                    .col(ColumnDef::new(Col::AgeRecipient).text().not_null())
                    .index(
                        Index::create()
                            .name("vlan_supplicant_creator_name_unique")
                            .unique()
                            .col(Col::Creator)
                            .col(Col::Name),
                    )
                    .index(
                        Index::create()
                            .name("vlan_supplicant_creator_id_unique")
                            .unique()
                            .col(Col::Creator)
                            .col(Col::Id),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::ConfluenceVlan)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::ConfluenceId).uuid().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .index(
                        Index::create()
                            .name("confluence_vlan_pair_unique")
                            .unique()
                            .col(Col::ConfluenceId)
                            .col(Col::VlanId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("confluence_vlan_workspace_fk")
                            .from(Vlan::ConfluenceVlan, (Col::Creator, Col::ConfluenceId))
                            .to(Confluence::Table, (Confluence::Creator, Confluence::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("confluence_vlan_network_fk")
                            .from(Vlan::ConfluenceVlan, (Col::Creator, Col::VlanId))
                            .to(Vlan::Network, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::Grant)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::SupplicantId).uuid().not_null())
                    .index(
                        Index::create()
                            .name("vlan_grant_identity_unique")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::SupplicantId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_grant_network_fk")
                            .from(Vlan::Grant, (Col::Creator, Col::VlanId))
                            .to(Vlan::Network, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_grant_supplicant_fk")
                            .from(Vlan::Grant, (Col::Creator, Col::SupplicantId))
                            .to(Vlan::Supplicant, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Vlan::Route)
                    .col(id_column())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::Cidr).cidr().not_null())
                    .index(
                        Index::create()
                            .name("vlan_route_cidr_unique")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::Cidr),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_route_network_fk")
                            .from(Vlan::Route, Col::VlanId)
                            .to(Vlan::Network, Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("confluence_vlan_network_idx")
                    .table(Vlan::ConfluenceVlan)
                    .col(Col::VlanId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("vlan_grant_supplicant_idx")
                    .table(Vlan::Grant)
                    .col(Col::SupplicantId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("vlan_grant_creator_vlan_id_supplicant_id_key")
                    .unique()
                    .table(Vlan::Grant)
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
                            .from(Vlan::Tunnel, (Col::Creator, Col::VlanId))
                            .to(Vlan::Network, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
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
                            .from(
                                Vlan::TunnelGrant,
                                (Col::Creator, Col::VlanId, Col::TunnelId),
                            )
                            .to(Vlan::Tunnel, (Col::Creator, Col::VlanId, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_tunnel_grant_membership_fk")
                            .from(
                                Vlan::TunnelGrant,
                                (Col::Creator, Col::VlanId, Col::SupplicantId),
                            )
                            .to(Vlan::Grant, (Col::Creator, Col::VlanId, Col::SupplicantId))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .table(Vlan::TunnelGrant)
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
                    .table(Vlan::WireguardPeer)
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
                            .from(Vlan::WireguardPeer, Col::TunnelId)
                            .to(Vlan::Tunnel, Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        use ProfileSupplicant as Link;
        schema
            .create_index(
                Index::create()
                    .name(PROFILE_CONFLUENCE_INDEX)
                    .table(Profile::Table)
                    .unique()
                    .col(Profile::ConfluenceId)
                    .col(Profile::Id)
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(Link::Table)
                    .col(ColumnDef::new(Link::ProfileId).uuid().not_null())
                    .col(ColumnDef::new(Link::ConfluenceId).uuid().not_null())
                    .col(ColumnDef::new(Link::Creator).string().not_null())
                    .col(ColumnDef::new(Link::SupplicantId).uuid().not_null())
                    .primary_key(Index::create().col(Link::ProfileId).col(Link::SupplicantId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("profile_supplicant_profile_fk")
                            .from(Link::Table, (Link::ConfluenceId, Link::ProfileId))
                            .to(Profile::Table, (Profile::ConfluenceId, Profile::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("profile_supplicant_workspace_fk")
                            .from(Link::Table, (Link::Creator, Link::ConfluenceId))
                            .to(Confluence::Table, (Confluence::Creator, Confluence::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("profile_supplicant_supplicant_fk")
                            .from(Link::Table, (Link::Creator, Link::SupplicantId))
                            .to(Vlan::Supplicant, (Col::Creator, Col::Id))
                            // Deleting the last recipient must never silently turn encryption off.
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("profile_supplicant_supplicant_idx")
                    .table(Link::Table)
                    .col(Link::SupplicantId)
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .add_column(
                        ColumnDef::new(Profile::AllowUnsafeAgePrivateKey)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .add_column(ColumnDef::new(SubscribeSource::LastSyncError).json_binary())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, schema: &SchemaManager) -> Result<(), DbErr> {
        schema
            .drop_table(Table::drop().table(ProfileSupplicant::Table).to_owned())
            .await?;
        for table in [
            Vlan::WireguardPeer,
            Vlan::TunnelGrant,
            Vlan::Tunnel,
            Vlan::Route,
            Vlan::Grant,
            Vlan::ConfluenceVlan,
            Vlan::Supplicant,
            Vlan::Network,
        ] {
            schema
                .drop_table(Table::drop().table(table).to_owned())
                .await?;
        }
        schema
            .drop_index(
                Index::drop()
                    .name(PROFILE_CONFLUENCE_INDEX)
                    .table(Profile::Table)
                    .to_owned(),
            )
            .await?;
        schema
            .drop_index(
                Index::drop()
                    .name(CONFLUENCE_CREATOR_INDEX)
                    .table(Confluence::Table)
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .drop_column(Profile::AllowUnsafeAgePrivateKey)
                    .to_owned(),
            )
            .await?;
        schema
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .drop_column(SubscribeSource::LastSyncError)
                    .to_owned(),
            )
            .await
    }
}
