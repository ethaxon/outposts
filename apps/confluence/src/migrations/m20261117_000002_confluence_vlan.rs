use super::defs::Confluence;
use sea_orm::TransactionTrait;
use sea_orm::sea_query::Func;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum VlanNetwork {
    Table,
}
#[derive(DeriveIden)]
enum VlanSupplicant {
    Table,
}
#[derive(DeriveIden)]
enum ConfluenceVlan {
    Table,
}
#[derive(DeriveIden)]
enum VlanGrant {
    Table,
}
#[derive(DeriveIden)]
enum VlanGateway {
    Table,
}
#[derive(DeriveIden)]
enum VlanRoute {
    Table,
}
#[derive(DeriveIden)]
enum Col {
    Id,
    Creator,
    Name,
    Enabled,
    AgeRecipient,
    ConfluenceId,
    VlanId,
    SupplicantId,
    Slots,
    Server,
    Port,
    Subnet,
    PrivateKey,
    Cidr,
}

fn id_column() -> ColumnDef {
    ColumnDef::new(Col::Id)
        .uuid()
        .not_null()
        .default(Func::cust(Alias::new("uuidv7")))
        .primary_key()
        .take()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let transaction = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&transaction);
        // Composite foreign keys enforce same-creator links independently of API checks.
        schema
            .create_index(
                Index::create()
                    .name("confluence_creator_id_unique")
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
                    .table(VlanNetwork::Table)
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
                    .table(VlanSupplicant::Table)
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
                    .table(ConfluenceVlan::Table)
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
                            .from(ConfluenceVlan::Table, (Col::Creator, Col::ConfluenceId))
                            .to(Confluence::Table, (Confluence::Creator, Confluence::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("confluence_vlan_network_fk")
                            .from(ConfluenceVlan::Table, (Col::Creator, Col::VlanId))
                            .to(VlanNetwork::Table, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(VlanGrant::Table)
                    .col(id_column())
                    .col(ColumnDef::new(Col::Creator).string().not_null())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::SupplicantId).uuid().not_null())
                    .col(ColumnDef::new(Col::Slots).text().not_null())
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
                            .from(VlanGrant::Table, (Col::Creator, Col::VlanId))
                            .to(VlanNetwork::Table, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_grant_supplicant_fk")
                            .from(VlanGrant::Table, (Col::Creator, Col::SupplicantId))
                            .to(VlanSupplicant::Table, (Col::Creator, Col::Id))
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(VlanGateway::Table)
                    .col(id_column())
                    .col(ColumnDef::new(Col::VlanId).uuid().not_null())
                    .col(ColumnDef::new(Col::Name).text().not_null())
                    .col(ColumnDef::new(Col::Server).text().not_null())
                    .col(ColumnDef::new(Col::Port).integer().not_null())
                    .col(ColumnDef::new(Col::Subnet).cidr().not_null())
                    .col(ColumnDef::new(Col::PrivateKey).text().not_null())
                    .check(Expr::col(Col::Port).between(1, 65535))
                    .index(
                        Index::create()
                            .name("vlan_gateway_name_unique")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::Name),
                    )
                    .index(
                        Index::create()
                            .name("vlan_gateway_subnet_unique")
                            .unique()
                            .col(Col::VlanId)
                            .col(Col::Subnet),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("vlan_gateway_network_fk")
                            .from(VlanGateway::Table, Col::VlanId)
                            .to(VlanNetwork::Table, Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_table(
                Table::create()
                    .table(VlanRoute::Table)
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
                            .from(VlanRoute::Table, Col::VlanId)
                            .to(VlanNetwork::Table, Col::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("confluence_vlan_network_idx")
                    .table(ConfluenceVlan::Table)
                    .col(Col::VlanId)
                    .to_owned(),
            )
            .await?;
        schema
            .create_index(
                Index::create()
                    .name("vlan_grant_supplicant_idx")
                    .table(VlanGrant::Table)
                    .col(Col::SupplicantId)
                    .to_owned(),
            )
            .await?;
        transaction.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let transaction = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&transaction);
        schema
            .drop_table(Table::drop().table(VlanRoute::Table).to_owned())
            .await?;
        schema
            .drop_table(Table::drop().table(VlanGateway::Table).to_owned())
            .await?;
        schema
            .drop_table(Table::drop().table(VlanGrant::Table).to_owned())
            .await?;
        schema
            .drop_table(Table::drop().table(ConfluenceVlan::Table).to_owned())
            .await?;
        schema
            .drop_table(Table::drop().table(VlanSupplicant::Table).to_owned())
            .await?;
        schema
            .drop_table(Table::drop().table(VlanNetwork::Table).to_owned())
            .await?;
        schema
            .drop_index(
                Index::drop()
                    .name("confluence_creator_id_unique")
                    .table(Confluence::Table)
                    .to_owned(),
            )
            .await?;
        transaction.commit().await
    }
}
