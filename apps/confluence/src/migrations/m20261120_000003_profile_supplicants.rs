use sea_orm::TransactionTrait;
use sea_orm_migration::prelude::*;

use super::defs::{Confluence, Profile, VlanColumn, VlanTable};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ProfileSupplicant {
    Table,
    ProfileId,
    ConfluenceId,
    Creator,
    SupplicantId,
}

const PROFILE_WORKSPACE_INDEX: &str = "profile_confluence_id_id_key";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let tx = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&tx);
        use ProfileSupplicant as Link;

        schema
            .create_index(
                Index::create()
                    .name(PROFILE_WORKSPACE_INDEX)
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
                            .to(VlanTable::Supplicant, (VlanColumn::Creator, VlanColumn::Id))
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
        tx.commit().await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Restore the pre-migration backup to roll back Profile age encryption".into(),
        ))
    }
}
