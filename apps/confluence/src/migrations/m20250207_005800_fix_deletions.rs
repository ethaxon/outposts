use sea_orm_migration::prelude::*;

use super::defs::{Confluence, Profile, SubscribeSource};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .drop_foreign_key(Alias::new("subscribe_source_confluence_id_fk"))
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("subscribe_source_confluence_id_fk")
                            .from_tbl(SubscribeSource::Table)
                            .from_col(SubscribeSource::ConfluenceId)
                            .to_tbl(Confluence::Table)
                            .to_col(Confluence::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .drop_foreign_key(Alias::new("profile_confluence_id_fk"))
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("profile_confluence_id_fk")
                            .from_tbl(Profile::Table)
                            .from_col(Profile::ConfluenceId)
                            .to_tbl(Confluence::Table)
                            .to_col(Confluence::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .drop_foreign_key(Alias::new("subscribe_source_confluence_id_fk"))
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("subscribe_source_confluence_id_fk")
                            .from_tbl(SubscribeSource::Table)
                            .from_col(SubscribeSource::ConfluenceId)
                            .to_tbl(Confluence::Table)
                            .to_col(Confluence::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .drop_foreign_key(Alias::new("profile_confluence_id_fk"))
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("profile_confluence_id_fk")
                            .from_tbl(Profile::Table)
                            .from_col(Profile::ConfluenceId)
                            .to_tbl(Confluence::Table)
                            .to_col(Confluence::Id),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
