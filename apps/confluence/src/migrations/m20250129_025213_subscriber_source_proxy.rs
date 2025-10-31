use sea_orm_migration::prelude::*;

use super::defs::SubscribeSource;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .add_column_if_not_exists(ColumnDef::new(SubscribeSource::ProxyServer).text())
                    .add_column_if_not_exists(ColumnDef::new(SubscribeSource::ProxyAuth).text())
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
                    .drop_column(SubscribeSource::ProxyAuth)
                    .drop_column(SubscribeSource::ProxyServer)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
