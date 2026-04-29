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
                    .add_column_if_not_exists(
                        ColumnDef::new(SubscribeSource::TrafficNextResetAt).timestamp(),
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
                    .drop_column(SubscribeSource::TrafficNextResetAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
