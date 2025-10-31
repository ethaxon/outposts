use super::defs::Confluence;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Confluence::Table)
                    .add_column_if_not_exists(ColumnDef::new(Confluence::CronExpr).string())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::CronExprTz).string())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::CronPrevAt).timestamp())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::CronNextAt).timestamp())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::CronErr).text())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Confluence::Table)
                    .drop_column(Confluence::CronExpr)
                    .drop_column(Confluence::CronExprTz)
                    .drop_column(Confluence::CronPrevAt)
                    .drop_column(Confluence::CronNextAt)
                    .drop_column(Confluence::CronErr)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
