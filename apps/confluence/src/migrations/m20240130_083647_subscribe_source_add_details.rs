use super::defs::{Confluence, SubscribeSource};
use sea_orm_migration::prelude::*;

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
                        ColumnDef::new(SubscribeSource::SubDownload).big_integer(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(SubscribeSource::SubUpload).big_integer(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(SubscribeSource::SubTotal).big_integer(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(SubscribeSource::SubExpire).timestamp(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Confluence::Table)
                    .add_column_if_not_exists(ColumnDef::new(Confluence::SubDownload).big_integer())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::SubUpload).big_integer())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::SubTotal).big_integer())
                    .add_column_if_not_exists(ColumnDef::new(Confluence::SubExpire).timestamp())
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
                    .drop_column(SubscribeSource::SubDownload)
                    .drop_column(SubscribeSource::SubExpire)
                    .drop_column(SubscribeSource::SubTotal)
                    .drop_column(SubscribeSource::SubUpload)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Confluence::Table)
                    .drop_column(Confluence::SubDownload)
                    .drop_column(Confluence::SubExpire)
                    .drop_column(Confluence::SubTotal)
                    .drop_column(Confluence::SubUpload)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
