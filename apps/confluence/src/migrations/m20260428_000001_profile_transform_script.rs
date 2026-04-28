use super::defs::Profile;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .add_column(ColumnDef::new(Profile::TransformScript).text().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .drop_column(Profile::TransformScript)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
