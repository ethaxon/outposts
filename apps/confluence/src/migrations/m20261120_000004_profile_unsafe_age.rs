use sea_orm_migration::prelude::*;

use super::defs::Profile;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
                    .drop_column(Profile::AllowUnsafeAgePrivateKey)
                    .to_owned(),
            )
            .await
    }
}
