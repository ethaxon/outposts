use sea_orm_migration::prelude::*;

use super::defs::SubscribeSource;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(SubscribeSource::TrafficResetPolicy)
                            .text()
                            .default("default"),
                    )
                    .to_owned(),
            )
            .await?;
        db.execute_unprepared(
            "UPDATE subscribe_source \
             SET traffic_reset_policy = 'default' \
             WHERE traffic_reset_policy IS NULL OR traffic_reset_policy = '';",
        )
        .await?;
        db.execute_unprepared(
            "ALTER TABLE subscribe_source \
             ALTER COLUMN traffic_reset_policy SET DEFAULT 'default', \
             ALTER COLUMN traffic_reset_policy SET NOT NULL;",
        )
        .await?;
        db.execute_unprepared(
            "ALTER TABLE subscribe_source \
             DROP CONSTRAINT IF EXISTS subscribe_source_traffic_reset_policy_check;",
        )
        .await?;
        db.execute_unprepared(
            "ALTER TABLE subscribe_source \
             ADD CONSTRAINT subscribe_source_traffic_reset_policy_check \
             CHECK (traffic_reset_policy IN ('default', 'monthly', 'quarterly', 'yearly', 'one_time'));",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE subscribe_source \
                 DROP CONSTRAINT IF EXISTS subscribe_source_traffic_reset_policy_check;",
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .drop_column(SubscribeSource::TrafficResetPolicy)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
