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
        db.execute(
            &Query::update()
                .table(SubscribeSource::Table)
                .value(SubscribeSource::TrafficResetPolicy, "default")
                .cond_where(
                    Cond::any()
                        .add(Expr::col(SubscribeSource::TrafficResetPolicy).is_null())
                        .add(Expr::col(SubscribeSource::TrafficResetPolicy).eq("")),
                )
                .to_owned(),
        )
        .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
                    .modify_column(
                        ColumnDef::new(SubscribeSource::TrafficResetPolicy)
                            .default("default")
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        // SeaQuery does not expose conditional constraint removal or ADD CHECK for ALTER TABLE.
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
