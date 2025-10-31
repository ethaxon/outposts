use sea_orm_migration::prelude::*;

use super::defs::{
    create_postgres_auto_update_ts_fn, create_postgres_auto_update_ts_trigger,
    drop_postgres_auto_update_ts_fn, drop_postgres_auto_update_ts_trigger,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_postgres_auto_update_ts_fn(manager, "updated_at").await?;
        create_postgres_auto_update_ts_trigger(manager, "updated_at", "confluence").await?;
        create_postgres_auto_update_ts_trigger(manager, "updated_at", "profile").await?;
        create_postgres_auto_update_ts_trigger(manager, "updated_at", "subscribe_source").await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_postgres_auto_update_ts_trigger(manager, "updated_at", "confluence").await?;
        drop_postgres_auto_update_ts_trigger(manager, "updated_at", "profile").await?;
        drop_postgres_auto_update_ts_trigger(manager, "updated_at", "subscribe_source").await?;
        drop_postgres_auto_update_ts_fn(manager, "updated_at").await?;
        Ok(())
    }
}
