use sea_orm::sea_query::{ExprTrait, Func};
use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::prelude::*;

use super::defs::{Confluence, Profile, SubscribeSource};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Replacement {
    IdV7,
    ConfluenceIdV7,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let transaction = manager.get_connection().begin().await?;
        let schema = SchemaManager::new(&transaction);
        let version = transaction
            .query_one(
                &Query::select()
                    .expr_as(
                        Func::cust(Alias::new("current_setting"))
                            .arg("server_version_num")
                            .cast_as(Alias::new("int4")),
                        Alias::new("version"),
                    )
                    .to_owned(),
            )
            .await?
            .ok_or_else(|| DbErr::Migration("Cannot determine PostgreSQL version".into()))?;
        if version.try_get::<i32>("", "version")? < 180000 {
            return Err(DbErr::Migration(
                "Confluence requires PostgreSQL 18 or newer".into(),
            ));
        }
        // SeaQuery has no table-lock or trigger-enable statements. Preserve historical timestamps during backfill.
        transaction
            .execute_unprepared(
                "LOCK TABLE confluence, profile, subscribe_source IN ACCESS EXCLUSIVE MODE",
            )
            .await?;
        for table in ["confluence", "profile", "subscribe_source"] {
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} DISABLE TRIGGER update_{table}_updated_at_column_trigger"
                ))
                .await?;
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(
                            ColumnDef::new(Replacement::IdV7)
                                .uuid()
                                .not_null()
                                .default(Func::cust(Alias::new("uuidv7"))),
                        )
                        .to_owned(),
                )
                .await?;
        }
        for table in ["profile", "subscribe_source"] {
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(ColumnDef::new(Replacement::ConfluenceIdV7).uuid())
                        .to_owned(),
                )
                .await?;
        }
        for table in ["profile", "subscribe_source"] {
            transaction
                .execute(
                    &Query::update()
                        .table(Alias::new(table))
                        .value(
                            Replacement::ConfluenceIdV7,
                            Expr::col((Confluence::Table, Replacement::IdV7)),
                        )
                        .from(Confluence::Table)
                        .and_where(
                            Expr::col((Alias::new(table), Profile::ConfluenceId))
                                .equals((Confluence::Table, Confluence::Id)),
                        )
                        .to_owned(),
                )
                .await?;
        }
        // Drop the old child columns first to remove their foreign keys by dependency instead of by name.
        for table in ["profile", "subscribe_source"] {
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .modify_column(
                            ColumnDef::new(Replacement::ConfluenceIdV7)
                                .uuid()
                                .not_null(),
                        )
                        .drop_column(Profile::ConfluenceId)
                        .to_owned(),
                )
                .await?;
        }
        // PostgreSQL removes each old primary key with its integer column.
        for table in ["confluence", "profile", "subscribe_source"] {
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Confluence::Id)
                        .to_owned(),
                )
                .await?;
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .rename_column(Replacement::IdV7, Confluence::Id)
                        .to_owned(),
                )
                .await?;
            // SeaQuery cannot add a primary-key constraint to an existing column.
            transaction
                .execute_unprepared(&format!("ALTER TABLE {table} ADD PRIMARY KEY (id)"))
                .await?;
        }
        for table in ["profile", "subscribe_source"] {
            schema
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .rename_column(Replacement::ConfluenceIdV7, Profile::ConfluenceId)
                        .to_owned(),
                )
                .await?;
        }
        schema
            .alter_table(
                Table::alter()
                    .table(Profile::Table)
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
        schema
            .alter_table(
                Table::alter()
                    .table(SubscribeSource::Table)
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
        for table in ["confluence", "profile", "subscribe_source"] {
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} ENABLE TRIGGER update_{table}_updated_at_column_trigger"
                ))
                .await?;
        }
        transaction.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let transaction = manager.get_connection().begin().await?;
        transaction
            .execute_unprepared(
                "LOCK TABLE confluence, profile, subscribe_source IN ACCESS EXCLUSIVE MODE",
            )
            .await?;

        // Keeping the UUID columns until relinking is complete preserves every relationship.
        for table in ["confluence", "profile", "subscribe_source"] {
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} RENAME COLUMN id TO id_v7;
                     ALTER TABLE {table} ADD COLUMN id SERIAL;"
                ))
                .await?;
        }
        for table in ["profile", "subscribe_source"] {
            // The foreign-key backfill must preserve the historical updated_at values.
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} DISABLE TRIGGER update_{table}_updated_at_column_trigger;
                     ALTER TABLE {table} RENAME COLUMN confluence_id TO confluence_id_v7;
                     ALTER TABLE {table} ADD COLUMN confluence_id INTEGER;
                     UPDATE {table} AS child SET confluence_id = confluence.id
                     FROM confluence WHERE child.confluence_id_v7 = confluence.id_v7;
                     ALTER TABLE {table} ALTER COLUMN confluence_id SET NOT NULL,
                         DROP COLUMN confluence_id_v7;
                     ALTER TABLE {table} ENABLE TRIGGER update_{table}_updated_at_column_trigger;"
                ))
                .await?;
        }
        for table in ["confluence", "profile", "subscribe_source"] {
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} DROP COLUMN id_v7;
                     ALTER TABLE {table} ADD PRIMARY KEY (id);"
                ))
                .await?;
        }
        for table in ["profile", "subscribe_source"] {
            transaction
                .execute_unprepared(&format!(
                    "ALTER TABLE {table} ADD CONSTRAINT {table}_confluence_id_fk
                     FOREIGN KEY (confluence_id) REFERENCES confluence (id)
                     ON DELETE CASCADE ON UPDATE CASCADE;"
                ))
                .await?;
        }
        transaction.commit().await
    }
}
