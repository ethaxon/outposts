use confluence::migrations::{Migrator, MigratorTrait};
use confluence::models::{
    confluence as workspace, confluence_vlan, profile, subscribe_source as source, vlan_grant,
    vlan_network, vlan_supplicant,
};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Alias, Asterisk, Expr, ExprTrait, Func, JoinType, Query};
use sea_orm::{ActiveModelTrait, EntityTrait, LoaderTrait};
use sea_orm::{ConnectionTrait, Database};

fn epoch() -> Expr {
    Func::cust(Alias::new("to_timestamp")).arg(0).into()
}

#[tokio::test]
#[ignore = "requires an empty, isolated PostgreSQL 18 database in TEST_DATABASE_URL"]
async fn migrate_integer_records_preserving_tokens_timestamps_and_relations() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let db = Database::connect(url).await.unwrap();
    let tables = Query::select()
        .expr(Expr::val(1))
        .from((Alias::new("information_schema"), Alias::new("tables")))
        .and_where(Expr::col(Alias::new("table_schema")).eq("public"))
        .to_owned();
    let row = db
        .query_one(
            &Query::select()
                .expr_as(Expr::exists(tables).not(), Alias::new("empty"))
                .to_owned(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.try_get::<bool>("", "empty").unwrap(),
        "Migration verification requires a fresh database"
    );
    let legacy_steps = Migrator::migrations().len() as u32 - 2;
    Migrator::up(&db, Some(legacy_steps)).await.unwrap();
    // Restored databases can use custom constraint names for the same relationships.
    for (table, old, new) in [
        ("confluence", "confluence_pkey", "legacy workspace key"),
        ("profile", "profile_pkey", "legacy profile key"),
        (
            "subscribe_source",
            "subscribe_source_pkey",
            "legacy source key",
        ),
        (
            "profile",
            "profile_confluence_id_fk",
            "legacy profile workspace reference",
        ),
        (
            "subscribe_source",
            "subscribe_source_confluence_id_fk",
            "legacy source workspace reference",
        ),
    ] {
        db.execute_unprepared(&format!(
            "ALTER TABLE {table} RENAME CONSTRAINT {old} TO \"{new}\""
        ))
        .await
        .unwrap();
    }
    let token = "00000000-0000-4000-8000-000000000001";
    db.execute(
        &Query::insert()
            .into_table(workspace::Entity)
            .columns([
                workspace::Column::Id,
                workspace::Column::Name,
                workspace::Column::Template,
                workspace::Column::Creator,
                workspace::Column::MuxContent,
                workspace::Column::CreatedAt,
                workspace::Column::UpdatedAt,
            ])
            .values_panic([
                Expr::val(100),
                Expr::val("legacy workspace"),
                Expr::val("proxies: []"),
                Expr::val("migration-test"),
                Expr::val("proxies: []"),
                epoch(),
                epoch(),
            ])
            .to_owned(),
    )
    .await
    .unwrap();
    db.execute(
        &Query::insert()
            .into_table(profile::Entity)
            .columns([
                profile::Column::Id,
                profile::Column::ConfluenceId,
                profile::Column::ResourceToken,
                profile::Column::CreatedAt,
                profile::Column::UpdatedAt,
            ])
            .values_panic([
                Expr::val(200),
                Expr::val(100),
                Expr::val(token),
                epoch(),
                epoch(),
            ])
            .to_owned(),
    )
    .await
    .unwrap();
    db.execute(
        &Query::insert()
            .into_table(source::Entity)
            .columns([
                source::Column::Id,
                source::Column::ConfluenceId,
                source::Column::Url,
                source::Column::Name,
                source::Column::Content,
                source::Column::CreatedAt,
                source::Column::UpdatedAt,
            ])
            .values_panic([
                Expr::val(300),
                Expr::val(100),
                Expr::val("https://example.com/subscription"),
                Expr::val("legacy source"),
                Expr::val("proxies: []"),
                epoch(),
                epoch(),
            ])
            .to_owned(),
    )
    .await
    .unwrap();
    // An unexpected external dependency must block the migration without leaving a partial rewrite.
    db.execute_unprepared("CREATE VIEW legacy_workspace_ids AS SELECT id FROM confluence")
        .await
        .unwrap();
    let error = Migrator::up(&db, None).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("because other objects depend on it"),
        "{error}"
    );
    db.execute_unprepared("DROP VIEW legacy_workspace_ids")
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let timestamps = Expr::col((Alias::new("c"), workspace::Column::CreatedAt))
        .eq(epoch())
        .and(Expr::col((Alias::new("c"), workspace::Column::UpdatedAt)).eq(epoch()))
        .and(Expr::col((Alias::new("p"), profile::Column::CreatedAt)).eq(epoch()))
        .and(Expr::col((Alias::new("p"), profile::Column::UpdatedAt)).eq(epoch()))
        .and(Expr::col((Alias::new("s"), source::Column::CreatedAt)).eq(epoch()))
        .and(Expr::col((Alias::new("s"), source::Column::UpdatedAt)).eq(epoch()));
    let row = db
        .query_one(
            &Query::select()
                .expr_as(
                    Func::cust(Alias::new("uuid_extract_version"))
                        .arg(Expr::col((Alias::new("c"), workspace::Column::Id))),
                    Alias::new("cv"),
                )
                .expr_as(
                    Func::cust(Alias::new("uuid_extract_version"))
                        .arg(Expr::col((Alias::new("p"), profile::Column::Id))),
                    Alias::new("pv"),
                )
                .expr_as(
                    Func::cust(Alias::new("uuid_extract_version"))
                        .arg(Expr::col((Alias::new("s"), source::Column::Id))),
                    Alias::new("sv"),
                )
                .column((Alias::new("p"), profile::Column::ResourceToken))
                .expr_as(timestamps, Alias::new("timestamps_preserved"))
                .from_as(workspace::Entity, Alias::new("c"))
                .join_as(
                    JoinType::InnerJoin,
                    profile::Entity,
                    Alias::new("p"),
                    Expr::col((Alias::new("p"), profile::Column::ConfluenceId))
                        .equals((Alias::new("c"), workspace::Column::Id)),
                )
                .join_as(
                    JoinType::InnerJoin,
                    source::Entity,
                    Alias::new("s"),
                    Expr::col((Alias::new("s"), source::Column::ConfluenceId))
                        .equals((Alias::new("c"), workspace::Column::Id)),
                )
                .and_where(
                    Expr::col((Alias::new("c"), workspace::Column::Name)).eq("legacy workspace"),
                )
                .to_owned(),
        )
        .await
        .unwrap()
        .unwrap();
    for column in ["cv", "pv", "sv"] {
        assert_eq!(row.try_get::<i16>("", column).unwrap(), 7);
    }
    assert_eq!(row.try_get::<String>("", "resource_token").unwrap(), token);
    assert!(row.try_get::<bool>("", "timestamps_preserved").unwrap());
    db.execute(
        &Query::insert()
            .into_table(workspace::Entity)
            .columns([
                workspace::Column::Name,
                workspace::Column::Template,
                workspace::Column::Creator,
                workspace::Column::MuxContent,
            ])
            .values_panic([
                Expr::val("new workspace"),
                Expr::val("proxies: []"),
                Expr::val("migration-test"),
                Expr::val("proxies: []"),
            ])
            .to_owned(),
    )
    .await
    .unwrap();
    let row = db
        .query_one(
            &Query::select()
                .expr_as(
                    Func::cust(Alias::new("uuid_extract_version"))
                        .arg(Expr::col(workspace::Column::Id)),
                    Alias::new("version"),
                )
                .from(workspace::Entity)
                .and_where(Expr::col(workspace::Column::Name).eq("new workspace"))
                .to_owned(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i16>("", "version").unwrap(), 7);
    db.execute(
        &Query::delete()
            .from_table(workspace::Entity)
            .and_where(Expr::col(workspace::Column::Name).eq("legacy workspace"))
            .to_owned(),
    )
    .await
    .unwrap();
    for table in ["profile", "subscribe_source"] {
        let row = db
            .query_one(
                &Query::select()
                    .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("remaining"))
                    .from(Alias::new(table))
                    .to_owned(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "remaining").unwrap(), 0);
    }
    verify_vlan_relationships(&db).await;
}

async fn verify_vlan_relationships(db: &sea_orm::DatabaseConnection) {
    let create_workspace = |creator: &str| workspace::ActiveModel {
        creator: Set(creator.into()),
        name: Set("VLAN workspace".into()),
        template: Set(String::new()),
        mux_content: Set(String::new()),
        ..Default::default()
    };
    let a = create_workspace("owner").insert(db).await.unwrap();
    let b = create_workspace("owner").insert(db).await.unwrap();
    let foreign = create_workspace("other").insert(db).await.unwrap();
    let vlan = vlan_network::ActiveModel {
        creator: Set("owner".into()),
        name: Set("shared".into()),
        enabled: Set(false),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    let link = |creator: &str, workspace_id| confluence_vlan::ActiveModel {
        creator: Set(creator.into()),
        confluence_id: Set(workspace_id),
        vlan_id: Set(vlan.id),
        ..Default::default()
    };
    link("owner", a.id).insert(db).await.unwrap();
    link("owner", b.id).insert(db).await.unwrap();
    assert!(link("other", foreign.id).insert(db).await.is_err());
    let identity = vlan_supplicant::ActiveModel {
        creator: Set("other".into()),
        name: Set("supplicant".into()),
        age_recipient: Set("test".into()),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    assert!(
        vlan_grant::ActiveModel {
            creator: Set("owner".into()),
            vlan_id: Set(vlan.id),
            supplicant_id: Set(identity.id),
            slots: Set("2".into()),
            ..Default::default()
        }
        .insert(db)
        .await
        .is_err()
    );

    let b_id = b.id;
    let linked = [a.clone(), b]
        .as_slice()
        .load_many_to_many(vlan_network::Entity, confluence_vlan::Entity, db)
        .await
        .unwrap();
    assert_eq!(linked, vec![vec![vlan.clone()], vec![vlan.clone()]]);
    workspace::Entity::delete_by_id(a.id)
        .exec(db)
        .await
        .unwrap();
    assert_eq!(
        vlan_network::Entity::find_by_id(vlan.id)
            .one(db)
            .await
            .unwrap(),
        Some(vlan.clone())
    );
    vlan_network::Entity::delete_by_id(vlan.id)
        .exec(db)
        .await
        .unwrap();
    assert!(
        workspace::Entity::find_by_id(b_id)
            .one(db)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        confluence_vlan::Entity::find()
            .all(db)
            .await
            .unwrap()
            .is_empty()
    );
}
