use confluence::migrations::{Migrator, MigratorTrait, SchemaManager};
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
    let legacy_steps = Migrator::migrations()
        .iter()
        .position(|migration| migration.name() == "m20261117_000001_uuidv7_primary_keys")
        .unwrap() as u32;
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
    Migrator::up(&db, Some(1)).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    verify_wireguard_schema(&db).await;
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
    assert!(
        source::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .last_sync_error
            .is_none()
    );
    verify_migration_rollback(&db, token).await;
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
    verify_subscription_source_refresh(&db).await;
}

async fn verify_migration_rollback(db: &sea_orm::DatabaseConnection, token: &str) {
    Migrator::down(db, Some(1)).await.unwrap();
    let schema = SchemaManager::new(db);
    for table in [
        "profile_supplicant",
        "confluence_vlan",
        "vlan_network",
        "vlan_supplicant",
        "vlan_grant",
        "vlan_route",
        "vlan_tunnel",
        "vlan_tunnel_grant",
        "vlan_wireguard_peer",
    ] {
        assert!(!schema.has_table(table).await.unwrap(), "{table}");
    }
    for (table, column) in [
        ("profile", "allow_unsafe_age_private_key"),
        ("subscribe_source", "last_sync_error"),
    ] {
        assert!(
            !schema.has_column(table, column).await.unwrap(),
            "{table}.{column}"
        );
    }
    assert_eq!(Migrator::get_pending_migrations(db).await.unwrap().len(), 1);

    // An external reference must block the UUID rollback without a partial rewrite.
    db.execute_unprepared("CREATE VIEW current_workspace_ids AS SELECT id FROM confluence")
        .await
        .unwrap();
    let error = Migrator::down(db, Some(1)).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("because other objects depend on it"),
        "{error}"
    );
    db.execute_unprepared("DROP VIEW current_workspace_ids")
        .await
        .unwrap();

    Migrator::down(db, Some(1)).await.unwrap();
    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            r#"
            SELECT c.id AS workspace_id, p.id AS profile_id, s.id AS source_id, p.resource_token,
                (
                    c.created_at = timestamp '1970-01-01' AND c.updated_at = c.created_at
                    AND p.created_at = c.created_at AND p.updated_at = c.created_at
                    AND s.created_at = c.created_at AND s.updated_at = c.created_at
                ) AS timestamps_preserved
            FROM confluence c
            JOIN profile p ON p.confluence_id = c.id
            JOIN subscribe_source s ON s.confluence_id = c.id
            WHERE c.name = 'legacy workspace' AND s.name = 'legacy source'
            "#,
        ))
        .await
        .unwrap();
    let [row] = rows.as_slice() else {
        panic!("Integer rollback must preserve the original relations");
    };
    for id in ["workspace_id", "profile_id", "source_id"] {
        assert!(row.try_get::<i32>("", id).unwrap() > 0);
    }
    assert_eq!(row.try_get::<String>("", "resource_token").unwrap(), token);
    assert!(row.try_get::<bool>("", "timestamps_preserved").unwrap());
    assert_eq!(Migrator::get_pending_migrations(db).await.unwrap().len(), 2);

    // Default inserts on all three tables must allocate IDs beyond the backfill.
    db.execute_unprepared(
        r#"
        INSERT INTO confluence (creator, name, template, mux_content)
        VALUES ('migration-test', 'sequence probe', '', '');
        INSERT INTO profile (confluence_id, resource_token)
        SELECT id, 'temporary-token' FROM confluence WHERE name = 'sequence probe';
        INSERT INTO subscribe_source (confluence_id, url, name, content)
        SELECT id, 'https://example.com/probe', 'sequence probe', ''
        FROM confluence WHERE name = 'sequence probe';
        DELETE FROM confluence WHERE name = 'sequence probe';
        "#,
    )
    .await
    .unwrap();

    Migrator::up(db, None).await.unwrap();
}

async fn verify_subscription_source_refresh(db: &sea_orm::DatabaseConnection) {
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Json, Router};
    use confluence::auth::CurrentUser;
    use confluence::config::{AppConfig, AuthConfig};
    use confluence::models::subscribe_source::SubscribeSourceSyncErrorKind::*;
    use confluence::services::{
        AppState, find_many_confluences, find_one_confluence, mux_one_confluence_impl,
        sync_one_subscribe_source,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const ORIGINAL: &str = "proxies:\n  - {name: first, server: first.example.com, type: ss}\n";
    const RECOVERY: &str = "proxies:\n  - {name: next, server: next.example.com, type: ss}\n";
    let cases = [
        (StatusCode::OK, "proxies: [".to_string(), InvalidYaml),
        (
            StatusCode::OK,
            "<html>try again</html>".to_string(),
            MissingProxies,
        ),
        (StatusCode::OK, "proxies: []".to_string(), MissingProxies),
        (
            StatusCode::OK,
            "proxies: [invalid]".to_string(),
            InvalidConfig,
        ),
        (
            StatusCode::BAD_GATEWAY,
            "\0".to_string() + &"错".repeat(30_000),
            HttpStatus,
        ),
    ];
    let responses = std::iter::once((StatusCode::OK, ORIGINAL.to_owned(), "download=42"))
        .chain(
            cases
                .iter()
                .map(|(status, body, _)| (*status, body.clone(), "download=999")),
        )
        .chain(std::iter::once((
            StatusCode::OK,
            RECOVERY.to_owned(),
            "download=55",
        )))
        .collect::<VecDeque<_>>();
    let responses = Arc::new(Mutex::new(responses));
    let upstream = Router::new().route(
        "/subscription",
        get(move || {
            let (status, body, usage) = responses.lock().unwrap().pop_front().unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("subscription-userinfo", HeaderValue::from_static(usage));
            headers.append("x-upstream", HeaderValue::from_static("one"));
            headers.append("x-upstream", HeaderValue::from_static("two"));
            async move { (status, headers, body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let user = CurrentUser {
        user_id: "refresh-test".into(),
    };
    let state = Arc::new(AppState::new(
        db.clone(),
        AppConfig {
            listen: String::new(),
            auth: AuthConfig::DEV {
                user_id: user.user_id.clone(),
            },
            database_url: String::new(),
        },
        None,
        None,
    ));
    let cm = workspace::ActiveModel {
        creator: Set(user.user_id.clone()),
        name: Set("Refresh workspace".into()),
        template: Set("proxies: []\nproxy-groups: []\nrules: []\n".into()),
        mux_content: Set(String::new()),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    let sm = source::ActiveModel {
        confluence_id: Set(cm.id),
        name: Set("Provider".into()),
        url: Set(format!("http://{address}/subscription")),
        content: Set(String::new()),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    let source_id = sm.id;
    let sync = || {
        sync_one_subscribe_source(
            State(state.clone()),
            Extension(user.clone()),
            Path(source_id),
        )
    };
    let Json(synced) = sync().await.unwrap();
    assert_eq!(synced.content, ORIGINAL);
    assert_eq!(synced.sub_download, Some(42));
    for (status, body, kind) in cases {
        let Json(stale) = sync().await.unwrap();
        assert_eq!(stale.content, ORIGINAL);
        assert_eq!(stale.sub_download, Some(42));
        let persisted = source::Entity::find_by_id(source_id)
            .one(db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.last_sync_error, stale.last_sync_error);
        let error = stale.last_sync_error.unwrap();
        assert_eq!(error.kind, kind);
        assert_eq!(error.status, Some(status.as_u16()));
        let upstream_headers = error
            .headers
            .iter()
            .filter(|(name, _)| name == "x-upstream")
            .count();
        assert_eq!(upstream_headers, 2);
        let saved_body = error.body.unwrap();
        if kind == HttpStatus {
            assert!(error.body_truncated);
            assert!(saved_body.starts_with('\u{FFFD}'));
            assert!(saved_body.len() <= 64 * 1024);
        } else {
            assert!(!error.body_truncated);
            assert_eq!(saved_body, body);
        }
    }
    let stale = source::Entity::find_by_id(source_id)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    let (muxed, _, _) = mux_one_confluence_impl(db, cm.clone(), vec![stale], vec![])
        .await
        .unwrap();
    assert!(muxed.mux_content.contains("first.example.com"));
    let Json(recovered) = sync().await.unwrap();
    assert_eq!(recovered.content, RECOVERY);
    assert_eq!(recovered.sub_download, Some(55));
    assert!(recovered.last_sync_error.is_none());
    server.abort();

    let older = chrono::DateTime::from_timestamp(1, 0).unwrap().naive_utc();
    let older_source = |id, name: &str| source::ActiveModel {
        id: Set(id),
        confluence_id: Set(cm.id),
        name: Set(name.into()),
        created_at: Set(older),
        url: Set(String::new()),
        content: Set(String::new()),
        ..Default::default()
    };
    let first = uuid::Uuid::from_u128(1);
    let second = uuid::Uuid::from_u128(2);
    older_source(second, "Second").insert(db).await.unwrap();
    older_source(first, "First").insert(db).await.unwrap();
    let Json(workspace) =
        find_one_confluence(Path(cm.id), Extension(user.clone()), State(state.clone()))
            .await
            .unwrap();
    let Json(mut workspaces) = find_many_confluences(Extension(user), State(state))
        .await
        .unwrap();
    for dto in [workspace, workspaces.pop().unwrap()] {
        let ids = dto
            .subscribe_sources
            .into_iter()
            .map(|source| source.id)
            .collect::<Vec<_>>();
        assert_eq!(ids, [first, second, source_id]);
    }
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

async fn verify_wireguard_schema(db: &sea_orm::DatabaseConnection) {
    use confluence::models::{vlan_route, vlan_tunnel, vlan_tunnel_grant, vlan_wireguard_peer};

    const VLAN_ID: uuid::Uuid = uuid::uuid!("00000000-0000-7000-8000-000000000001");
    const FIRST_MEMBER: uuid::Uuid = uuid::uuid!("00000000-0000-7000-8000-000000000002");
    const SECOND_MEMBER: uuid::Uuid = uuid::uuid!("00000000-0000-7000-8000-000000000006");
    db.execute_unprepared(
        r#"
        INSERT INTO vlan_network (id, creator, name, enabled)
        VALUES ('00000000-0000-7000-8000-000000000001', 'migration-test', 'migration-vlan', true);
        INSERT INTO vlan_supplicant (id, creator, name, age_recipient)
        VALUES ('00000000-0000-7000-8000-000000000002', 'migration-test', 'first-member', 'fixture'),
               ('00000000-0000-7000-8000-000000000006', 'migration-test', 'second-member', 'fixture');
        INSERT INTO confluence_vlan (creator, confluence_id, vlan_id)
        SELECT creator, id, '00000000-0000-7000-8000-000000000001' FROM confluence WHERE name = 'legacy workspace';
        INSERT INTO vlan_grant (creator, vlan_id, supplicant_id)
        VALUES ('migration-test', '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-000000000002'),
               ('migration-test', '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-000000000006');
        INSERT INTO vlan_route (vlan_id, cidr)
        VALUES ('00000000-0000-7000-8000-000000000001', '198.51.100.0/24');
        "#,
    )
    .await
    .unwrap();

    let tunnel = vlan_tunnel::ActiveModel {
        creator: Set("migration-test".into()),
        vlan_id: Set(VLAN_ID),
        name: Set("wireguard".into()),
        addresses: Set(vec!["10.64.0.2/32".into()]),
        persistent_keepalive: Set(Some(25)),
        private_key: Set("fixture-client-key".into()),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    assert_eq!(tunnel.id.get_version_num(), 7);

    let grant = |creator: &str, supplicant_id| vlan_tunnel_grant::ActiveModel {
        creator: Set(creator.into()),
        vlan_id: Set(VLAN_ID),
        tunnel_id: Set(tunnel.id),
        supplicant_id: Set(supplicant_id),
        ..Default::default()
    };
    grant("migration-test", FIRST_MEMBER)
        .insert(db)
        .await
        .unwrap();
    assert!(grant("other", SECOND_MEMBER).insert(db).await.is_err());
    grant("migration-test", SECOND_MEMBER)
        .insert(db)
        .await
        .unwrap();
    assert!(
        grant("migration-test", FIRST_MEMBER)
            .insert(db)
            .await
            .is_err()
    );
    let peer = |allowed_ips| vlan_wireguard_peer::ActiveModel {
        tunnel_id: Set(tunnel.id),
        position: Set(0),
        server: Set("192.0.2.2".into()),
        port: Set(51820),
        public_key: Set("fixture-peer-key".into()),
        pre_shared_key: Set(Some("fixture-psk".into())),
        allowed_ips: Set(allowed_ips),
        ..Default::default()
    };
    assert!(peer(vec![]).insert(db).await.is_err());
    let peer = peer(vec!["198.51.100.0/24".into()])
        .insert(db)
        .await
        .unwrap();

    assert_eq!(
        vlan_tunnel::Entity::find().all(db).await.unwrap(),
        std::slice::from_ref(&tunnel)
    );
    assert_eq!(
        vlan_wireguard_peer::Entity::find().all(db).await.unwrap(),
        [peer]
    );
    assert_eq!(
        vlan_tunnel_grant::Entity::find()
            .all(db)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(vlan_route::Entity::find().all(db).await.unwrap().len(), 1);
    assert_eq!(
        confluence_vlan::Entity::find().all(db).await.unwrap().len(),
        1
    );
    for table in ["vlan_gateway", "vlan_wireguard_config", "vlan_tunnel_next"] {
        assert!(!SchemaManager::new(db).has_table(table).await.unwrap());
    }
    for (table, column) in [
        ("vlan_grant", "slots"),
        ("vlan_tunnel_grant", "slots"),
        ("vlan_tunnel", "kind"),
    ] {
        assert!(
            !SchemaManager::new(db)
                .has_column(table, column)
                .await
                .unwrap()
        );
    }

    db.execute_unprepared("DELETE FROM vlan_grant WHERE creator = 'migration-test'")
        .await
        .unwrap();
    assert!(
        vlan_tunnel_grant::Entity::find()
            .all(db)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(vlan_tunnel::Entity::find().all(db).await.unwrap(), [tunnel]);
    db.execute_unprepared("DELETE FROM vlan_network WHERE name = 'migration-vlan'")
        .await
        .unwrap();
    assert!(
        vlan_tunnel::Entity::find()
            .all(db)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        vlan_wireguard_peer::Entity::find()
            .all(db)
            .await
            .unwrap()
            .is_empty()
    );

    verify_config_management(db).await;
    verify_profile_encryption(db).await;
}

async fn verify_config_management(db: &sea_orm::DatabaseConnection) {
    use std::sync::Arc;

    use axum::{
        Extension, Json,
        extract::{Path, State},
    };
    use confluence::{
        auth::CurrentUser,
        config::{AppConfig, AuthConfig},
        models::vlan_tunnel,
        services::AppState,
        vlan::{VlanGrant, VlanNetwork},
        vlan_services::{create_network, list_catalog, update_network},
    };

    let user = CurrentUser {
        user_id: "migration-test".into(),
    };
    let state = Arc::new(AppState::new(
        db.clone(),
        AppConfig {
            listen: String::new(),
            auth: AuthConfig::DEV {
                user_id: user.user_id.clone(),
            },
            database_url: String::new(),
        },
        None,
        None,
    ));
    let private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let input: VlanNetwork = serde_json::from_value(serde_json::json!({
        "id": "",
        "network": "config-test",
        "enabled": true,
        "routes": ["198.51.100.0/24"],
        "accept_supplicants": [],
        "tunnels": [{
            "id": "",
            "name": "vpn",
            "supplicant_ids": [],
            "config": {
                "addresses": ["192.0.2.2/32"],
                "private_key": private_key,
                "peers": [{
                    "server": "192.0.2.1",
                    "port": 51820,
                    "public_key": private_key,
                    "allowed_ips": ["198.51.100.0/24"]
                }]
            }
        }]
    }))
    .unwrap();

    let (_, Json(mut saved)) =
        create_network(State(state.clone()), Extension(user.clone()), Json(input))
            .await
            .unwrap();
    let id = saved.id.parse().unwrap();
    let tunnel = &mut saved.tunnels[0];
    let tunnel_id: uuid::Uuid = tunnel.id.parse().unwrap();
    assert!(tunnel.supplicant_ids.is_empty());
    assert!(tunnel.config.has_private_key);
    assert!(tunnel.config.private_key.is_none());

    for suffix in ["2", "6"] {
        let supplicant_id = format!("00000000-0000-7000-8000-00000000000{suffix}");
        tunnel.supplicant_ids.push(supplicant_id.clone());
        saved.accept_supplicants.push(VlanGrant { supplicant_id });
    }
    let Json(assigned) = update_network(
        State(state.clone()),
        Extension(user.clone()),
        Path(id),
        Json(saved),
    )
    .await
    .unwrap();
    let Json(catalog) = list_catalog(State(state.clone()), Extension(user.clone()))
        .await
        .unwrap();
    assert_eq!(catalog.vlan_configs, std::slice::from_ref(&assigned));
    assert_eq!(assigned.tunnels[0].supplicant_ids.len(), 2);
    assert_eq!(
        vlan_tunnel::Entity::find_by_id(tunnel_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .private_key,
        private_key,
    );

    let mut revoked = assigned;
    revoked.accept_supplicants.clear();
    revoked.tunnels[0].supplicant_ids.clear();
    let Json(saved) = update_network(
        State(state),
        Extension(user),
        Path(id),
        Json(revoked.clone()),
    )
    .await
    .unwrap();
    assert_eq!(saved, revoked);
    db.execute_unprepared("DELETE FROM vlan_network WHERE name = 'config-test'")
        .await
        .unwrap();
}

async fn verify_profile_encryption(db: &sea_orm::DatabaseConnection) {
    use std::{io::Read, sync::Arc};

    use age::secrecy::ExposeSecret;
    use axum::{
        Extension, Json,
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, header},
    };
    use confluence::{
        auth::CurrentUser,
        config::{AppConfig, AuthConfig},
        dto::{
            ConfluenceVlansUpdateDto, ProfileCreationDto, ProfilePreviewRequestDto,
            ProfileUpdateDto,
        },
        services::{
            AppState, create_one_confluence, create_one_profile, delete_one_confluence,
            find_many_confluences, find_one_confluence, find_one_profile_as_subscription_by_token,
            preview_one_profile, update_one_profile,
        },
        vlan::{
            VlanGrant, VlanNetwork, VlanSupplicant, VlanTunnel, WireGuardClientConfig,
            WireGuardPeer,
        },
        vlan_services::{
            create_network, create_supplicant, delete_supplicant, list_supplicants,
            update_confluence_vlans,
        },
    };

    fn decrypt(ciphertext: &str, identity: &age::x25519::Identity) -> Option<String> {
        let armor = age::armor::ArmoredReader::new(ciphertext.as_bytes());
        let mut reader = age::Decryptor::new(armor)
            .ok()?
            .decrypt(std::iter::once(identity as &dyn age::Identity))
            .ok()?;
        let mut plaintext = String::new();
        reader.read_to_string(&mut plaintext).ok()?;
        Some(plaintext)
    }

    let user = CurrentUser {
        user_id: "profile-owner".into(),
    };
    let other = CurrentUser {
        user_id: "other-owner".into(),
    };
    let state = Arc::new(AppState::new(
        db.clone(),
        AppConfig {
            listen: String::new(),
            auth: AuthConfig::DEV {
                user_id: user.user_id.clone(),
            },
            database_url: String::new(),
        },
        None,
        None,
    ));
    let mut supplicants = Vec::new();
    for (owner, name) in [
        (&user, "alice"),
        (&user, "bob"),
        (&user, "eve"),
        (&other, "foreign"),
    ] {
        let key = age::x25519::Identity::generate();
        let (_, Json(supplicant)) = create_supplicant(
            State(state.clone()),
            Extension(owner.clone()),
            Json(VlanSupplicant {
                id: String::new(),
                name: name.into(),
                age_recipient: key.to_public().to_string(),
            }),
        )
        .await
        .unwrap();
        supplicants.push((supplicant.id.parse::<uuid::Uuid>().unwrap(), key));
    }
    let [
        (alice_id, alice),
        (bob_id, bob),
        (eve_id, eve),
        (foreign_id, _),
    ] = supplicants.as_slice()
    else {
        unreachable!()
    };
    let (_, Json(workspace)) = create_one_confluence(Extension(user.clone()), State(state.clone()))
        .await
        .unwrap();
    let row = workspace::Entity::find_by_id(workspace.id)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    let mut row: workspace::ActiveModel = row.into();
    let yaml = "proxies: []\n";
    row.mux_content = Set(yaml.into());
    row.update(db).await.unwrap();

    let (_, Json(vlan)) = create_network(
        State(state.clone()),
        Extension(user.clone()),
        Json(VlanNetwork {
            id: String::new(),
            enabled: true,
            network: "office".into(),
            routes: vec!["203.0.113.0/24".into()],
            tunnels: vec![],
            accept_supplicants: [alice_id, eve_id]
                .map(|id| VlanGrant {
                    supplicant_id: id.to_string(),
                })
                .to_vec(),
        }),
    )
    .await
    .unwrap();
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
    let tunnel = |name: &str, supplicant_ids| VlanTunnel {
        id: String::new(),
        name: name.into(),
        supplicant_ids,
        config: WireGuardClientConfig {
            addresses: vec!["192.0.2.3/32".into()],
            mtu: None,
            persistent_keepalive: None,
            private_key: Some(key.clone()),
            has_private_key: false,
            peers: vec![WireGuardPeer {
                server: "192.0.2.5".into(),
                port: 51820,
                public_key: key.clone(),
                allowed_ips: vec!["198.51.100.0/24".into()],
                pre_shared_key: None,
                has_pre_shared_key: false,
            }],
        },
    };
    let both = vec![alice_id.to_string(), bob_id.to_string()];
    let (_, Json(shared)) = create_network(
        State(state.clone()),
        Extension(user.clone()),
        Json(VlanNetwork {
            id: String::new(),
            enabled: true,
            network: "lab".into(),
            routes: vec!["198.51.100.0/24".into()],
            tunnels: vec![
                tunnel("common", both.clone()),
                tunnel("private", vec![alice_id.to_string()]),
            ],
            accept_supplicants: both
                .into_iter()
                .map(|supplicant_id| VlanGrant { supplicant_id })
                .collect(),
        }),
    )
    .await
    .unwrap();
    let Json(profile) = create_one_profile(
        State(state.clone()),
        Extension(user.clone()),
        Json(ProfileCreationDto {
            confluence_id: workspace.id,
            transform_script: None,
            age_supplicant_ids: Some(vec![*alice_id, *bob_id]),
            allow_unsafe_age_private_key: None,
        }),
    )
    .await
    .unwrap();
    let mut expected = vec![*alice_id, *bob_id];
    expected.sort();
    assert_eq!(profile.age_supplicant_ids, expected);
    assert!(!profile.allow_unsafe_age_private_key);
    let Json(detail) = find_one_confluence(
        Path(workspace.id),
        Extension(user.clone()),
        State(state.clone()),
    )
    .await
    .unwrap();
    let Json(list) = find_many_confluences(Extension(user.clone()), State(state.clone()))
        .await
        .unwrap();
    assert_eq!(detail.profiles, std::slice::from_ref(&profile));
    assert_eq!(list[0].profiles, std::slice::from_ref(&profile));

    let fetch_with_ua = |query: &str, ua: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, ua.parse().unwrap());
        find_one_profile_as_subscription_by_token(
            Path(profile.resource_token.clone()),
            State(state.clone()),
            headers,
            format!("/subscription/{}{query}", profile.resource_token)
                .parse()
                .unwrap(),
            Bytes::new(),
        )
    };
    let fetch = |query: &str| fetch_with_ua(query, "TestClient/1");
    let (headers, ciphertext) = fetch("").await.unwrap();
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    assert!(headers.get(header::ETAG).is_none());
    assert_eq!(decrypt(&ciphertext, alice).as_deref(), Some(yaml));
    assert_eq!(decrypt(&ciphertext, bob).as_deref(), Some(yaml));
    assert!(decrypt(&ciphertext, eve).is_none());

    let Json(linked_vlans) = update_confluence_vlans(
        State(state.clone()),
        Extension(user.clone()),
        Path(workspace.id),
        Json(ConfluenceVlansUpdateDto {
            vlan_ids: vec![vlan.id.parse().unwrap(), shared.id.parse().unwrap()],
        }),
    )
    .await
    .unwrap();
    assert_eq!(linked_vlans.len(), 2);
    let Json(supplicants) = list_supplicants(State(state.clone()), Extension(user.clone()))
        .await
        .unwrap();
    assert_eq!(
        supplicants
            .iter()
            .map(|row| (
                row.supplicant.name.as_str(),
                row.vlan_count,
                row.profile_count
            ))
            .collect::<Vec<_>>(),
        [("alice", 2, 1), ("bob", 1, 1), ("eve", 1, 0)]
    );
    let (_, default_ciphertext) = fetch("").await.unwrap();
    let default_yaml = decrypt(&default_ciphertext, alice).unwrap();
    assert_eq!(
        decrypt(&default_ciphertext, bob).as_deref(),
        Some(default_yaml.as_str())
    );
    assert!(default_yaml.contains("VLAN-lab-COMMON-WG"));
    assert!(!default_yaml.contains("VLAN-lab-PRIVATE-WG"));
    assert!(!default_yaml.contains("VLAN-office"));
    assert!(decrypt(&default_ciphertext, eve).is_none());

    let shared_query = "?supplicants=bob,alice&vlans=lab";
    let (_, shared_ciphertext) = fetch(shared_query).await.unwrap();
    assert_eq!(
        decrypt(&shared_ciphertext, alice).as_deref(),
        Some(default_yaml.as_str())
    );
    assert_eq!(
        decrypt(&shared_ciphertext, bob).as_deref(),
        Some(default_yaml.as_str())
    );
    assert!(fetch("?supplicants=alice,bob&vlans=office").await.is_err());
    assert!(fetch("?supplicant=alice&vlans=office").await.is_err());
    let (_, solo_ciphertext) = fetch("?supplicants=alice").await.unwrap();
    let solo_yaml = decrypt(&solo_ciphertext, alice).unwrap();
    assert!(solo_yaml.contains("VLAN-office"));
    assert!(solo_yaml.contains("VLAN-lab-PRIVATE-WG"));
    assert!(decrypt(&solo_ciphertext, bob).is_none());

    let Json(preview) = preview_one_profile(
        Path(profile.id),
        State(state.clone()),
        Extension(user.clone()),
        Json(ProfilePreviewRequestDto {
            url: format!("https://example.test/subscription{shared_query}"),
            headers: Default::default(),
            body: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(preview.supplicants, ["alice", "bob"]);
    assert_eq!(preview.recipients, ["alice", "bob"]);
    assert_eq!(preview.vlans, ["lab"]);
    assert_eq!(preview.plaintext, default_yaml);
    assert_eq!(
        decrypt(preview.encrypted.as_deref().unwrap(), bob).unwrap(),
        preview.plaintext
    );

    let (_, vlan_ciphertext) = fetch("?supplicants=alice&vlans=office").await.unwrap();
    assert!(
        decrypt(&vlan_ciphertext, alice)
            .unwrap()
            .contains("VLAN-office")
    );
    assert!(decrypt(&vlan_ciphertext, bob).is_none());
    assert!(
        fetch("?supplicants=eve&vlans=office")
            .await
            .unwrap_err()
            .to_string()
            .contains("this Profile")
    );
    assert!(
        fetch("?supplicants=bob&vlans=office")
            .await
            .unwrap_err()
            .to_string()
            .contains("accepted by this VLAN")
    );
    assert!(
        delete_supplicant(State(state.clone()), Extension(user.clone()), Path(*bob_id))
            .await
            .is_err()
    );

    let update = |ids, allow_unsafe_age_private_key, transform_script| {
        update_one_profile(
            Path(profile.id),
            State(state.clone()),
            Extension(user.clone()),
            Json(ProfileUpdateDto {
                transform_script,
                age_supplicant_ids: ids,
                allow_unsafe_age_private_key,
            }),
        )
    };
    assert!(update(Some(vec![*foreign_id]), None, None).await.is_err());
    let Json(unchanged) = update(None, None, None).await.unwrap();
    assert_eq!(unchanged.age_supplicant_ids, expected);

    let alice_key = alice.to_string();
    let bob_key = bob.to_string();
    let eve_key = eve.to_string();
    let age_request = |name: &str, scope: &str, key: &str| {
        format!(
            "TestClient/1 confluence/supplicants={name}{scope}&_unsafe_supplicant_private={key}"
        )
    };
    let profile_ua = age_request("alice", "", alice_key.expose_secret());
    let vlan_ua = age_request("alice", "&vlans=office", alice_key.expose_secret());
    let multi_ua = age_request("alice,bob", "", alice_key.expose_secret());
    assert!(fetch_with_ua("", &vlan_ua).await.is_err());
    let Json(enabled) = update(
        None,
        Some(true),
        Some("export default (ctx) => ({...ctx.profile, 'x-test-user-agent': ctx.request.headers['user-agent']})".into()),
    )
    .await
    .unwrap();
    assert!(enabled.allow_unsafe_age_private_key);
    assert_eq!(enabled.age_supplicant_ids, expected);
    assert!(
        fetch_with_ua("", &multi_ua)
            .await
            .unwrap_err()
            .to_string()
            .contains("exactly one")
    );

    let (headers, plaintext) = fetch_with_ua("", &profile_ua).await.unwrap();
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    assert!(headers.get(header::ETAG).is_none());
    let plaintext: serde_json::Value = serde_yaml::from_str(&plaintext).unwrap();
    assert_eq!(
        plaintext["x-test-user-agent"],
        "TestClient/1 confluence/supplicants=alice"
    );

    let (headers, plaintext) = fetch_with_ua("?supplicants=alice&vlans=office", &vlan_ua)
        .await
        .unwrap();
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    let plaintext: serde_json::Value = serde_yaml::from_str(&plaintext).unwrap();
    assert_eq!(plaintext["proxy-groups"][0]["name"], "VLAN-office");
    assert_eq!(
        plaintext["x-test-user-agent"],
        "TestClient/1 confluence/supplicants=alice&vlans=office"
    );
    assert!(
        fetch_with_ua("?supplicants=alice&vlans=unknown", &vlan_ua)
            .await
            .is_err()
    );
    for (name, key) in [("alice", &bob_key), ("bob", &bob_key), ("eve", &eve_key)] {
        let ua = age_request(name, "&vlans=office", key.expose_secret());
        assert!(fetch_with_ua("", &ua).await.is_err());
    }
    let query = format!(
        "?supplicants=alice&vlans=office&%5Funsafe_supplicant_private={}",
        alice_key.expose_secret()
    );
    let rejected = fetch(&query).await.unwrap_err().to_string();
    assert!(rejected.contains("only in User-Agent"));
    assert!(!rejected.contains(alice_key.expose_secret()));

    let Json(cleared) = update(Some(vec![]), None, Some(String::new()))
        .await
        .unwrap();
    assert!(cleared.age_supplicant_ids.is_empty());
    assert_eq!(fetch("").await.unwrap().1, yaml);
    assert!(fetch("?supplicants=eve&vlans=office").await.is_err());
    assert!(fetch("?vlans=lab").await.is_err());
    assert!(fetch_with_ua("", &vlan_ua).await.is_err());
    assert!(fetch_with_ua("", &profile_ua).await.is_err());
    let Json(disabled) = update(None, Some(false), None).await.unwrap();
    assert!(!disabled.allow_unsafe_age_private_key);
    assert!(fetch_with_ua("", &vlan_ua).await.is_err());

    delete_one_confluence(
        State(state.clone()),
        Extension(user.clone()),
        Path(workspace.id),
    )
    .await
    .unwrap();
    for network in [vlan, shared] {
        confluence::vlan_services::delete_network(
            State(state.clone()),
            Extension(user.clone()),
            Path(network.id.parse().unwrap()),
        )
        .await
        .unwrap();
    }
}
