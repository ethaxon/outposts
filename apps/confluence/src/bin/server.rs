use axum::{
    Router, handler::HandlerWithoutStateExt, http::Method, http::StatusCode, middleware,
    routing::delete, routing::get, routing::post, routing::put,
};
use confluence::auth::auth;
use confluence::auth::config_projection::get_oidc_config;

use confluence::config::{AppConfig, AuthConfig, parse_scopes};
use confluence::error::AppError;
use confluence::migrations;
use confluence::services::{
    AppState, create_one_confluence, create_one_profile, create_one_subscribe_source,
    delete_one_confluence, delete_one_profile, delete_one_subscribe_source, find_many_confluences,
    find_one_confluence, find_one_profile_as_subscription_by_token, mux_one_confluence,
    sync_one_confluence, sync_one_subscribe_source, update_one_confluence,
    update_one_confluence_cron, update_one_subscribe_source,
};
use confluence::tasks::init_backend_jobs;
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::MigratorTrait;
use securitydept_core::oauth_resource_server::{
    OAuthResourceServerConfig, OAuthResourceServerVerifier,
};
use securitydept_core::token_set_context::access_token_substrate::{
    AccessTokenSubstrateRuntime, TokenPropagation,
};
use std::env;
use std::sync::Arc;
use tokio_cron_scheduler::JobScheduler;
use tower_http::cors::{Any, CorsLayer};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ACCEPT};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

fn oidc_well_known_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    dotenvy::dotenv().ok();

    let db_url =
        env::var("CONFLUENCE_DATABASE_URL").expect("CONFLUENCE_DATABASE_URL is not set in env");

    let mut opt = ConnectOptions::new(db_url.clone());
    opt.set_schema_search_path("public")
        .max_connections(20)
        .min_connections(2)
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Debug);

    let conn = Database::connect(opt)
        .await
        .expect("Database connection failed");

    let auth_type = env::var("AUTH_TYPE").expect("AUTH_TYPE is not set in env");
    let listen = env::var("CONFLUENCE_LISTEN").unwrap_or_else(|_| String::from("0.0.0.0:4001"));

    {
        migrations::Migrator::up(&conn, None).await?;
    }

    let (auth, oidc_verifier, substrate_runtime) = match &auth_type as &str {
        "BASIC" => {
            tracing::info!("using basic authentication");
            let username =
                env::var("AUTH_BASIC_USERNAME").expect("AUTH_BASIC_USERNAME is not set in env");
            let password =
                env::var("AUTH_BASIC_PASSWORD").expect("AUTH_BASIC_PASSWORD is not set in env");
            (AuthConfig::BASIC { username, password }, None, None)
        }
        "OIDC" => {
            tracing::info!("using OIDC authentication with access-token substrate");
            let issuer = env::var("OIDC_ISSUER").expect("OIDC_ISSUER is not set in env");
            // Audience is optional: when absent, audience validation is skipped in the verifier.
            let audience = env::var("CONFLUENCE_OIDC_AUDIENCE").ok();
            let required_scopes = parse_scopes(
                &env::var("CONFLUENCE_OIDC_SCOPES")
                    .expect("CONFLUENCE_OIDC_SCOPES is not set in env"),
            );
            let user_claim =
                env::var("CONFLUENCE_OIDC_USER_CLAIM").unwrap_or_else(|_| "sub".to_string());
            // OIDC client_id that the frontend web application uses. The backend is a
            // pure resource server; this value is served via /api/auth/config so the
            // browser can bootstrap its auth flow without compile-time credentials.
            let frontend_client_id = env::var("OUTPOSTS_WEB_OIDC_CLIENT_ID")
                .expect("OUTPOSTS_WEB_OIDC_CLIENT_ID is not set in env");

            let mut verifier_config = OAuthResourceServerConfig::default();
            verifier_config.remote.well_known_url = Some(oidc_well_known_url(&issuer));
            if let Some(aud) = audience.clone() {
                verifier_config.audiences = vec![aud];
            }
            verifier_config.required_scopes = required_scopes.clone();

            let verifier = Arc::new(
                OAuthResourceServerVerifier::from_config(verifier_config)
                    .await
                    .map_err(AppError::from)?,
            );

            // Build the substrate runtime (propagation disabled — confluence does not
            // forward tokens downstream; propagation can be enabled in a future iteration).
            let runtime = AccessTokenSubstrateRuntime::new(&TokenPropagation::Disabled)
                .expect("substrate runtime with propagation disabled should always succeed");

            (
                AuthConfig::OIDC {
                    issuer,
                    audience: audience.unwrap_or_default(),
                    required_scopes,
                    user_claim,
                    frontend_client_id,
                },
                Some(verifier),
                Some(runtime),
            )
        }
        auth_type => {
            panic!("unsupported auth type {}", auth_type)
        }
    };

    let state = Arc::new(AppState::new(
        conn,
        AppConfig {
            listen,
            database_url: db_url,
            auth,
        },
        oidc_verifier,
        substrate_runtime,
    ));

    let mut job_scheduler = JobScheduler::new()
        .await
        .expect("failed to create backend task scheduler");

    init_backend_jobs(&mut job_scheduler, state.clone())
        .await
        .unwrap();

    tracing::info!("backend tasks initialized successfully");

    tokio::join!(serve(handle_confluence(state.clone()), state));
    Ok(())
}

async fn handle_health() -> (StatusCode, &'static str) {
    (StatusCode::OK, "OK")
}

async fn handle_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

fn handle_confluence(state: Arc<AppState>) -> Router {
    let confluence_api = Router::<Arc<AppState>>::new()
        .route("/", get(find_many_confluences).post(create_one_confluence))
        .route(
            "/{id}",
            get(find_one_confluence)
                .delete(delete_one_confluence)
                .put(update_one_confluence),
        )
        .route("/mux/{id}", post(mux_one_confluence))
        .route("/sync/{id}", post(sync_one_confluence))
        .route("/cron/{id}", post(update_one_confluence_cron))
        .layer(middleware::from_fn_with_state(state.clone(), auth));

    let profile_api = Router::<Arc<AppState>>::new()
        .route("/", post(create_one_profile))
        .route("/{id}", delete(delete_one_profile))
        .layer(middleware::from_fn_with_state(state.clone(), auth));

    let subscribe_source_api = Router::<Arc<AppState>>::new()
        .route("/", post(create_one_subscribe_source))
        .route(
            "/{id}",
            put(update_one_subscribe_source).delete(delete_one_subscribe_source),
        )
        .route("/sync/{id}", post(sync_one_subscribe_source))
        .layer(middleware::from_fn_with_state(state.clone(), auth));

    let profile_token_api = Router::<Arc<AppState>>::new()
        .route("/{token}", get(find_one_profile_as_subscription_by_token));

    let health_api = Router::<Arc<AppState>>::new().route("/", get(handle_health));

    // Unauthenticated: serves the OIDC client config projection to the browser
    // before the user has logged in. No private data is exposed.
    let auth_config_api = Router::<Arc<AppState>>::new()
        .route("/config", get(get_oidc_config));

    Router::<Arc<AppState>>::new()
        .nest("/api/profile", profile_api)
        .nest("/api/confluence", confluence_api)
        .nest("/api/subscribe_source", subscribe_source_api)
        .nest("/api/profile_token", profile_token_api)
        .nest("/api/health", health_api)
        .nest("/api/auth", auth_config_api)
        .fallback_service(handle_404.into_service())
        .with_state(state)
}

async fn serve(app: Router, state: Arc<AppState>) {
    let listener = tokio::net::TcpListener::bind(&state.config.listen)
        .await
        .unwrap_or_else(|_| panic!("failed to bind to address of {}", &state.config.listen));
    tracing::info!("listening on {}", listener.local_addr().unwrap());

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_origin(Any)
        // '*' wildcard does not cover Authorization per CORS spec; list it explicitly.
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT]);

    axum::serve(listener, app.layer(cors).layer(TraceLayer::new_for_http()))
        .await
        .unwrap();
}
