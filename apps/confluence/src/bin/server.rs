use axum::{
    Router, handler::HandlerWithoutStateExt, http::Method, http::StatusCode, middleware,
    routing::delete, routing::get, routing::post, routing::put,
};
use confluence::auth::auth;
use confluence::config::{AppConfig, AuthConfig};
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
use std::env;
use std::sync::Arc;
use tokio_cron_scheduler::JobScheduler;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            if cfg!(debug_assertions) || cfg!(test) {
                EnvFilter::new("debug")
            } else {
                EnvFilter::new("info")
            }
        }))
        .init();

    dotenvy::dotenv().ok();

    let db_url =
        env::var("CONFLUENCE_DATABASE_URL").expect("CONFLUENCE_DATABASE_URL is not set in env");

    let mut opt = ConnectOptions::new(db_url.clone());
    opt.set_schema_search_path("public")
        .max_connections(100)
        .min_connections(5)
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

    let state = Arc::new(AppState::new(
        conn,
        AppConfig {
            listen,
            database_url: db_url,
            auth: match &auth_type as &str {
                "BASIC" => {
                    let username = env::var("AUTH_BASIC_USERNAME")
                        .expect("AUTH_BASIC_USERNAME is not set in env");
                    let password = env::var("AUTH_BASIC_PASSWORD")
                        .expect("AUTH_BASIC_PASSWORD is not set in env");
                    AuthConfig::BASIC { username, password }
                }
                "OIDC" => {
                    let issuer = env::var("AUTH_ISSUER").expect("AUTH_ISSUER is not set in env");
                    let audience = env::var("CONFLUENCE_API_ENDPOINT")
                        .expect("CONFLUENCE_API_ENDPOINT is not set in env");
                    AuthConfig::OIDC { issuer, audience }
                }
                auth_type => {
                    panic!("unsupported auth type {}", auth_type)
                }
            },
        },
    ));

    let mut job_scheduler = JobScheduler::new()
        .await
        .expect("failed to create backend task scheduler");

    init_backend_jobs(&mut job_scheduler, state.clone())
        .await
        .unwrap();

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

    Router::<Arc<AppState>>::new()
        .nest("/api/profile", profile_api)
        .nest("/api/confluence", confluence_api)
        .nest("/api/subscribe_source", subscribe_source_api)
        .nest("/api/profile_token", profile_token_api)
        .nest("/api/health", health_api)
        .fallback_service(handle_404.into_service())
        .with_state(state)
}

async fn serve(app: Router, state: Arc<AppState>) {
    let listener = tokio::net::TcpListener::bind(&state.config.listen)
        .await
        .unwrap_or_else(|_| panic!("failed to bind to address of {}", &state.config.listen));
    tracing::info!("listening on {}", listener.local_addr().unwrap());

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        // allow requests from any origin
        .allow_origin(Any)
        .allow_headers(Any);

    axum::serve(listener, app.layer(cors).layer(TraceLayer::new_for_http()))
        .await
        .unwrap();
}
