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
use std::net::IpAddr;
use std::net::SocketAddr;
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
    let host = env::var("CONFLUENCE_HOST").unwrap_or_else(|_| String::from("0.0.0.0"));
    let port = env::var("CONFLUENCE_PORT").map_or(4001u16, |p| p.parse::<u16>().unwrap());

    {
        migrations::Migrator::up(&conn, None).await?;
    }

    let state = Arc::new(AppState::new(
        conn,
        AppConfig {
            port,
            host,
            database_url: db_url,
            auth: match &auth_type as &str {
                "DEV_NO_AUTH" => {
                    let user_id =
                        env::var("AUTH_DEV_USER_ID").expect("AUTH_DEV_USER_ID is not set in env");
                    AuthConfig::DevNoAuth { user_id }
                }
                "JWT" => {
                    let issuer = env::var("AUTH_ISSUER").expect("AUTH_ISSUER is not set in env");
                    let jwks_uri =
                        env::var("AUTH_JWKS_URI").expect("AUTH_JWKS_URI is not set in env");
                    let audience = env::var("CONFLUENCE_API_ENDPOINT")
                        .expect("CONFLUENCE_API_ENDPOINT is not set in env");
                    AuthConfig::JWT {
                        jwks_uri,
                        issuer,
                        audience,
                    }
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
    let addr = SocketAddr::from((
        state.config.host.parse::<IpAddr>().unwrap(),
        state.config.port,
    ));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
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
