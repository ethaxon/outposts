use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use sea_orm::{AccessMode, IsolationLevel, TransactionTrait};
use uuid::Uuid;

use crate::{
    auth::CurrentUser,
    dto::WorkspaceVlansUpdateDto,
    error::AppError,
    models::{confluence_vlan, vlan_network, vlan_supplicant},
    services::AppState,
    vlan::{VlanConfig, VlanNetwork, VlanSupplicant, aggregate_routes},
};

pub async fn aggregate_vlan_routes(
    Json(routes): Json<Vec<String>>,
) -> Result<Json<Vec<String>>, AppError> {
    Ok(Json(aggregate_routes(&routes)?))
}

pub async fn list_catalog(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<VlanConfig>, AppError> {
    let tx = state
        .conn
        .begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await?;
    let vlan_configs = vlan_network::Entity::list_owned(&tx, &user.user_id).await?;
    let supplicant_configs = vlan_supplicant::Entity::list_owned(&tx, &user.user_id).await?;
    tx.commit().await?;
    Ok(Json(VlanConfig {
        vlan_configs,
        supplicant_configs,
    }))
}

pub async fn create_network(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Json(input): Json<VlanNetwork>,
) -> Result<(StatusCode, Json<VlanNetwork>), AppError> {
    let saved = vlan_network::Entity::save_owned(&state.conn, &user.user_id, None, input).await?;
    Ok((StatusCode::CREATED, Json(saved)))
}

pub async fn update_network(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<VlanNetwork>,
) -> Result<Json<VlanNetwork>, AppError> {
    Ok(Json(
        vlan_network::Entity::save_owned(&state.conn, &user.user_id, Some(id), input).await?,
    ))
}

pub async fn delete_network(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    vlan_network::Entity::delete_owned(&state.conn, &user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_supplicant(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Json(input): Json<VlanSupplicant>,
) -> Result<(StatusCode, Json<VlanSupplicant>), AppError> {
    let saved =
        vlan_supplicant::Entity::save_owned(&state.conn, &user.user_id, None, input).await?;
    Ok((StatusCode::CREATED, Json(saved)))
}

pub async fn update_supplicant(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<VlanSupplicant>,
) -> Result<Json<VlanSupplicant>, AppError> {
    Ok(Json(
        vlan_supplicant::Entity::save_owned(&state.conn, &user.user_id, Some(id), input).await?,
    ))
}

pub async fn delete_supplicant(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    vlan_supplicant::Entity::delete_owned(&state.conn, &user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_workspace_vlans(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(input): Json<WorkspaceVlansUpdateDto>,
) -> Result<Json<Vec<Uuid>>, AppError> {
    Ok(Json(
        confluence_vlan::Entity::replace_for_workspace(
            &state.conn,
            &user.user_id,
            id,
            input.vlan_ids,
        )
        .await?,
    ))
}
