use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, LoaderTrait, QueryOrder, QuerySelect, TransactionTrait};

use super::{vlan_grant, vlan_route, vlan_tunnel};
use crate::error::AppError;
use crate::vlan::VlanNetwork;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_network")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub name: String,
    pub enabled: bool,
    #[sea_orm(has_many)]
    pub workspace_links: HasMany<super::confluence_vlan::Entity>,
    #[sea_orm(has_many, via = "confluence_vlan")]
    pub workspaces: HasMany<super::confluence::Entity>,
    #[sea_orm(has_many)]
    pub grants: HasMany<super::vlan_grant::Entity>,
    #[sea_orm(has_many, via = "vlan_grant")]
    pub supplicants: HasMany<super::vlan_supplicant::Entity>,
    #[sea_orm(has_many)]
    pub tunnels: HasMany<super::vlan_tunnel::Entity>,
    #[sea_orm(has_many)]
    pub routes: HasMany<super::vlan_route::Entity>,
}

impl Entity {
    pub(crate) async fn list_owned<C: ConnectionTrait>(
        db: &C,
        creator: &str,
    ) -> Result<Vec<VlanNetwork>, AppError> {
        let rows = Self::find()
            .filter(Column::Creator.eq(creator))
            .order_by_asc(Column::Name)
            .all(db)
            .await?;
        Ok(Self::load_details(db, rows)
            .await?
            .into_iter()
            .map(VlanNetwork::redact_keys)
            .collect())
    }

    pub(super) async fn load_details<C: ConnectionTrait>(
        db: &C,
        rows: Vec<Model>,
    ) -> Result<Vec<VlanNetwork>, AppError> {
        let tunnels = vlan_tunnel::Entity::load_for_networks(db, &rows).await?;
        let (routes, grants) = tokio::try_join!(
            rows.load_many(
                vlan_route::Entity::find().order_by_asc(vlan_route::Column::Id),
                db
            ),
            rows.load_many(
                vlan_grant::Entity::find().order_by_asc(vlan_grant::Column::Id),
                db
            ),
        )?;
        Ok(itertools::izip!(rows, tunnels, routes, grants)
            .map(|(row, tunnels, routes, grants)| VlanNetwork {
                id: row.id.to_string(),
                network: row.name,
                enabled: row.enabled,
                tunnels,
                routes: routes
                    .into_iter()
                    .map(|route| route.cidr.to_string())
                    .collect(),
                accept_supplicants: grants.into_iter().map(Into::into).collect(),
            })
            .collect())
    }

    pub(crate) async fn save_owned(
        db: &DatabaseConnection,
        creator: &str,
        id: Option<Uuid>,
        mut input: VlanNetwork,
    ) -> Result<VlanNetwork, AppError> {
        let tx = db.begin().await?;
        let row = if let Some(id) = id {
            Some(
                Self::find_by_id(id)
                    .filter(Column::Creator.eq(creator))
                    .lock_exclusive()
                    .one(&tx)
                    .await?
                    .ok_or_else(|| AppError::not_found("VLAN not found"))?,
            )
        } else {
            None
        };
        let previous = if let Some(row) = &row {
            vlan_tunnel::Entity::load_for_networks(&tx, std::slice::from_ref(row))
                .await?
                .pop()
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        input.preserve_keys(&previous)?;
        let grants =
            vlan_grant::Entity::validate_assignments(&tx, creator, &input.accept_supplicants)
                .await?;

        let network = if let Some(row) = row {
            let mut active: ActiveModel = row.into();
            active.name = Set(input.network.clone());
            active.enabled = Set(input.enabled);
            active.update(&tx).await.map_err(AppError::vlan_write)?
        } else {
            ActiveModel {
                creator: Set(creator.to_owned()),
                name: Set(input.network.clone()),
                enabled: Set(input.enabled),
                ..Default::default()
            }
            .insert(&tx)
            .await
            .map_err(AppError::vlan_write)?
        };
        vlan_route::Entity::replace_for_vlan(&tx, network.id, &input.routes).await?;
        vlan_grant::Entity::replace_for_vlan(&tx, creator, network.id, grants).await?;
        vlan_tunnel::Entity::replace_for_vlan(&tx, creator, network.id, &input.tunnels).await?;
        let saved = Self::load_details(&tx, vec![network])
            .await?
            .pop()
            .ok_or_else(|| AppError::internal_str("Missing saved VLAN"))?;
        tx.commit().await?;
        Ok(saved.redact_keys())
    }

    pub(crate) async fn delete_owned(
        db: &DatabaseConnection,
        creator: &str,
        id: Uuid,
    ) -> Result<(), AppError> {
        if Self::delete_by_id(id)
            .filter(Column::Creator.eq(creator))
            .exec(db)
            .await?
            .rows_affected
            == 0
        {
            return Err(AppError::not_found("VLAN not found"));
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
