use std::collections::BTreeSet;

use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, LoaderTrait, QueryOrder, QuerySelect, TransactionTrait};

use super::{confluence, vlan_network};
use crate::error::AppError;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "confluence_vlan")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub confluence_id: Uuid,
    pub vlan_id: Uuid,
    #[sea_orm(
        belongs_to,
        from = "(creator, confluence_id)",
        to = "(creator, id)",
        on_delete = "Cascade"
    )]
    pub confluence: HasOne<super::confluence::Entity>,
    #[sea_orm(
        belongs_to,
        from = "(creator, vlan_id)",
        to = "(creator, id)",
        on_delete = "Cascade"
    )]
    pub network: HasOne<super::vlan_network::Entity>,
}

impl Entity {
    pub(crate) async fn load_ids_for_workspaces<C: ConnectionTrait>(
        db: &C,
        workspaces: &[confluence::Model],
    ) -> Result<Vec<Vec<Uuid>>, AppError> {
        Ok(workspaces
            .load_many(Self::find().order_by_asc(Column::VlanId), db)
            .await?
            .into_iter()
            .map(|links| links.into_iter().map(|link| link.vlan_id).collect())
            .collect())
    }

    pub(crate) async fn replace_for_workspace(
        db: &DatabaseConnection,
        creator: &str,
        workspace_id: Uuid,
        ids: Vec<Uuid>,
    ) -> Result<Vec<Uuid>, AppError> {
        let tx = db.begin().await?;
        confluence::Entity::find_by_id(workspace_id)
            .filter(confluence::Column::Creator.eq(creator))
            .lock_exclusive()
            .one(&tx)
            .await?
            .ok_or_else(|| AppError::not_found("Workspace not found"))?;
        let ids: BTreeSet<_> = ids.into_iter().collect();
        if !ids.is_empty() {
            let owned = vlan_network::Entity::find()
                .filter(vlan_network::Column::Creator.eq(creator))
                .filter(vlan_network::Column::Id.is_in(ids.iter().copied()))
                .count(&tx)
                .await?;
            if owned != ids.len() as u64 {
                return Err(AppError::bad_request("One or more VLANs are unavailable"));
            }
        }
        Self::delete_many()
            .filter(Column::ConfluenceId.eq(workspace_id))
            .filter(Column::Creator.eq(creator))
            .exec(&tx)
            .await?;
        if !ids.is_empty() {
            Self::insert_many(ids.iter().map(|id| ActiveModel {
                creator: Set(creator.to_owned()),
                confluence_id: Set(workspace_id),
                vlan_id: Set(*id),
                ..Default::default()
            }))
            .exec(&tx)
            .await
            .map_err(AppError::vlan_write)?;
        }
        tx.commit().await?;
        Ok(ids.into_iter().collect())
    }
}

impl ActiveModelBehavior for ActiveModel {}
