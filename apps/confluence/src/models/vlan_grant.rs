use std::collections::HashMap;

use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction};

use super::vlan_supplicant;
use crate::error::AppError;
use crate::vlan::VlanGrant;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_grant")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub vlan_id: Uuid,
    pub supplicant_id: Uuid,
    pub slots: String,
    #[sea_orm(
        belongs_to,
        from = "(creator, vlan_id)",
        to = "(creator, id)",
        on_delete = "Cascade"
    )]
    pub network: HasOne<super::vlan_network::Entity>,
    #[sea_orm(
        belongs_to,
        from = "(creator, supplicant_id)",
        to = "(creator, id)",
        on_delete = "Restrict"
    )]
    pub supplicant: HasOne<super::vlan_supplicant::Entity>,
}

impl From<Model> for VlanGrant {
    fn from(row: Model) -> Self {
        Self {
            supplicant_id: row.supplicant_id.to_string(),
            slots: row.slots,
        }
    }
}

impl Entity {
    pub(super) async fn validate_assignments(
        tx: &DatabaseTransaction,
        creator: &str,
        assignments: &[VlanGrant],
    ) -> Result<HashMap<Uuid, String>, AppError> {
        let mut grants = HashMap::new();
        for grant in assignments {
            let id = grant
                .supplicant_id
                .parse::<Uuid>()
                .map_err(|_| AppError::bad_request("Invalid supplicant ID"))?;
            if grants.insert(id, grant.slots.clone()).is_some() {
                return Err(AppError::bad_request("Duplicate VLAN supplicant grant"));
            }
        }
        if !grants.is_empty() {
            let owned = vlan_supplicant::Entity::find()
                .filter(vlan_supplicant::Column::Creator.eq(creator))
                .filter(vlan_supplicant::Column::Id.is_in(grants.keys().copied()))
                .count(tx)
                .await?;
            if owned != grants.len() as u64 {
                return Err(AppError::bad_request(
                    "One or more supplicants are unavailable",
                ));
            }
        }

        Ok(grants)
    }

    pub(super) async fn replace_for_vlan(
        tx: &DatabaseTransaction,
        creator: &str,
        id: Uuid,
        mut grants: HashMap<Uuid, String>,
    ) -> Result<(), AppError> {
        for row in Self::find().filter(Column::VlanId.eq(id)).all(tx).await? {
            if let Some(slots) = grants.remove(&row.supplicant_id) {
                if row.slots != slots {
                    let mut active: ActiveModel = row.into();
                    active.slots = Set(slots);
                    active.update(tx).await.map_err(AppError::vlan_write)?;
                }
            } else {
                Self::delete_by_id(row.id).exec(tx).await?;
            }
        }
        for (supplicant_id, slots) in grants {
            ActiveModel {
                creator: Set(creator.to_owned()),
                vlan_id: Set(id),
                supplicant_id: Set(supplicant_id),
                slots: Set(slots),
                ..Default::default()
            }
            .insert(tx)
            .await
            .map_err(AppError::vlan_write)?;
        }
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
