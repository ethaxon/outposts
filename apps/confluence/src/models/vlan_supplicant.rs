use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, LoaderTrait, QueryOrder, QuerySelect, Select, TransactionTrait};

use super::{profile_supplicant, vlan_grant};
use crate::dto::SupplicantSummaryDto;
use crate::error::AppError;
use crate::vlan::VlanSupplicant;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "vlan_supplicant")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub creator: String,
    pub name: String,
    pub age_recipient: String,
    #[sea_orm(has_many)]
    pub grants: HasMany<super::vlan_grant::Entity>,
    #[sea_orm(has_many)]
    pub profile_links: HasMany<profile_supplicant::Entity>,
    #[sea_orm(has_many, via = "vlan_grant")]
    pub networks: HasMany<super::vlan_network::Entity>,
}

impl From<Model> for VlanSupplicant {
    fn from(row: Model) -> Self {
        Self {
            id: row.id.to_string(),
            name: row.name,
            age_recipient: row.age_recipient,
        }
    }
}

impl Entity {
    fn owned_in_name_order(creator: &str) -> Select<Self> {
        Self::find()
            .filter(Column::Creator.eq(creator))
            .order_by_asc(Column::Name)
    }

    pub(crate) async fn list_owned<C: ConnectionTrait>(
        db: &C,
        creator: &str,
    ) -> Result<Vec<VlanSupplicant>, DbErr> {
        Ok(Self::owned_in_name_order(creator)
            .all(db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn list_owned_with_usage(
        db: &impl ConnectionTrait,
        creator: &str,
    ) -> Result<Vec<SupplicantSummaryDto>, DbErr> {
        let rows = Self::owned_in_name_order(creator).all(db).await?;
        let (grants, links) = tokio::try_join!(
            rows.load_many(vlan_grant::Entity, db),
            rows.load_many(profile_supplicant::Entity, db),
        )?;
        Ok(itertools::izip!(rows, grants, links)
            .map(|(row, grants, links)| SupplicantSummaryDto {
                supplicant: row.into(),
                vlan_count: grants.len(),
                profile_count: links.len(),
            })
            .collect())
    }

    pub(crate) async fn save_owned(
        db: &DatabaseConnection,
        creator: &str,
        id: Option<Uuid>,
        input: VlanSupplicant,
    ) -> Result<VlanSupplicant, AppError> {
        input.validate()?;
        let mut model = if let Some(id) = id {
            Self::find_by_id(id)
                .filter(Column::Creator.eq(creator))
                .one(db)
                .await?
                .ok_or_else(|| AppError::not_found("Supplicant not found"))?
                .into()
        } else {
            ActiveModel {
                creator: Set(creator.to_owned()),
                ..Default::default()
            }
        };
        model.name = Set(input.name);
        model.age_recipient = Set(input.age_recipient);
        let row = if id.is_some() {
            model.update(db).await
        } else {
            model.insert(db).await
        };
        Ok(row.map_err(AppError::vlan_write)?.into())
    }

    pub(crate) async fn delete_owned(
        db: &DatabaseConnection,
        creator: &str,
        id: Uuid,
    ) -> Result<(), AppError> {
        let tx = db.begin().await?;
        let supplicant = Self::find_by_id(id)
            .filter(Column::Creator.eq(creator))
            .lock_exclusive()
            .one(&tx)
            .await?
            .ok_or_else(|| AppError::not_found("Supplicant not found"))?;
        if vlan_grant::Entity::find()
            .filter(vlan_grant::Column::Creator.eq(creator))
            .filter(vlan_grant::Column::SupplicantId.eq(id))
            .count(&tx)
            .await?
            > 0
        {
            return Err(AppError::bad_request(
                "Remove the supplicant's VLAN grants before deleting it",
            ));
        }
        if profile_supplicant::Entity::find()
            .filter(profile_supplicant::Column::SupplicantId.eq(id))
            .count(&tx)
            .await?
            > 0
        {
            return Err(AppError::bad_request(
                "Remove the supplicant from Profile encryption settings before deleting it",
            ));
        }
        supplicant.delete(&tx).await.map_err(AppError::vlan_write)?;
        tx.commit().await?;
        Ok(())
    }
}

impl ActiveModelBehavior for ActiveModel {}
