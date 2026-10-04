use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::Set, DatabaseTransaction, LoaderTrait, QueryOrder};

use super::{profile, vlan_supplicant};
use crate::dto::ProfileDto;
use crate::error::AppError;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "profile_supplicant")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub profile_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub supplicant_id: Uuid,
    pub confluence_id: Uuid,
    pub creator: String,
    #[sea_orm(
        belongs_to,
        from = "(confluence_id, profile_id)",
        to = "(confluence_id, id)",
        on_delete = "Cascade"
    )]
    pub profile: HasOne<profile::Entity>,
    #[sea_orm(
        belongs_to,
        from = "(creator, supplicant_id)",
        to = "(creator, id)",
        on_delete = "Restrict"
    )]
    pub supplicant: HasOne<vlan_supplicant::Entity>,
}

impl Entity {
    pub(crate) async fn load_ids(
        db: &impl ConnectionTrait,
        profiles: &[profile::Model],
    ) -> Result<Vec<Vec<Uuid>>, AppError> {
        Ok(profiles
            .load_many(Self::find().order_by_asc(Column::SupplicantId), db)
            .await?
            .into_iter()
            .map(|links| links.into_iter().map(|link| link.supplicant_id).collect())
            .collect())
    }

    pub(crate) async fn load_profiles(
        db: &impl ConnectionTrait,
        profiles: Vec<profile::Model>,
    ) -> Result<Vec<ProfileDto>, AppError> {
        let ids = Self::load_ids(db, &profiles).await?;
        Ok(profiles
            .into_iter()
            .zip(ids)
            .map(ProfileDto::from)
            .collect())
    }

    pub(crate) async fn replace_for_profile(
        tx: &DatabaseTransaction,
        profile: &profile::Model,
        creator: &str,
        mut ids: Vec<Uuid>,
    ) -> Result<Vec<Uuid>, AppError> {
        ids.sort_unstable();
        ids.dedup();
        if !ids.is_empty()
            && vlan_supplicant::Entity::find()
                .filter(vlan_supplicant::Column::Creator.eq(creator))
                .filter(vlan_supplicant::Column::Id.is_in(ids.iter().copied()))
                .count(tx)
                .await?
                != ids.len() as u64
        {
            return Err(AppError::bad_request("Unknown Profile supplicant"));
        }
        Self::delete_many()
            .filter(Column::ProfileId.eq(profile.id))
            .exec(tx)
            .await?;
        if !ids.is_empty() {
            Self::insert_many(ids.iter().map(|id| ActiveModel {
                profile_id: Set(profile.id),
                supplicant_id: Set(*id),
                confluence_id: Set(profile.confluence_id),
                creator: Set(creator.into()),
            }))
            .exec(tx)
            .await
            .map_err(AppError::vlan_write)?;
        }
        Ok(ids)
    }
}

impl ActiveModelBehavior for ActiveModel {}
