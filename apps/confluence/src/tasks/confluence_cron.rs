use crate::{
    error::AppError,
    models::confluence,
    services::{
        find_certain_confluence_profiles_and_subscribe_sources, mux_one_confluence_impl,
        passive_sync_one_subscribe_source_with_url, AppState,
    },
};
use chrono::Utc;
use chrono_tz::Tz;
use cron::Schedule;
use futures::future;
use sea_orm::{prelude::*, Set, Unchanged};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone)]
pub struct ConfluenceCronTask {
    pub state: Arc<AppState>,
}

impl ConfluenceCronTask {
    async fn run_one_confluence_cron(&self, cm: confluence::Model) -> Result<(), AppError> {
        let db = &self.state.conn;
        let (pms, sms) = find_certain_confluence_profiles_and_subscribe_sources(db, cm.id).await?;

        let ua = cm.user_agent_or_default();

        let sms = future::try_join_all(
            sms.into_iter()
                .map(|sm| passive_sync_one_subscribe_source_with_url(sm, ua, db)),
        )
        .await?;

        mux_one_confluence_impl(db, cm, sms, pms).await?;
        Ok(())
    }

    pub async fn run(&self) -> Result<(), AppError> {
        let db = &self.state.conn;
        let cms = confluence::Entity::find()
            .filter(confluence::Column::CronNextAt.lte(Utc::now()))
            .all(db)
            .await?;

        for cm in cms {
            let id = cm.id;
            let cron_next_at =
                if let (Some(cron_expr), Some(cron_expr_tz)) = (&cm.cron_expr, &cm.cron_expr_tz) {
                    if let (Ok(cron), Ok(tz)) =
                        (Schedule::from_str(cron_expr), cron_expr_tz.parse::<Tz>())
                    {
                        cron.upcoming(tz).next().map(|t| t.naive_utc())
                    } else {
                        None
                    }
                } else {
                    None
                };
            let err_msg = self
                .run_one_confluence_cron(cm)
                .await
                .err()
                .map(|e| e.to_string());

            if let Some(err_msg) = &err_msg {
                tracing::error!("run confluence {} cron failed: {}", id, err_msg);
            };

            let _ = confluence::Entity::update(confluence::ActiveModel {
                id: Unchanged(id),
                cron_next_at: Set(cron_next_at),
                cron_prev_at: Set(Some(Utc::now().naive_utc())),
                cron_err: Set(err_msg),
                ..Default::default()
            })
            .exec(db)
            .await;
        }

        Ok(())
    }
}
