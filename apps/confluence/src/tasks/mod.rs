pub mod confluence_cron;

use confluence_cron::ConfluenceCronTask;
use std::{sync::Arc, time::Duration};
use tokio_cron_scheduler::{Job, JobScheduler, JobSchedulerError};

use crate::services::AppState;

pub async fn init_backend_jobs(
    job_scheduler: &mut JobScheduler,
    app_state: Arc<AppState>,
) -> Result<(), JobSchedulerError> {
    let confluence_cron_task = Arc::new(ConfluenceCronTask { state: app_state });
    
    job_scheduler
        .add(Job::new_repeated_async(
            Duration::from_secs(60),
            move |_uuid, _l| {
                let task = Arc::clone(&confluence_cron_task);
                Box::pin(async move {
                    tracing::debug!("confluence cron task start running...");
                    if let Err(err) = task.run().await {
                        tracing::error!("confluence cron task run error: {}", err.to_string());
                    } else {
                        tracing::debug!("confluence cron task succeed to run");
                    }
                })
            },
        )?)
        .await?;



    job_scheduler.start().await?;
    Ok(())
}
