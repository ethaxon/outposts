use chrono::{DateTime, Months, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SubscribeSourceTrafficResetPolicy {
    #[default]
    Default,
    Monthly,
    Quarterly,
    Yearly,
    OneTime,
}

impl SubscribeSourceTrafficResetPolicy {
    pub fn next_reset_at(&self, expire_at: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
        self.next_reset_at_after(expire_at, Utc::now())
    }

    pub(crate) fn next_reset_at_after(
        &self,
        expire_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let interval_months = match self {
            Self::Default | Self::Monthly => 1,
            Self::Quarterly => 3,
            Self::Yearly => 12,
            Self::OneTime => return None,
        };
        let mut next_reset = expire_at?;
        if next_reset <= now {
            return None;
        }
        loop {
            let Some(previous_reset) = next_reset.checked_sub_months(Months::new(interval_months))
            else {
                return Some(next_reset);
            };
            if previous_reset <= now {
                return Some(next_reset);
            }
            next_reset = previous_reset;
        }
    }
}

impl From<Option<&str>> for SubscribeSourceTrafficResetPolicy {
    fn from(value: Option<&str>) -> Self {
        match value.map(str::trim).filter(|s| !s.is_empty()) {
            Some("monthly") => Self::Monthly,
            Some("quarterly") => Self::Quarterly,
            Some("yearly") => Self::Yearly,
            Some("one_time") => Self::OneTime,
            Some("default") | Some(_) | None => Self::Default,
        }
    }
}
