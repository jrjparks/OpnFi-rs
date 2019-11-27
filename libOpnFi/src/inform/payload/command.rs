use serde::{self, Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn time() -> u64 {
    let now = SystemTime::now();
    let epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("Time travel is not allowed.");
    epoch.as_secs()
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(tag = "_type", rename_all = "lowercase")]
pub enum OpnFiInformPayloadCommand {
    NoOp(OpnFiInformPayloadNoOpCommand),
    SetParam(OpnFiInformPayloadSetParamsCommand),
    Upgrade,
    Reboot,
    Cmd,
    SetDefault,
}

// ===== NoOp =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadNoOpCommand {
    interval: u64,
    server_time_in_utc: Option<String>,
}

impl Default for OpnFiInformPayloadNoOpCommand {
    fn default() -> Self {
        OpnFiInformPayloadNoOpCommand {
            interval: 10,
            server_time_in_utc: Some(time().to_string()),
        }
    }
}

impl OpnFiInformPayloadNoOpCommand {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval)
    }
}

// ===== NoOp =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadSetParamsCommand {
    pub mgmt_cfg: Option<String>,
    pub system_cfg: Option<String>,
    server_time_in_utc: Option<String>,
}
