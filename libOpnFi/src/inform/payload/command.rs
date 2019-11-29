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
    Cmd(OpnFiInformPayloadCmdCommand),
    SetDefault(OpnFiInformPayloadSetDefaultCommand),
}

// ===== NoOp =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadNoOpCommand {
    interval: u64,
    server_time_in_utc: String,
}

impl Default for OpnFiInformPayloadNoOpCommand {
    fn default() -> Self {
        OpnFiInformPayloadNoOpCommand {
            interval: 10,
            server_time_in_utc: time().to_string(),
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
    pub blocked_sta: Option<String>,
    server_time_in_utc: String,
}

impl OpnFiInformPayloadSetParamsCommand {
    pub fn is_mgmt_cfg(&self) -> bool {
        self.mgmt_cfg.is_some()
    }

    pub fn is_system_cfg(&self) -> bool {
        self.system_cfg.is_some()
    }
}

// ===== CMD =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadCmdCommand {
    #[serde(rename = "_id")]
    pub id: String,
    pub cmd: String,
    pub date_time: String,
    pub device_id: String,
    server_time_in_utc: String,
    pub time: u64,
    pub use_alert: bool,
}

impl Default for OpnFiInformPayloadCmdCommand {
    fn default() -> Self {
        OpnFiInformPayloadCmdCommand {
            id: "".to_string(),
            cmd: "".to_string(),
            date_time: "".to_string(),
            device_id: "".to_string(),
            server_time_in_utc: time().to_string(),
            time: time(),
            use_alert: true,
        }
    }
}

// ===== SetDefault =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadSetDefaultCommand {
    server_time_in_utc: String,
}

impl Default for OpnFiInformPayloadSetDefaultCommand {
    fn default() -> Self {
        OpnFiInformPayloadSetDefaultCommand {
            server_time_in_utc: time().to_string(),
        }
    }
}
