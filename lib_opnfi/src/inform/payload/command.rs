use serde::{self, Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn time() -> u64 {
    let now = SystemTime::now();
    let epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("Time travel is not allowed.");
    epoch.as_secs()
}

/// The different inform commands
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(tag = "_type", rename_all = "lowercase")]
pub enum OpnFiInformPayloadCommand {
    NoOp(OpnFiInformPayloadNoOpCommand),
    SetParam(OpnFiInformPayloadSetParamsCommand),
    Upgrade(OpnFiInformPayloadUpgradeCommand),
    Reboot(OpnFiInformPayloadRebootCommand),
    Cmd(OpnFiInformPayloadCmdCommand),
    SetDefault(OpnFiInformPayloadSetDefaultCommand),
}

// ===== NoOp =====

/// NoOp command with next inform interval
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

// ===== SetParam =====

/// SetParams command to update configs.
/// Not sure what blocked_sta is, I only ever see it as an empty string.
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

impl Default for OpnFiInformPayloadSetParamsCommand {
    fn default() -> Self {
        Self {
            mgmt_cfg: None,
            system_cfg: None,
            blocked_sta: None,
            server_time_in_utc: time().to_string(),
        }
    }
}

// ===== Upgrade =====

/// Command to upgrade firmware or software
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadUpgradeCommand {
    md5sum: String,
    url: String,
    version: String,
    server_time_in_utc: String,
}

impl Default for OpnFiInformPayloadUpgradeCommand {
    fn default() -> Self {
        Self {
            md5sum: "".to_string(),
            url: "".to_string(),
            version: "".to_string(),
            server_time_in_utc: time().to_string(),
        }
    }
}

// ===== Reboot =====

/// Reboot device command
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadRebootCommand {
    #[serde(rename = "_id")]
    id: String,
    datetime: String,
    device_id: String,
    reboot_type: String,
    server_time_in_utc: String,
    time: u64,
}

impl Default for OpnFiInformPayloadRebootCommand {
    fn default() -> Self {
        let time = time();
        Self {
            id: "".to_string(),
            datetime: "".to_string(),
            device_id: "".to_string(),
            reboot_type: "soft".to_string(),
            server_time_in_utc: time.to_string(),
            time,
        }
    }
}

// ===== CMD =====

/// Generic command
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
        Self {
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

/// Device was forgotten, reset to defaults
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformPayloadSetDefaultCommand {
    server_time_in_utc: String,
}

impl Default for OpnFiInformPayloadSetDefaultCommand {
    fn default() -> Self {
        Self {
            server_time_in_utc: time().to_string(),
        }
    }
}
