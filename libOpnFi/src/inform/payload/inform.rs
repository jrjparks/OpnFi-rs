use mac_address::MacAddress;
use serde::{self, Deserialize, Serialize};
use serde_json;

// ===== System Status =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformSystemStatus {
    pub cpu: String,
    pub mem: String,
}

impl OpnFiInformSystemStatus {
    pub fn new(cpu: String, mem: String) -> Self {
        OpnFiInformSystemStatus { cpu, mem }
    }
}

// ===== Network Config =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OpnFiInformNetworkConfig {
    Disabled,
    DHCP,
    Static(OpnFiInformNetworkConfigStatic),
}

impl Default for OpnFiInformNetworkConfig {
    fn default() -> Self {
        OpnFiInformNetworkConfig::Disabled
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformNetworkConfigStatic {
    pub ip: String,
    pub netmask: String,
    pub gateway: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub dns1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub dns2: Option<String>,
}

// ===== Gatway Inform =====

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformGatewayPayload {
    pub bootrom_version: String,
    pub cfgversion: String,
    #[serde(default)]
    pub config_network_wan: OpnFiInformNetworkConfig,
    #[serde(default)]
    pub config_network_wan2: OpnFiInformNetworkConfig,
    pub default: bool,
    pub discovery_response: bool,
    pub fw_caps: i32,
    pub has_default_route_distance: bool,
    pub has_dnsmasq_hostfile_update: bool,
    pub has_dpi: bool,
    pub has_eth1: bool,
    pub has_porta: bool,
    pub has_ssh_disable: bool,
    pub has_vti: bool,
    pub hostname: String,
    pub inform_url: String,
    pub ip: String,
    pub isolated: bool,
    pub locating: bool,
    pub mac: String,
    pub model: String,
    pub model_display: String,
    pub netmask: String,
    pub radius_caps: i32,
    pub required_version: String,
    pub selfrun_beacon: bool,
    pub serial: String,
    pub state: i32,
    #[serde(rename = "system-stats")]
    pub system_status: OpnFiInformSystemStatus,
    pub time: usize,
    pub uplink: String,
    pub uptime: usize,
    pub version: String,
}
