use super::net::*;
use super::stats::*;
use serde::{self, Deserialize, Serialize};

// ===== Gatway Inform =====

/// Gateway inform payload, I may be missing a few fields.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct OpnFiInformGatewayPayload {
    pub bootrom_version: String,
    pub cfgversion: String,
    #[serde(default)]
    pub config_network_wan: OpnFiInformNetworkConfig,
    #[serde(default)]
    pub config_network_wan2: OpnFiInformNetworkConfig,
    #[serde(default)]
    pub config_port_table: Vec<OpnFiInformConfigPortTableItem>,
    pub default: bool,
    pub discovery_response: bool,
    pub fw_caps: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub guest_token: Option<String>,
    pub has_default_route_distance: bool,
    pub has_dnsmasq_hostfile_update: bool,
    pub has_dpi: bool,
    pub has_eth1: bool,
    pub has_porta: bool,
    pub has_ssh_disable: bool,
    pub has_vti: bool,
    pub hostname: String,
    #[serde(default)]
    pub if_table: Vec<OpnFiInformNetworkInterface>,
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
