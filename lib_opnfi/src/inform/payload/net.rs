use serde::{self, Deserialize, Serialize};

// ===== Network Config =====

/// Network config
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

// ===== Config Port Table =====

/// Port config, not sure how this is used, seems to be ignored or I'm missing a step.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct OpnFiInformConfigPortTableItem {
    name: String,
    ifname: String,
}

impl OpnFiInformConfigPortTableItem {
    pub fn new(name: String, ifname: String) -> Self {
        Self { name, ifname }
    }
}

// ===== Interface =====

/// Network interface for inform
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct OpnFiInformNetworkInterface {
    pub drops: usize,
    pub enabled: bool,
    pub full_duplex: bool,
    pub gateways: Vec<String>,
    pub ip: String,
    pub latency: usize,
    pub mac: String,
    pub name: String,
    pub nameservers: Vec<String>,
    pub netmask: String,
    pub num_port: usize,
    pub rx_bytes: usize,
    pub rx_dropped: usize,
    pub rx_errors: usize,
    pub rx_multicast: usize,
    pub rx_packets: usize,
    pub speed: usize,
    pub speedtest_lastrun: usize,
    pub speedtest_ping: usize,
    pub speedtest_status: String,
    pub tx_bytes: usize,
    pub tx_dropped: usize,
    pub tx_errors: usize,
    pub tx_packets: usize,
    pub up: bool,
    pub uptime: usize,
    pub xput_down: usize,
    pub xput_up: usize,
}
