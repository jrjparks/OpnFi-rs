use serde::{self, Deserialize, Serialize};

// ===== System Status =====

/// System status
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

impl Default for OpnFiInformSystemStatus {
    fn default() -> Self {
        Self::new("0".to_string(), "0".to_string())
    }
}
