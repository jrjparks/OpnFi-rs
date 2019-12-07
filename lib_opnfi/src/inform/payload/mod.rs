use crate::{
    error::OpnFiError,
    inform::{
        payload::command::{OpnFiInformPayloadCommand, OpnFiInformPayloadNoOpCommand},
        OpnFiInformTryFrom,
    },
    Result,
};
use serde_json;

pub mod command;
pub mod gateway;
pub mod net;
pub mod stats;

/// Main OpnFi inform payload enum.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(untagged)]
pub enum OpnFiInformPayload {
    Command(command::OpnFiInformPayloadCommand),
    Gateway(gateway::OpnFiInformGatewayPayload),
}

impl Default for OpnFiInformPayload {
    fn default() -> Self {
        OpnFiInformPayload::Command(OpnFiInformPayloadCommand::NoOp(
            OpnFiInformPayloadNoOpCommand::default(),
        ))
    }
}

/// This allows OpnFiInformPayload to be used as a payload
impl OpnFiInformTryFrom for OpnFiInformPayload {
    fn from_data(data: &Vec<u8>) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| OpnFiError::from(e))
    }

    fn to_data(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| OpnFiError::from(e))
    }
}
