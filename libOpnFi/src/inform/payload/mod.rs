use crate::inform::payload::command::{OpnFiInformPayloadCommand, OpnFiInformPayloadNoOpCommand};
use serde::{self, Deserialize, Serialize};
use serde_json;

pub mod command;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(untagged)]
pub enum OpnFiInformPayload {
    Command(command::OpnFiInformPayloadCommand),
}

impl Default for OpnFiInformPayload {
    fn default() -> Self {
        OpnFiInformPayload::Command(OpnFiInformPayloadCommand::NoOp(
            OpnFiInformPayloadNoOpCommand::default(),
        ))
    }
}

impl From<Vec<u8>> for OpnFiInformPayload {
    fn from(data: Vec<u8>) -> Self {
        serde_json::from_slice(data.as_slice()).unwrap_or_default()
    }
}

impl From<OpnFiInformPayload> for Vec<u8> {
    fn from(data: OpnFiInformPayload) -> Self {
        serde_json::to_vec(&data).unwrap_or_default()
    }
}
