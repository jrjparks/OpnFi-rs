use std::{
    fmt,
    io::{self, Read, Write},
    mem,
    net::Ipv4Addr,
};

use crate::error::OpnFiError;
use crate::tlv::{ReadTlvExt, Tlv, WriteTlvExt};
use crate::{OpnFiReadExt, OpnFiWriteExt, Result};
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use mac_address::MacAddress;

// ===== Discovery Command =====

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum OpnFiDiscoveryCommand {
    // 0x1
    // 0x2
    // 0x3
    // 0x4
    // 0x5
    Inform, // 0x6
    // 0x7
    Request,  // 0x8
    Response, // 0x9
    // 0xA
    // 0xB
    // 0xC
    Unknown(u8),
}

impl fmt::Display for OpnFiDiscoveryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            OpnFiDiscoveryCommand::Unknown(cmd) => format!("OpnFiCommand({})", cmd),
            OpnFiDiscoveryCommand::Inform => String::from("OpnFiCommand::Inform"),
            OpnFiDiscoveryCommand::Request => String::from("OpnFiCommand::Request"),
            OpnFiDiscoveryCommand::Response => String::from("OpnFiCommand::Response"),
        };
        write!(f, "OpnFiCommand({})", value)
    }
}

impl OpnFiDiscoveryCommand {
    pub fn new(cmd: u8) -> Self {
        match cmd {
            0x6 => OpnFiDiscoveryCommand::Inform,
            0x8 => OpnFiDiscoveryCommand::Request,
            0x9 => OpnFiDiscoveryCommand::Response,
            c => OpnFiDiscoveryCommand::Unknown(c),
        }
    }

    pub fn value(self) -> u8 {
        match self {
            OpnFiDiscoveryCommand::Inform => 0x6,
            OpnFiDiscoveryCommand::Request => 0x8,
            OpnFiDiscoveryCommand::Response => 0x9,
            OpnFiDiscoveryCommand::Unknown(c) => c,
        }
    }
}

impl From<OpnFiDiscoveryCommand> for u8 {
    fn from(cmd: OpnFiDiscoveryCommand) -> Self {
        cmd.value()
    }
}

impl From<u8> for OpnFiDiscoveryCommand {
    fn from(val: u8) -> OpnFiDiscoveryCommand {
        OpnFiDiscoveryCommand::new(val)
    }
}

// ===== Discovery Value =====

#[derive(PartialEq, Clone, Debug)]
pub enum OpnFiDiscoveryValue {
    HardwareAddress(MacAddress),  // 0x01 (1)
    IpInfo(Ipv4Addr, MacAddress), // 0x02 (2)
    FirmwareVersion(String),      // 0x03 (3)
    // 0x04 (4) - N/A
    // 0x05 (5) - N/A
    Username(String),   // 0x06 (6)
    Salt(Vec<u8>),      // 0x07 (7)
    Challenge(Vec<u8>), // 0x08 (8)
    // 0x09 (9) - N/A
    Uptime(i64),      // 0x0A (10)
    Hostname(String), // 0x0B (11)
    Platform(String), // 0x0C (12)
    ESSID(String),    // 0x0D (13)
    WMode(i32),       // 0x0E (14)
    // 0x0F (15) - N/A
    // 0x10 (16) - String
    // 0x11 (17) - N/A
    Sequence(i32),  // 0x12 (18)
    Serial(String), // 0x13 (19)
    // 0x14 (20) - N/A
    Model(String),                    // 0x15 (21)
    MinimumControllerVersion(String), // 0x16 (22)
    IsDefault(bool),                  // 0x17 (23)
    // 0x18 (24) - Boolean
    // 0x19 (25) - Boolean
    // 0x1A (26) - Boolean
    Version(String), // 0x1B (27)
    // 0x1C (28) - i32
    // 0x1D (29) - String
    Unknown { tag: u8, value: Vec<u8> },
    String { tag: u8, value: String },
    Bool { tag: u8, value: bool },
    Number { tag: u8, value: i32 },
}

impl OpnFiDiscoveryValue {
    pub fn new<T: ByteOrder>(tag: u8, value: Vec<u8>) -> Self {
        let utf8: fn(Vec<u8>) -> String = |x| String::from_utf8(x).unwrap_or_default();
        let bl: fn(Vec<u8>) -> bool = |x| x.as_slice().read_u8().unwrap_or(0) == 1;
        match tag {
            0x01 => {
                let mut bytes = [0u8; 6];
                bytes.copy_from_slice(value.as_slice());
                OpnFiDiscoveryValue::HardwareAddress(MacAddress::new(bytes))
            }
            0x02 => {
                let mut ip_bytes = [0u8; 4];
                let mut mac_bytes = [0u8; 6];
                let (i, m) = value.split_at(6);
                ip_bytes.copy_from_slice(i);
                mac_bytes.copy_from_slice(m);
                OpnFiDiscoveryValue::IpInfo(Ipv4Addr::from(ip_bytes), MacAddress::new(mac_bytes))
            }
            0x03 => OpnFiDiscoveryValue::FirmwareVersion(utf8(value)),

            0x06 => OpnFiDiscoveryValue::Username(utf8(value)),
            0x07 => OpnFiDiscoveryValue::Salt(value),
            0x08 => OpnFiDiscoveryValue::Challenge(value),

            0x0A => {
                OpnFiDiscoveryValue::Uptime(value.as_slice().read_i64::<T>().unwrap_or_default())
            }
            0x0B => OpnFiDiscoveryValue::Hostname(utf8(value)),
            0x0C => OpnFiDiscoveryValue::Platform(utf8(value)),
            0x0D => OpnFiDiscoveryValue::ESSID(utf8(value)),
            0x0E => {
                OpnFiDiscoveryValue::WMode(value.as_slice().read_i32::<T>().unwrap_or_default())
            }

            0x12 => {
                OpnFiDiscoveryValue::Sequence(value.as_slice().read_i32::<T>().unwrap_or_default())
            }
            0x13 => OpnFiDiscoveryValue::Serial(utf8(value)),

            0x15 => OpnFiDiscoveryValue::Model(utf8(value)),
            0x16 => OpnFiDiscoveryValue::MinimumControllerVersion(utf8(value)),
            0x17 => OpnFiDiscoveryValue::IsDefault(bl(value)),

            0x1B => OpnFiDiscoveryValue::Version(utf8(value)),

            0x18 | 0x19 | 0x1A => OpnFiDiscoveryValue::Bool {
                tag,
                value: bl(value),
            },
            0x10 | 0x1D => OpnFiDiscoveryValue::String {
                tag,
                value: utf8(value),
            },
            0x1C => OpnFiDiscoveryValue::Number {
                tag,
                value: value.as_slice().read_i32::<T>().unwrap_or_default(),
            },

            _ => OpnFiDiscoveryValue::Unknown { tag, value },
        }
    }
}

impl fmt::Display for OpnFiDiscoveryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpnFiDiscoveryValue::Unknown { tag, value } => {
                write!(f, "Unknown({}, {:?})", tag, value)
            }
            OpnFiDiscoveryValue::String { tag, value } => write!(f, "String({}, {})", tag, value),
            OpnFiDiscoveryValue::Bool { tag, value } => write!(f, "Bool({}, {})", tag, value),
            OpnFiDiscoveryValue::Number { tag, value } => write!(f, "Number({}, {})", tag, value),

            OpnFiDiscoveryValue::HardwareAddress(v) => write!(f, "HardwareAddress({})", v),
            OpnFiDiscoveryValue::IpInfo(a, m) => write!(f, "IpInfo({}, {})", a, m),
            OpnFiDiscoveryValue::FirmwareVersion(v) => write!(f, "FirmwareVersion({})", v),

            OpnFiDiscoveryValue::Username(v) => write!(f, "Username({})", v),
            OpnFiDiscoveryValue::Salt(v) => write!(f, "Salt({:?})", v),
            OpnFiDiscoveryValue::Challenge(v) => write!(f, "Challenge({:?})", v),

            OpnFiDiscoveryValue::Uptime(v) => write!(f, "Uptime({})", v),
            OpnFiDiscoveryValue::Hostname(v) => write!(f, "Hostname({})", v),
            OpnFiDiscoveryValue::Platform(v) => write!(f, "Platform({})", v),
            OpnFiDiscoveryValue::ESSID(v) => write!(f, "ESSID({})", v),
            OpnFiDiscoveryValue::WMode(v) => write!(f, "WMode({})", v),

            OpnFiDiscoveryValue::Sequence(v) => write!(f, "Sequence({})", v),
            OpnFiDiscoveryValue::Serial(v) => write!(f, "Serial({})", v),

            OpnFiDiscoveryValue::Model(v) => write!(f, "Model({})", v),
            OpnFiDiscoveryValue::MinimumControllerVersion(v) => {
                write!(f, "ControllerVersion({})", v)
            }
            OpnFiDiscoveryValue::IsDefault(v) => write!(f, "IsDefault({})", v),

            OpnFiDiscoveryValue::Version(v) => write!(f, "Version({})", v),
        }
    }
}

// ===== Discovery Packet =====

#[derive(PartialEq, Clone, Debug)]
pub struct OpnFiDiscoveryPacket {
    version: u8,
    command: OpnFiDiscoveryCommand,
    values: Vec<OpnFiDiscoveryValue>,
}

impl OpnFiDiscoveryPacket {
    pub fn new(
        version: u8,
        command: OpnFiDiscoveryCommand,
        values: Option<Vec<OpnFiDiscoveryValue>>,
    ) -> Self {
        OpnFiDiscoveryPacket {
            version,
            command,
            values: values.unwrap_or_default(),
        }
    }

    pub fn v2(command: OpnFiDiscoveryCommand, values: Option<Vec<OpnFiDiscoveryValue>>) -> Self {
        OpnFiDiscoveryPacket::new(0x02, command, values)
    }
}

impl Default for OpnFiDiscoveryPacket {
    fn default() -> Self {
        OpnFiDiscoveryPacket::new(0, OpnFiDiscoveryCommand::Unknown(0), None)
    }
}

impl fmt::Display for OpnFiDiscoveryPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let values = self
            .values
            .iter()
            .map(|v| format!("{}", v))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "OpnFiPacket[v{}] {} [{}]",
            self.version, self.command, values
        )
    }
}

// ===== Discovery Read/Write =====

impl<R: io::Read + ?Sized> OpnFiReadExt<R> for OpnFiDiscoveryValue {
    fn read<B: ByteOrder>(rdr: &mut R) -> io::Result<Self> {
        let tlv = rdr.read_tlv::<B>()?;
        Ok(OpnFiDiscoveryValue::new::<B>(tlv.tag, tlv.value))
    }
}

impl<W: io::Write + ?Sized> OpnFiWriteExt<W> for OpnFiDiscoveryValue {
    fn write<B: ByteOrder>(&self, wtr: &mut W) -> io::Result<()> {
        let tlv = match self.clone() {
            OpnFiDiscoveryValue::HardwareAddress(m) => Tlv::new(0x01, m.bytes().to_vec()),
            OpnFiDiscoveryValue::IpInfo(i, m) => {
                let mut buf: Vec<u8> = Vec::with_capacity(10);
                buf.write(m.bytes().as_ref())?;
                buf.write(i.octets().as_ref())?;
                Tlv::new(0x02, buf)
            }
            OpnFiDiscoveryValue::FirmwareVersion(v) => Tlv::new(0x03, v.into_bytes()),

            OpnFiDiscoveryValue::Username(v) => Tlv::new(0x06, v.into_bytes()),
            OpnFiDiscoveryValue::Salt(v) => Tlv::new(0x07, v),
            OpnFiDiscoveryValue::Challenge(v) => Tlv::new(0x08, v),

            OpnFiDiscoveryValue::Uptime(value) => {
                let mut buf = Vec::with_capacity(mem::size_of::<i64>());
                buf.write_i64::<B>(value)?;
                Tlv::new(0x0A, buf)
            }
            OpnFiDiscoveryValue::Hostname(v) => Tlv::new(0x0B, v.into_bytes()),
            OpnFiDiscoveryValue::Platform(v) => Tlv::new(0x0C, v.into_bytes()),
            OpnFiDiscoveryValue::ESSID(v) => Tlv::new(0x0D, v.into_bytes()),
            OpnFiDiscoveryValue::WMode(value) => {
                let mut buf = Vec::with_capacity(mem::size_of::<i32>());
                buf.write_i32::<B>(value)?;
                Tlv::new(0x0E, buf)
            }

            OpnFiDiscoveryValue::Sequence(value) => {
                let mut buf = Vec::with_capacity(mem::size_of::<i32>());
                buf.write_i32::<B>(value)?;
                Tlv::new(0x12, buf)
            }
            OpnFiDiscoveryValue::Serial(v) => Tlv::new(0x13, v.into_bytes()),

            OpnFiDiscoveryValue::Model(v) => Tlv::new(0x15, v.into_bytes()),
            OpnFiDiscoveryValue::MinimumControllerVersion(v) => Tlv::new(0x16, v.into_bytes()),
            OpnFiDiscoveryValue::IsDefault(v) => Tlv::new(0x17, vec![v as u8]),

            OpnFiDiscoveryValue::Version(v) => Tlv::new(0x1B, v.into_bytes()),

            OpnFiDiscoveryValue::Unknown { tag, value } => Tlv::new(tag, value),
            OpnFiDiscoveryValue::String { tag, value } => Tlv::new(tag, value.into_bytes()),
            OpnFiDiscoveryValue::Number { tag, value } => {
                let mut buf = Vec::with_capacity(mem::size_of::<i32>());
                buf.write_i32::<B>(value)?;
                Tlv::new(tag, buf)
            }
            OpnFiDiscoveryValue::Bool { tag, value } => Tlv::new(tag, vec![value as u8]),
        }?;
        wtr.write_tlv::<B>(&tlv)
    }
}

impl<R: io::Read + ?Sized> OpnFiReadExt<R> for OpnFiDiscoveryPacket {
    fn read<B: ByteOrder>(rdr: &mut R) -> io::Result<Self> {
        let version = rdr.read_u8()?;
        let tlv = rdr.read_tlv::<B>()?;
        let mut values = Vec::new();
        let mut value_rdr = io::Cursor::new(tlv.value);
        loop {
            match OpnFiDiscoveryValue::read::<B>(&mut value_rdr) {
                Ok(value) => values.push(value),
                _ => break,
            }
        }
        Ok(OpnFiDiscoveryPacket::new(
            version,
            OpnFiDiscoveryCommand::new(tlv.tag),
            Some(values),
        ))
    }
}

impl<W: io::Write + ?Sized> OpnFiWriteExt<W> for OpnFiDiscoveryPacket {
    fn write<B: ByteOrder>(&self, wtr: &mut W) -> io::Result<()> {
        wtr.write_u8(self.version)?;
        let mut values = Vec::new();
        for value in &self.values {
            value.write::<B>(&mut values)?;
        }
        let tlv = Tlv::new(u8::from(self.command), values)?;
        wtr.write_tlv::<B>(&tlv)
    }
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::ReadTlvExt;
    use byteorder::BigEndian;
    use std::{error, io::Cursor};

    type Result = std::result::Result<(), Box<dyn error::Error + 'static>>;

    #[test]
    fn test_read_opnfi_value() -> Result {
        let mut rdr = Cursor::new(vec![
            0x15, 0, 11, 72, 101, 108, 108, 111, 32, 82, 117, 115, 116, 33,
        ]);
        let val = OpnFiDiscoveryValue::read::<BigEndian>(&mut rdr)?;
        assert_eq!(val, OpnFiDiscoveryValue::Model(String::from("Hello Rust!")));
        Ok(())
    }

    #[test]
    fn test_write_opnfi_value() -> Result {
        let expected = vec![
            0x15, 0, 11, 72, 101, 108, 108, 111, 32, 82, 117, 115, 116, 33,
        ];
        let mut wtr = Cursor::new(Vec::new());
        let val = OpnFiDiscoveryValue::Model(String::from("Hello Rust!"));
        val.write::<BigEndian>(&mut wtr)?;
        assert_eq!(expected, wtr.into_inner());
        Ok(())
    }

    #[test]
    fn test_read_write_opnfi_value() -> Result {
        let mut wtr = Vec::new();
        let expected_val = OpnFiDiscoveryValue::Unknown {
            tag: 123,
            value: String::from("Test123").into_bytes(),
        };
        expected_val.write::<BigEndian>(&mut wtr)?;
        let mut rdr = Cursor::new(wtr);
        let val = OpnFiDiscoveryValue::read::<BigEndian>(&mut rdr)?;
        assert_eq!(expected_val, val);
        Ok(())
    }

    #[test]
    fn test_read_opnfi_packet() -> Result {
        let mut rdr = Cursor::new(vec![0x02, 0x08, 0x00, 0x00]);
        let val = OpnFiDiscoveryPacket::read::<BigEndian>(&mut rdr)?;
        let pkt = OpnFiDiscoveryPacket::v2(OpnFiDiscoveryCommand::Request, None);
        assert_eq!(val, pkt);
        Ok(())
    }

    #[test]
    fn test_write_opnfi_packet() -> Result {
        let expected = vec![0x02, 0x08, 0x00, 0x00];
        let mut wtr = Cursor::new(Vec::new());
        let val = OpnFiDiscoveryPacket::v2(OpnFiDiscoveryCommand::Request, None);
        val.write::<BigEndian>(&mut wtr)?;
        assert_eq!(expected, wtr.into_inner());
        Ok(())
    }

    #[test]
    fn test_read_write_opnfi_packet() -> Result {
        let mut wtr = Vec::new();
        let expected_pkt = OpnFiDiscoveryPacket::v2(
            OpnFiDiscoveryCommand::Unknown(1),
            Some(vec![OpnFiDiscoveryValue::Unknown {
                tag: 123,
                value: String::from("Test123").into_bytes(),
            }]),
        );
        expected_pkt.write::<BigEndian>(&mut wtr)?;
        let mut rdr = Cursor::new(wtr);
        let pkt = OpnFiDiscoveryPacket::read::<BigEndian>(&mut rdr)?;
        assert_eq!(expected_pkt, pkt);
        Ok(())
    }
}
