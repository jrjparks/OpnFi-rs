use std::{
    fmt,
    io::{self, Read, Write},
    mem,
    net::Ipv4Addr,
};

use crate::error::OpnFiError;
use crate::Result;
use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use enumflags2::BitFlags;
use mac_address::MacAddress;

mod cipher;
mod compression;
pub mod payload;

// ===== Constants =====

pub(crate) const MASTER_INFORM_KEY: [u8; 16] = [
    0xBA, 0x86, 0xF2, 0xBB, 0xE1, 0x7, 0xC7, 0xC5, 0x7E, 0xB5, 0xF2, 0x69, 0x7, 0x75, 0xC7, 0x12,
];
pub(crate) const UNIFI_MAGIC_HEADER: u32 = 1414414933;

// ===== Inform Packet =====

// TODO: Write better payload type?

#[derive(PartialEq, Clone, Debug)]
pub struct OpnfiInformPacket<T: Sized + Clone + From<Vec<u8>> + Into<Vec<u8>>> {
    pub magic_header: u32,
    pub packet_version: u32,
    pub hardware_address: MacAddress,
    pub flags: u16,
    pub payload_version: u32,
    pub payload: T,
}

impl<T: Sized + Clone + From<Vec<u8>> + Into<Vec<u8>>> OpnfiInformPacket<T> {
    pub fn new(
        magic_header: Option<u32>,
        packet_version: u32,
        hardware_address: MacAddress,
        flags: u16,
        payload_version: u32,
        payload: T,
    ) -> Self {
        OpnfiInformPacket {
            magic_header: magic_header.unwrap_or(UNIFI_MAGIC_HEADER),
            packet_version,
            hardware_address,
            flags,
            payload_version,
            payload,
        }
    }
}

// ===== Inform Packet Flags =====

#[derive(BitFlags, Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum OpnfiInformPacketFlag {
    Encrypted = 0x01,
    ZLibCompressed = 0x02,
    SnappyCompressed = 0x04,
    EncryptedGCM = 0x08,
}

// ===== Inform Read/Write =====

pub trait OpnFiReadExt<R: io::Read + ?Sized> {
    fn read<B>(key: Option<[u8; 16]>, header: Option<u32>, rdr: &mut R) -> io::Result<Self>
    where
        Self: Sized,
        B: ByteOrder;
}

pub trait OpnFiWriteExt<W: io::Write + ?Sized> {
    fn write<B>(&self, key: Option<[u8; 16]>, iv: [u8; 16], wtr: &mut W) -> io::Result<()>
    where
        Self: Sized,
        B: ByteOrder;
}

impl<R: io::Read + io::Seek + ?Sized, T: Sized + Clone + From<Vec<u8>> + Into<Vec<u8>>>
    OpnFiReadExt<R> for OpnfiInformPacket<T>
{
    fn read<B: ByteOrder>(
        key: Option<[u8; 16]>,
        header: Option<u32>,
        rdr: &mut R,
    ) -> io::Result<Self> {
        let key = key.unwrap_or(MASTER_INFORM_KEY);
        let header = header.unwrap_or(UNIFI_MAGIC_HEADER);
        let mut aad = [0u8; 40];
        rdr.read_exact(&mut aad)?;
        rdr.seek(io::SeekFrom::Start(0))?;

        let packet_header = rdr.read_u32::<B>()?;
        if header != packet_header {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Header mismatch: {} != {}", packet_header, header),
            ));
        }
        let packet_version = rdr.read_u32::<B>()?;

        let mut hardware_address_bytes = [0u8; 6];
        rdr.read_exact(&mut hardware_address_bytes)?;
        let hardware_address = MacAddress::new(hardware_address_bytes);

        let flags = rdr.read_u16::<B>()?;

        let mut initialization_vector = [0u8; 16];
        rdr.read_exact(&mut initialization_vector)?;

        let payload_version = rdr.read_u32::<B>()?;
        let payload_length = rdr.read_u32::<B>()?;

        let mut payload_data = Vec::new();
        rdr.take(payload_length as u64)
            .read_to_end(&mut payload_data)?;
        if payload_data.len() < payload_length as usize {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Packet payload length less than expected: {} < {}",
                    payload_data.len(),
                    payload_length
                ),
            ));
        }

        let payload: T = Ok(payload_data)
            .and_then(|data| {
                if flags & (OpnfiInformPacketFlag::EncryptedGCM as u16) != 0 {
                    cipher::decode_gcm(data.as_slice(), &key, Some(&initialization_vector), &aad)
                } else if flags & (OpnfiInformPacketFlag::Encrypted as u16) != 0 {
                    cipher::decode_cbc(data.as_slice(), &key, Some(&initialization_vector))
                } else {
                    Ok(data)
                }
            })
            .and_then(|data| {
                if flags & (OpnfiInformPacketFlag::SnappyCompressed as u16) != 0 {
                    compression::decode_snappy(&data)
                } else if flags & (OpnfiInformPacketFlag::ZLibCompressed as u16) != 0 {
                    compression::decode_zlib(&data)
                } else {
                    Ok(data)
                }
            })
            .and_then(|data| Ok(T::from(data)))?;

        Ok(OpnfiInformPacket::new(
            Some(packet_header),
            packet_version,
            hardware_address,
            flags,
            payload_version,
            payload,
        ))
    }
}

impl<W: io::Write + ?Sized, T: Sized + Clone + From<Vec<u8>> + Into<Vec<u8>>> OpnFiWriteExt<W>
    for OpnfiInformPacket<T>
{
    fn write<B: ByteOrder>(
        &self,
        key: Option<[u8; 16]>,
        iv: [u8; 16],
        wtr: &mut W,
    ) -> io::Result<()> {
        let key = key.unwrap_or(MASTER_INFORM_KEY);
        let mut aad = Vec::new();
        aad.write_u32::<B>(self.magic_header)?;
        aad.write_u32::<B>(self.packet_version)?;
        aad.write_all(&self.hardware_address.bytes())?;
        aad.write_u16::<B>(self.flags)?;
        aad.write_all(&iv)?;
        aad.write_u32::<B>(self.payload_version)?;

        let payload_data = Ok(self.payload.clone().into())
            .and_then(|data| {
                if self.flags & (OpnfiInformPacketFlag::SnappyCompressed as u16) != 0 {
                    compression::encode_snappy(&data)
                } else if self.flags & (OpnfiInformPacketFlag::ZLibCompressed as u16) != 0 {
                    compression::encode_zlib(&data)
                } else {
                    Ok(data)
                }
            })
            .and_then(|data| {
                if self.flags & (OpnfiInformPacketFlag::EncryptedGCM as u16) != 0 {
                    aad.write_u32::<B>((data.len() + 16) as u32)?;
                    cipher::encode_gcm(data.as_slice(), &key, Some(&iv), &aad)
                } else if self.flags & (OpnfiInformPacketFlag::Encrypted as u16) != 0 {
                    let data = cipher::encode_cbc(data.as_slice(), &key, Some(&iv))?;
                    aad.write_u32::<B>(data.len() as u32)?;
                    Ok(data)
                } else {
                    Ok(data)
                }
            })?;

        wtr.write_all(&aad)?;
        wtr.write_all(&payload_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::BigEndian;
    use rand;
    use rand::prelude::*;
    use std::{
        error,
        io::{self, Seek, SeekFrom},
    };

    type Result = std::result::Result<(), Box<dyn error::Error + 'static>>;

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct TestPayload(String);

    impl From<Vec<u8>> for TestPayload {
        fn from(data: Vec<u8>) -> Self {
            TestPayload(String::from_utf8(data).unwrap_or_default())
        }
    }

    impl From<TestPayload> for Vec<u8> {
        fn from(data: TestPayload) -> Self {
            data.0.into_bytes()
        }
    }

    fn get_test_packet(flags: u16) -> OpnfiInformPacket<TestPayload> {
        OpnfiInformPacket::new(
            Some(UNIFI_MAGIC_HEADER),
            0,
            MacAddress::new([0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
            flags,
            1,
            TestPayload(String::from("Hello World!")),
        )
    }

    macro_rules! packet_tests {
        ($($name:ident: $flags:expr,)*) => {
            $(
                #[test]
                fn $name () -> Result {
                    let packet_in: OpnfiInformPacket<TestPayload> = get_test_packet($flags);
                    let mut initialization_vector = [0u8; 16];
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    rng.fill_bytes(&mut initialization_vector);
                    let mut packet_data = io::Cursor::new(Vec::new());
                    packet_in.write::<BigEndian>(None, initialization_vector, &mut packet_data)?;
                    packet_data.seek(io::SeekFrom::Start(0))?;
                    let packet_out: OpnfiInformPacket<TestPayload> = OpnfiInformPacket::read::<BigEndian>(None, Some(UNIFI_MAGIC_HEADER), &mut packet_data)?;
                    assert_eq!(packet_in, packet_out);
                    Ok(())
                }
            )*
        };
    }

    packet_tests! {
        test_gcm_zlib: OpnfiInformPacketFlag::EncryptedGCM as u16 | OpnfiInformPacketFlag::ZLibCompressed as u16,
        test_gcm_snappy: OpnfiInformPacketFlag::EncryptedGCM as u16 | OpnfiInformPacketFlag::SnappyCompressed as u16,
        test_cbc_zlib: OpnfiInformPacketFlag::Encrypted as u16 | OpnfiInformPacketFlag::ZLibCompressed as u16,
        test_cbc_snappy: OpnfiInformPacketFlag::Encrypted as u16 | OpnfiInformPacketFlag::SnappyCompressed as u16,
    }
}
