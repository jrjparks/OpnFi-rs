use flate2::{
    read::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use snap;
use std::io;
use std::io::prelude::*;

// ===== ZLib =====

/// Decode from ZLib compressed payload
pub(crate) fn decode_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut rdr = ZlibDecoder::new(data);
    let mut data = Vec::new();
    rdr.read_to_end(&mut data)?;
    Ok(data)
}

/// Encode to ZLib compressed payload
pub(crate) fn encode_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut rdr = ZlibEncoder::new(data, Compression::best());
    let mut data = Vec::new();
    rdr.read_to_end(&mut data)?;
    Ok(data)
}

// ===== Snappy =====

/// Decode from a Snappy compressed payload
pub(crate) fn decode_snappy(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut rdr = snap::Reader::new(data);
    let mut data = Vec::new();
    rdr.read_to_end(&mut data)?;
    Ok(data)
}

/// Encode to a Snappy compressed payload
pub(crate) fn encode_snappy(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut wtr = snap::Writer::new(Vec::new());
    wtr.write_all(data)?;
    let data = wtr
        .into_inner()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(data)
}
