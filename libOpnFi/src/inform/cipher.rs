use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use openssl::symm::{decrypt, decrypt_aead, encrypt, encrypt_aead, Cipher};
use std::io;
use std::io::prelude::*;

const TAG_SIZE: usize = 16;

// ===== AES-GCM =====

pub(crate) fn decode_gcm(
    data: &[u8],
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let (data, tag) = data.split_at(data.len() - TAG_SIZE);
    let plain_data = decrypt_aead(Cipher::aes_128_gcm(), key, iv, aad, data, tag)?;
    Ok(plain_data)
}

pub(crate) fn encode_gcm(
    data: &[u8],
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let mut tag = [0; TAG_SIZE];
    let mut cipher_data = encrypt_aead(Cipher::aes_128_gcm(), key, iv, aad, data, &mut tag)?;
    cipher_data.write_all(&tag)?;
    Ok(cipher_data)
}

// ===== AES-CBC =====

pub(crate) fn decode_cbc(data: &[u8], key: &[u8], iv: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let plain_data = decrypt(Cipher::aes_128_cbc(), key, iv, data)?;
    Ok(plain_data)
}

pub(crate) fn encode_cbc(data: &[u8], key: &[u8], iv: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let cipher_data = encrypt(Cipher::aes_128_cbc(), key, iv, data)?;
    Ok(cipher_data)
}
