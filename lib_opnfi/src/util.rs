use pnet::util::MacAddr;

pub fn bytes_to_mac(bytes: &[u8; 6]) -> MacAddr {
    MacAddr(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

pub fn mac_to_bytes(mac: &MacAddr) -> [u8; 6] {
    [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
}
