use regex::{self, Regex};
use std::io::BufRead;
use std::str::FromStr;
use std::{fs, io, net::IpAddr, path};

pub(crate) fn get_nameservers() -> io::Result<Vec<IpAddr>> {
    lazy_static! {
        static ref NAMESERVER_REGEX: Regex = Regex::new(r"^nameserver\s([\d.:a-f]+)$").unwrap();
    }
    let resolv_path = path::Path::new("/etc/resolv.conf");
    let mut nameservers = Vec::new();
    if resolv_path.exists() {
        let rdr = io::BufReader::new(fs::File::open(resolv_path)?);
        for line in rdr.lines() {
            if let Some(cap) = NAMESERVER_REGEX.captures(line?.as_str()) {
                if let Some(mat) = cap.get(1) {
                    nameservers.push(IpAddr::from_str(mat.as_str()).unwrap())
                }
            }
        }
        Ok(nameservers)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find /etc/resolv.conf",
        ))
    }
}
