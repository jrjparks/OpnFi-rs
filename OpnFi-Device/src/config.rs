use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::path;
use toml;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub(crate) struct Config {
    pub capability: Vec<String>,
    pub cfgversion: String,
    pub selfrun_guest_mode: String,
    pub led_enabled: bool,
    pub stun_url: String,
    pub mgmt_url: String,
    pub authkey: String,
    pub use_aes_gcm: bool,
    pub report_crash: bool,
}

impl Config {
    pub fn new() -> Self {
        Config {
            capability: Vec::new(),
            cfgversion: String::new(),
            selfrun_guest_mode: String::new(),
            led_enabled: false,
            stun_url: String::new(),
            mgmt_url: String::new(),
            authkey: String::new(),
            use_aes_gcm: false,
            report_crash: false,
        }
    }

    pub fn update_from_mgmt_cfg(&mut self, mgmt_cfg: String) {
        for cfg_line in mgmt_cfg.lines() {
            let pair: Vec<_> = cfg_line.splitn(2, "=").collect();
            match (pair[0], pair[1]) {
                ("capability", val) => {
                    self.capability = val.split(",").map(|s| String::from(s)).collect()
                }
                ("selfrun_guest_mode", val) => self.selfrun_guest_mode = String::from(val),
                ("cfgversion", val) => self.cfgversion = String::from(val),
                ("led_enabled", val) => self.led_enabled = val.eq("true"),
                ("stun_url", val) => self.stun_url = String::from(val),
                ("mgmt_url", val) => self.mgmt_url = String::from(val),
                ("authkey", val) => self.authkey = String::from(val),
                ("use_aes_gcm", val) => self.use_aes_gcm = val.eq("true"),
                ("report_crash", val) => self.report_crash = val.eq("true"),
                (k, v) => warn!("Unknown Config entry: {} = {}", k, v),
            }
        }
    }

    pub fn from_mgmt_cfg(mgmt_cfg: String) -> Self {
        let mut cfg: Self = Self::new();
        cfg.update_from_mgmt_cfg(mgmt_cfg);
        cfg
    }

    pub fn load(path: &String) -> io::Result<Self> {
        let path = path::Path::new(&path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut file = OpenOptions::new()
            .write(false)
            .read(true)
            .create(false)
            .open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        toml::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    pub fn save(&self, path: &String) -> io::Result<()> {
        let path = path::Path::new(&path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .read(false)
            .create(true)
            .truncate(true)
            .open(path)?;
        let data =
            toml::to_vec(&self).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        file.write_all(&data)
    }
}
