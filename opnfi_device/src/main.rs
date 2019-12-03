#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate clap;
extern crate lib_opnfi;
use crate::config::Config;
use crate::util::*;
use lib_opnfi::inform::payload::gateway::OpnFiInformGatewayPayload;
use lib_opnfi::inform::payload::net::{
    OpnFiInformConfigPortTableItem, OpnFiInformNetworkConfig, OpnFiInformNetworkInterface,
};
use lib_opnfi::inform::payload::stats::OpnFiInformSystemStatus;
use lib_opnfi::inform::payload::{command::OpnFiInformPayloadCommand, OpnFiInformPayload};
use lib_opnfi::inform::{OpnFiReadExt, OpnFiWriteExt, OpnfiInformPacket, OpnfiInformPacketFlag};
use rand::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{
    error, fs, io, path,
    thread::sleep,
    time::{Duration, Instant},
};
use sysinfo::{ProcessorExt, SystemExt};

mod config;
mod net;
mod util;

type Result = std::result::Result<(), Box<dyn error::Error + 'static>>;

fn main() -> Result {
    if simple_logger::init_with_level(log::Level::Info).is_err() {
        panic!("Unable to start logger!");
    }

    let matches = clap::App::new("OpnFi Device")
        .version("0.1.0")
        .author("James Parks <jrjparks@zathera.com>")
        .about("Emulates a UniFi device")
        .arg(
            clap::Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a config file path to use")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("controller")
                .long("controller")
                .value_name("FILE")
                .help("Sets a config file path to use")
                .takes_value(true),
        )
        .get_matches();

    let config_path = String::from(matches.value_of("config").unwrap_or("./config/opnfi.toml"));
    let config_path = path::Path::new(&config_path);
    if let Some(cfg_path) = config_path.to_str() {
        info!("Using config path: {}", cfg_path);
    }
    let mut config = config::Config::load(config_path).ok();
    if config.is_none() {
        info!("Unable to locate existing config, entering adoption mode.");
    }

    let inform_url = match matches.value_of("controller") {
        Some(host) => format!("http://{}:8080/inform", host),
        None => match &config {
            Some(config) => config.inform_url.clone(),
            None => String::from("http://unifi:8080/inform"),
        },
    };
    info!("Reporting inform packets to {}", inform_url);

    let mut net_devices = net::device::UnixNetworkDevice::list_devices()?;

    let mut sysinf = sysinfo::System::new();
    let http_client = reqwest::Client::new();
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut infom_interval = 10;
    let mut last_inform = Instant::now()
        .checked_sub(Duration::from_secs(infom_interval))
        .unwrap();
    let mut send_inform = true;
    let running = Arc::new(AtomicBool::new(true));
    let loop_running = running.clone();
    ctrlc::set_handler(move || {
        loop_running.store(false, Ordering::SeqCst);
    })
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now.duration_since(last_inform).as_secs() >= infom_interval {
            send_inform = true;
            sysinf.refresh_all();
            for net_dev in &mut net_devices {
                net_dev.refresh()?;
                // info!("Refreshed network device: {:?}", net_dev);
            }
        }

        if send_inform {
            send_inform = false;
            last_inform = now;

            // Load SysInfo for inform
            let uptime = sysinf.get_uptime() as u64;
            let mem_used = sysinf.get_used_memory() as f32;
            let mem_total = sysinf.get_total_memory() as f32;
            let mem_usage = (mem_used / mem_total * 100f32) as u64;
            let procs = sysinf.get_processor_list();
            let cpu_usage = (procs[0].get_cpu_usage() * 100f32) as u64;

            // Load key
            let key = match &config {
                Some(config) => hex::decode(config.authkey.as_str())
                    .map(|v| copy_to_array(v.as_slice()))
                    .ok(),
                _ => None,
            };

            // Packet flags
            let mut flags = OpnfiInformPacketFlag::Encrypted as u16
                | OpnfiInformPacketFlag::ZLibCompressed as u16;
            if let Some(config) = &config {
                if config.use_aes_gcm {
                    flags |= OpnfiInformPacketFlag::EncryptedGCM as u16;
                }
            }

            // Initialization Vector for crypto
            let mut initialization_vector = [0u8; 16];
            rng.fill_bytes(&mut initialization_vector);

            // Interfaces
            let wan = net::device::UnixNetworkDevice::new(&String::from("wlp3s0"))?;
            let wan_interface: OpnFiInformNetworkInterface = wan.clone().into();

            let lan = net::device::UnixNetworkDevice::new(&String::from("virbr1"))?;
            let lan_interface: OpnFiInformNetworkInterface = lan.clone().into();

            // Payload
            let payload = OpnFiInformPayload::Gateway(OpnFiInformGatewayPayload {
                bootrom_version: "pfsense".to_string(),
                cfgversion: match &config {
                    Some(config) => config.cfgversion.clone(),
                    _ => "0123456789abcdef".to_string(),
                },
                config_network_wan: OpnFiInformNetworkConfig::DHCP,
                config_network_wan2: OpnFiInformNetworkConfig::default(),
                config_port_table: vec![
                    OpnFiInformConfigPortTableItem::new("wan".to_string(), "wlp3s0".to_string()),
                    OpnFiInformConfigPortTableItem::new("lan".to_string(), "virbr1".to_string()),
                ],
                default: config.is_none(),
                discovery_response: false,
                fw_caps: std::i32::MAX,
                has_eth1: true,
                has_ssh_disable: true,
                hostname: "fake-dev.local".to_string(),
                inform_url: inform_url.clone(),
                if_table: vec![wan_interface.clone(), lan_interface.clone()],
                ip: wan_interface.ip,
                mac: wan_interface.mac,
                model: "UGWXG".to_string(),
                model_display: "Netgate SG-4860".to_string(),
                // model_display: "UniFi Security Gateway XG-8".to_string(),
                netmask: wan_interface.netmask,
                radius_caps: 0,
                required_version: "0.0.1".to_string(),
                selfrun_beacon: true,
                serial: "00DEADBEEF00".to_string(),
                state: 1,
                system_status: OpnFiInformSystemStatus::new(
                    cpu_usage.to_string(),
                    mem_usage.to_string(),
                ),
                time: uptime as usize,
                uplink: "wlp3s0".to_string(),
                uptime: uptime as usize,
                version: "2.4.4-RELEASE-p3".to_string(),
                ..OpnFiInformGatewayPayload::default()
            });
            if true {
                match serde_json::to_string_pretty(&payload) {
                    Ok(json) => info!("{}", json),
                    Err(e) => warn!("{}", e),
                }
            }
            let inform_packet =
                lib_opnfi::inform::OpnfiInformPacket::new(None, 0, wan.mac(), flags, 1, payload);

            // Write Inform packet to a buffer
            let mut inform_data = Vec::new();
            inform_packet.write::<byteorder::NetworkEndian>(
                key,
                initialization_vector,
                &mut inform_data,
            )?;

            let inform_response = http_client
                .post(inform_url.as_str())
                .body(inform_data)
                .send();

            if let Ok(mut inform_response) = inform_response {
                info!("Sent inform packet");
                if inform_response.status().is_success() {
                    info!("Parsing inform packet response...");
                    if let Some(body_length) = inform_response.content_length() {
                        if body_length >= 40 {
                            let mut inform_response_body = Vec::new();
                            inform_response.copy_to(&mut inform_response_body)?;
                            let mut inform_response_body = io::Cursor::new(inform_response_body);
                            let packet: lib_opnfi::Result<OpnfiInformPacket<OpnFiInformPayload>> =
                                OpnfiInformPacket::read::<byteorder::NetworkEndian>(
                                    key,
                                    None,
                                    &mut inform_response_body,
                                );
                            if let Ok(packet) = packet {
                                match packet.payload {
                                    OpnFiInformPayload::Command(cmd) => match cmd {
                                        OpnFiInformPayloadCommand::NoOp(noop) => {
                                            infom_interval = noop.interval().as_secs()
                                        }
                                        OpnFiInformPayloadCommand::SetParam(params) => {
                                            if let Some(mgmt_cfg) = params.mgmt_cfg {
                                                match &mut config {
                                                    Some(config) => {
                                                        config.update_from_mgmt_cfg(mgmt_cfg)
                                                    }
                                                    None => {
                                                        config =
                                                            Some(Config::from_mgmt_cfg(mgmt_cfg))
                                                    }
                                                }
                                                if let Some(config) = &config {
                                                    match config.save(&config_path) {
                                                        Ok(_) => info!("Config save: OK"),
                                                        Err(e) => {
                                                            error!("Config save: Err -> {}", e)
                                                        }
                                                    }
                                                }
                                                send_inform = true;
                                            }
                                        }
                                        OpnFiInformPayloadCommand::SetDefault(_) => {
                                            fs::remove_file(config_path)?;
                                            config = None;
                                            send_inform = true;
                                        }
                                        cmd => warn!("Unhandled Command: {:?}", cmd),
                                    },
                                    payload => warn!("Unhandled: {:?}", payload),
                                }
                            }
                        }
                    }
                } else if config.is_none() {
                    info!("Device is pending adoption");
                    infom_interval = 10;
                } else {
                    warn!(
                        "Controller response status code: {}",
                        inform_response.status()
                    );
                    infom_interval = 10;
                }
            } else {
                warn!("Unable to send inform packet.");
                infom_interval = 10;
            }
        }

        sleep(Duration::from_millis(100));
    }

    info!("Shutting down...");

    Ok(())
}
