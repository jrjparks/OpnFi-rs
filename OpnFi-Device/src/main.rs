#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate clap;
extern crate libOpnFi;
use crate::config::Config;
use libOpnFi::inform::payload::inform::{
    OpnFiInformGatewayPayload, OpnFiInformNetworkConfig, OpnFiInformSystemStatus,
};
use libOpnFi::inform::payload::{command::OpnFiInformPayloadCommand, OpnFiInformPayload};
use libOpnFi::inform::{OpnFiReadExt, OpnFiWriteExt, OpnfiInformPacket, OpnfiInformPacketFlag};
use rand::prelude::*;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{
    error, fs, io, path,
    thread::sleep,
    time::{Duration, Instant},
};
use sysinfo::{NetworkExt, ProcessorExt, SystemExt};

mod config;
mod net;

type Result = std::result::Result<(), Box<dyn error::Error + 'static>>;

struct SimpleInformPayload {}

fn copy_to_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

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
                .takes_value(true)
                .default_value("unifi"),
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

    let inform_host = matches.value_of("controller").unwrap_or("unifi");
    info!("Reporting inform packets to {}", inform_host);
    let inform_url = format!("http://{}:8080/inform", inform_host);

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

            // Payload
            let payload = OpnFiInformPayload::Gateway(OpnFiInformGatewayPayload {
                bootrom_version: "pfsense".to_string(),
                cfgversion: match &config {
                    Some(config) => config.cfgversion.clone(),
                    _ => "0123456789abcdef".to_string(),
                },
                config_network_wan: OpnFiInformNetworkConfig::DHCP,
                config_network_wan2: OpnFiInformNetworkConfig::default(),
                default: config.is_none(),
                discovery_response: false,
                fw_caps: std::i32::MAX,
                has_default_route_distance: false,
                has_dnsmasq_hostfile_update: false,
                has_dpi: false,
                has_eth1: true,
                has_porta: false,
                has_ssh_disable: true,
                has_vti: false,
                hostname: "fake-dev.local".to_string(),
                inform_url: inform_url.clone(),
                ip: "1.2.3.4".to_string(),
                isolated: false,
                locating: false,
                mac: "00:de:ad:be:ef:00".to_string(),
                model: "UGWXG".to_string(),
                model_display: "Netgate SG-4860".to_string(),
                // model_display: "UniFi Security Gateway XG-8".to_string(),
                netmask: "255.255.255.0".to_string(),
                radius_caps: 0,
                required_version: "0.0.0".to_string(),
                selfrun_beacon: true,
                serial: "00DEADBEEF00".to_string(),
                state: 1,
                system_status: OpnFiInformSystemStatus::new(
                    cpu_usage.to_string(),
                    mem_usage.to_string(),
                ),
                time: uptime as usize,
                uplink: "eth0".to_string(),
                uptime: uptime as usize,
                version: "2.4.4-RELEASE-p3".to_string(),
            });
            if false {
                match serde_json::to_string_pretty(&payload) {
                    Ok(json) => info!("{}", json),
                    Err(e) => warn!("{}", e),
                }
            }
            let mac = mac_address::MacAddress::from_str("00:de:ad:be:ef:00")?;
            let inform_packet =
                libOpnFi::inform::OpnfiInformPacket::new(None, 0, mac, flags, 1, payload);

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
                            let packet: io::Result<OpnfiInformPacket<OpnFiInformPayload>> =
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
                                        _ => warn!("Unhandled Command"),
                                    },
                                    payload => warn!("Unhandled: {:?}", payload),
                                }
                            }
                        }
                    }
                } else if config.is_none() {
                    info!("Device is pending adoption")
                } else {
                    warn!(
                        "Controller response status code: {}",
                        inform_response.status()
                    );
                }
            } else {
                warn!("Unable to send inform packet.")
            }
        }

        sleep(Duration::from_millis(100));
    }

    info!("Shutting down...");

    Ok(())
}
