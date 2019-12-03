use crate::net::device::UnixNetworkDevice;
use lib_opnfi::inform::payload::net::OpnFiInformNetworkInterface;

pub(crate) mod device;

impl From<device::UnixNetworkDevice> for OpnFiInformNetworkInterface {
    fn from(value: UnixNetworkDevice) -> Self {
        let interface = value.interface();
        let stats = value.statistics();
        let ip = interface
            .ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .next()
            .unwrap();
        Self {
            drops: stats.rx_dropped + stats.tx_dropped,
            enabled: true,
            full_duplex: true,
            gateways: vec![],
            ip: ip.ip().to_string(),
            latency: 1,
            mac: value.mac().to_string(),
            name: value.name().to_string(),
            nameservers: vec![],
            netmask: ip.mask().to_string(),
            num_port: interface.index as usize,
            rx_bytes: stats.rx_bytes,
            rx_dropped: stats.rx_dropped,
            rx_errors: stats.rx_errors,
            rx_multicast: 0,
            rx_packets: stats.rx_packets,
            speed: 1000,
            speedtest_lastrun: 0,
            speedtest_ping: 0,
            speedtest_status: "Idle".to_string(),
            tx_bytes: stats.tx_bytes,
            tx_dropped: stats.tx_dropped,
            tx_errors: stats.tx_errors,
            tx_packets: stats.tx_packets,
            up: true,
            uptime: 0,
            xput_down: 0,
            xput_up: 0,
        }
    }
}
