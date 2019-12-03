use pnet::{
    datalink::{interfaces, NetworkInterface},
    util::MacAddr,
};
use std::str::FromStr;
use std::{fs, io, path};

#[derive(PartialEq, Clone, Debug)]
pub(crate) struct UnixNetworkDevice {
    name: String,
    mac: MacAddr,
    interface: NetworkInterface,
    statistics: UnixNetworkDeviceStatistics,
}

impl UnixNetworkDevice {
    pub fn new(name: &String) -> io::Result<UnixNetworkDevice> {
        let device_path = path::Path::new("/sys/class/net").join(name);
        if !device_path.as_path().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unable to locate UnixNetworkDevice {}", name),
            ));
        }

        let mac_string = fs::read_to_string(device_path.join("address"))?;
        if mac_string.trim().len() < 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mac address is empty.",
            ));
        }
        let mac = MacAddr::from_str(mac_string.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let interface = interfaces().into_iter().filter(|i| i.name == *name).next();
        if interface.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unable to locate NetworkInterface {}", name),
            ));
        }
        let interface = interface.unwrap();

        let statistics = UnixNetworkDeviceStatistics::new(name);

        Ok(UnixNetworkDevice {
            name: name.clone(),
            mac,
            interface,
            statistics,
        })
    }

    pub fn refresh(&mut self) -> io::Result<()> {
        self.statistics = UnixNetworkDeviceStatistics::new(&self.name);
        Ok(())
    }

    pub fn list_devices() -> io::Result<Vec<Self>> {
        let device_names = fs::read_dir("/sys/class/net")?
            .filter(|dn| dn.is_ok())
            .map(|dn| dn.unwrap())
            .filter(|dn| dn.path().is_dir())
            .map(|dn| String::from(dn.file_name().to_str().unwrap()))
            .map(|dn| Self::new(&dn))
            .filter(|d| d.is_ok())
            .map(|d| d.unwrap())
            .collect();
        Ok(device_names)
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    pub fn interface(&self) -> NetworkInterface {
        self.interface.clone()
    }

    pub fn statistics(&self) -> UnixNetworkDeviceStatistics {
        self.statistics.clone()
    }
}

// ===== Statistics =====

#[derive(PartialOrd, PartialEq, Clone, Debug)]
pub(crate) struct UnixNetworkDeviceStatistics {
    pub collisions: usize,
    pub multicast: usize,
    pub rx_bytes: usize,
    pub rx_compressed: usize,
    pub rx_crc_errors: usize,
    pub rx_dropped: usize,
    pub rx_errors: usize,
    pub rx_fifo_errors: usize,
    pub rx_frame_errors: usize,
    pub rx_length_errors: usize,
    pub rx_missed_errors: usize,
    pub rx_nohandler: usize,
    pub rx_over_errors: usize,
    pub rx_packets: usize,
    pub tx_aborted_errors: usize,
    pub tx_bytes: usize,
    pub tx_carrier_errors: usize,
    pub tx_compressed: usize,
    pub tx_dropped: usize,
    pub tx_errors: usize,
    pub tx_fifo_errors: usize,
    pub tx_heartbeat_errors: usize,
    pub tx_packets: usize,
    pub tx_window_errors: usize,
}

impl UnixNetworkDeviceStatistics {
    pub fn new(device_name: &String) -> UnixNetworkDeviceStatistics {
        let read_value = |statistic_name: &str| -> io::Result<usize> {
            let stat_path = path::Path::new("/sys/class/net")
                .join(device_name)
                .join("statistics")
                .join(statistic_name);
            let value = fs::read_to_string(stat_path.as_path())?;
            usize::from_str(value.trim())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
        };

        UnixNetworkDeviceStatistics {
            collisions: read_value("collisions").unwrap_or_default(),
            multicast: read_value("multicast").unwrap_or_default(),
            rx_bytes: read_value("rx_bytes").unwrap_or_default(),
            rx_compressed: read_value("rx_compressed").unwrap_or_default(),
            rx_crc_errors: read_value("rx_crc_errors").unwrap_or_default(),
            rx_dropped: read_value("rx_dropped").unwrap_or_default(),
            rx_errors: read_value("rx_errors").unwrap_or_default(),
            rx_fifo_errors: read_value("rx_fifo_errors").unwrap_or_default(),
            rx_frame_errors: read_value("rx_frame_errors").unwrap_or_default(),
            rx_length_errors: read_value("rx_length_errors").unwrap_or_default(),
            rx_missed_errors: read_value("rx_missed_errors").unwrap_or_default(),
            rx_nohandler: read_value("rx_nohandler").unwrap_or_default(),
            rx_over_errors: read_value("rx_over_errors").unwrap_or_default(),
            rx_packets: read_value("rx_packets").unwrap_or_default(),
            tx_aborted_errors: read_value("tx_aborted_errors").unwrap_or_default(),
            tx_bytes: read_value("tx_bytes").unwrap_or_default(),
            tx_carrier_errors: read_value("tx_carrier_errors").unwrap_or_default(),
            tx_compressed: read_value("tx_compressed").unwrap_or_default(),
            tx_dropped: read_value("tx_dropped").unwrap_or_default(),
            tx_errors: read_value("tx_errors").unwrap_or_default(),
            tx_fifo_errors: read_value("tx_fifo_errors").unwrap_or_default(),
            tx_heartbeat_errors: read_value("tx_heartbeat_errors").unwrap_or_default(),
            tx_packets: read_value("tx_packets").unwrap_or_default(),
            tx_window_errors: read_value("tx_window_errors").unwrap_or_default(),
        }
    }
}
