//! Interface table: `name`, `mac`, `mtu`, `up`, IPv4 addresses, `ifindex`,
//! from `/sys/class/net/*` (+ `if_addrs` for IPv4s). Testable with fixture
//! dirs via [`IfTable::from_sysfs`].

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
/// One interface entry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct IfEntry {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub up: bool,
    pub ipv4s: Vec<std::net::Ipv4Addr>,
    /// Live IPv6 addresses (tranche 7b: `--server`/scan v6 source pick).
    pub ipv6s: Vec<std::net::Ipv6Addr>,
    /// `sysfs` ifindex (from `/sys/class/net/<name>/ifindex`).
    pub ifindex: i32,
}

/// All interfaces, keyed by name (BTreeMap: stable ordering).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfTable {
    entries: BTreeMap<String, IfEntry>,
}

impl IfTable {
    /// Empty table (fixture/test default).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from a sysfs-style root directory (`/sys/class/net` layout):
    /// one subdirectory per interface with `address`, `mtu`, `flags`,
    /// `ifindex` files.
    pub fn from_sysfs(root: &Path) -> Result<Self, std::io::Error> {
        let mut entries = BTreeMap::new();
        let dir = fs::read_dir(root)?;
        for dent in dir.flatten() {
            let name = dent.file_name().to_string_lossy().to_string();
            // Skip non-directories (sysfs may have compat files).
            if !dent.path().is_dir() {
                continue;
            }
            let read_trim = |file: &str| -> Option<String> {
                fs::read_to_string(dent.path().join(file))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            let mac = parse_mac(&read_trim("address").unwrap_or_default());
            let mtu: u32 = read_trim("mtu").and_then(|s| s.parse().ok()).unwrap_or(0);
            let up = is_up(&read_trim("flags").unwrap_or_default());
            let ifindex: i32 = read_trim("ifindex")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let ipv4s = crate::iface::system_ipv4s_for(&name);
            let ipv6s = crate::iface::system_ipv6s_for(&name);
            entries.insert(
                name.clone(),
                IfEntry {
                    name,
                    mac,
                    mtu,
                    up,
                    ipv4s,
                    ipv6s,
                    ifindex,
                },
            );
        }
        Ok(Self { entries })
    }

    /// Build from the live system (`/sys/class/net` + `if_addrs`).
    pub fn from_system() -> Result<Self, std::io::Error> {
        Self::from_sysfs(Path::new("/sys/class/net"))
    }

    pub fn get(&self, name: &str) -> Option<&IfEntry> {
        self.entries.get(name)
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = &IfEntry> {
        self.entries.values()
    }
}

/// Parse `aa:bb:cc:dd:ee:ff` (sysfs uses `:`; also tolerate `-`).
fn parse_mac(raw: &str) -> [u8; 6] {
    let sep = if raw.contains(':') { ':' } else { '-' };
    let mut mac = [0u8; 6];
    for (i, part) in raw.split(sep).take(6).enumerate() {
        mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    mac
}

/// `flags` file is `0x<hex>`; IFF_UP is 0x1.
fn is_up(flags: &str) -> bool {
    let hex = flags.trim_start_matches("0x");
    u64::from_str_radix(hex, 16)
        .map(|f| f & 0x1 != 0)
        .unwrap_or(false)
}

/// Live IPv4 addresses for one interface via `if_addrs` (used by both
/// `from_sysfs` fixtures and `from_system`).
pub(crate) fn system_ipv4s_for(name: &str) -> Vec<std::net::Ipv4Addr> {
    if_addrs::get_if_addrs()
        .map(|addrs| {
            addrs
                .iter()
                .filter(|a| a.name == name)
                .filter_map(|a| match a.addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Live IPv6 addresses for one interface via `if_addrs` (tranche 7b).
/// Link-local `fe80::/10` addresses are skipped: a scan/`query --tcp`
/// source wants a routable address.
pub(crate) fn system_ipv6s_for(name: &str) -> Vec<std::net::Ipv6Addr> {
    if_addrs::get_if_addrs()
        .map(|addrs| {
            addrs
                .iter()
                .filter(|a| a.name == name)
                .filter_map(|a| match a.addr.ip() {
                    std::net::IpAddr::V6(v6) => Some(v6),
                    std::net::IpAddr::V4(_) => None,
                })
                .filter(|v6| !is_link_local(*v6))
                .collect()
        })
        .unwrap_or_default()
}

/// The interface's link-local address (`fe80::/10`), if any — the NDP
/// NS source preference (tranche 10b; RFC 4861 §7.3.3).
pub(crate) fn system_ipv6_ll_for(name: &str) -> Option<std::net::Ipv6Addr> {
    if_addrs::get_if_addrs().ok().and_then(|addrs| {
        addrs
            .iter()
            .filter(|a| a.name == name)
            .filter_map(|a| match a.addr.ip() {
                std::net::IpAddr::V6(v6) => Some(v6),
                std::net::IpAddr::V4(_) => None,
            })
            .find(|v6| is_link_local(*v6))
    })
}

/// `fe80::/10` link-local check (per RFC 4291 §2.5.6).
fn is_link_local(a: std::net::Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Fixture sysfs tree. Each call gets a unique directory: tests run in
    /// parallel and share `std::env::temp_dir()`.
    fn fixture() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wrex-iftable-test-{n}"));
        let _ = fs::remove_dir_all(&dir);
        for (name, mac, mtu, flags) in [
            ("lo", "00:00:00:00:00:00", "65536", "0x10049"),
            ("eth0", "aa:bb:cc:dd:ee:ff", "1500", "0x1043"),
        ] {
            let d = dir.join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("address"), mac).unwrap();
            fs::write(d.join("mtu"), mtu).unwrap();
            fs::write(d.join("flags"), flags).unwrap();
            fs::write(d.join("ifindex"), if name == "lo" { "1" } else { "2" }).unwrap();
        }
        dir
    }

    #[test]
    fn from_sysfs_fixture() {
        let t = IfTable::from_sysfs(&fixture()).unwrap();
        let names = t.names();
        assert_eq!(names, vec!["eth0".to_string(), "lo".to_string()]);
        let lo = t.get("lo").unwrap();
        assert_eq!(lo.mac, [0; 6]);
        assert_eq!(lo.mtu, 65536);
        assert!(lo.up);
        assert_eq!(lo.ifindex, 1);
        let eth0 = t.get("eth0").unwrap();
        assert_eq!(eth0.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(eth0.mtu, 1500);
        assert!(eth0.up);
        assert_eq!(eth0.ifindex, 2);
    }

    #[test]
    fn flags_parsing() {
        assert!(is_up("0x10049")); // IFF_UP | IFF_LOOPBACK | ...
        assert!(is_up("0x1043"));
        assert!(!is_up("0x1002")); // no IFF_UP
        assert!(!is_up("garbage"));
        assert!(!is_up(""));
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(parse_mac(""), [0; 6]);
        assert_eq!(parse_mac("zz:zz:zz:zz:zz:zz"), [0; 6]);
    }

    #[test]
    fn unknown_iface_errors_list_available() {
        let t = IfTable::from_sysfs(&fixture()).unwrap();
        assert!(t.get("wlan9").is_none());
        let e = crate::DriverError::IfaceNotFound {
            wanted: "wlan9".into(),
            available: t.names().join(", "),
        };
        assert!(e.to_string().contains("eth0, lo"), "{}", e);
    }
}
