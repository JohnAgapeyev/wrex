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
    /// `ifindex` files. Live addresses come from ONE `get_if_addrs()`
    /// pass (perf-pass 3c: the tranche-3 shape re-enumerated the
    /// interface table per interface, per family — ~2N netlink dumps
    /// at every raw-verb startup, ~10ms measured on the dev host; tests
    /// pass a controlled address list).
    pub fn from_sysfs(root: &Path) -> Result<Self, std::io::Error> {
        let addrs = if_addrs::get_if_addrs().unwrap_or_default();
        Self::from_sysfs_with_addrs(root, &addrs)
    }

    /// [`IfTable::from_sysfs`] with the address enumeration supplied —
    /// the testable core (fixtures own the sysfs tree; tests own the
    /// addresses, so no live netlink rides the unit suite).
    pub fn from_sysfs_with_addrs(
        root: &Path,
        addrs: &[if_addrs::Interface],
    ) -> Result<Self, std::io::Error> {
        // One pass over the address list, partitioned per interface.
        let mut v4s: BTreeMap<&str, Vec<std::net::Ipv4Addr>> = BTreeMap::new();
        let mut v6s: BTreeMap<&str, Vec<std::net::Ipv6Addr>> = BTreeMap::new();
        for a in addrs {
            match a.addr.ip() {
                std::net::IpAddr::V4(v4) => v4s.entry(a.name.as_str()).or_default().push(v4),
                std::net::IpAddr::V6(v6) => {
                    // Link-local fe80::/10 never sources a scan/query
                    // (tranche 7b's convention) — only routable v6s.
                    if !is_link_local(v6) {
                        v6s.entry(a.name.as_str()).or_default().push(v6)
                    }
                }
            }
        }
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
            let ipv4s = v4s.get(name.as_str()).cloned().unwrap_or_default();
            let ipv6s = v6s.get(name.as_str()).cloned().unwrap_or_default();
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

    /// The perf-pass 3c core: one address list serves every interface —
    /// v4 + routable v6 attach by name, link-local `fe80::/10` is
    /// skipped (the tranche-7b routable-source convention), and an
    /// interface absent from the list gets no addresses (never an
    /// error). Hermetic: the address list is supplied, no live netlink.
    #[test]
    fn addrs_partition_one_pass() {
        fn mk(name: &str, ip: std::net::IpAddr) -> if_addrs::Interface {
            let addr = match ip {
                std::net::IpAddr::V4(ip) => if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip,
                    netmask: std::net::Ipv4Addr::from([255, 255, 255, 0]),
                    prefixlen: 24,
                    broadcast: None,
                }),
                std::net::IpAddr::V6(ip) => if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                    ip,
                    netmask: std::net::Ipv6Addr::from([
                        0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    prefixlen: 64,
                    broadcast: None,
                }),
            };
            if_addrs::Interface {
                name: name.to_string(),
                addr,
                index: Some(1),
                oper_status: if_addrs::IfOperStatus::Up,
                is_p2p: false,
            }
        }
        let addrs = vec![
            mk("lo", "127.0.0.1".parse().unwrap()),
            mk("lo", "fd00::1".parse().unwrap()),
            mk("lo", "fe80::1".parse().unwrap()), // link-local: skipped
            mk("eth0", "192.0.2.10".parse().unwrap()),
            mk("wlan9", "198.51.100.7".parse().unwrap()), // not in sysfs: ignored
        ];
        let t = IfTable::from_sysfs_with_addrs(&fixture(), &addrs).unwrap();
        let lo = t.get("lo").unwrap();
        assert_eq!(
            lo.ipv4s,
            vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            lo.ipv6s,
            vec!["fd00::1".parse::<std::net::Ipv6Addr>().unwrap()],
            "the link-local must be skipped"
        );
        let eth0 = t.get("eth0").unwrap();
        assert_eq!(
            eth0.ipv4s,
            vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert!(eth0.ipv6s.is_empty());
    }
}
