//! Windows TUN uplink discovery excludes the TUN's own split default routes.
#[cfg(windows)]
use anyhow::{bail, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uplink {
    pub index: u32,
    pub gateway: u32,
    pub source: u32,
}

/// Keeps a change pending until recovery succeeds; reconnecting to the same
/// Wi-Fi still needs new sessions after a period without a default route.
#[derive(Default)]
pub struct Recovery {
    applied: Option<Uplink>,
    offline: bool,
}
impl Recovery {
    pub fn new(applied: Uplink) -> Self { Self { applied: Some(applied), offline: false } }
    pub fn needed(&mut self, next: Option<&Uplink>, resumed: bool) -> bool {
        let Some(next) = next else { self.offline = true; return false };
        if resumed { self.offline = true; }
        self.offline || self.applied.as_ref() != Some(next)
    }
    pub fn applied(&mut self, next: Uplink) { self.applied = Some(next); self.offline = false; }
}

#[cfg(windows)]
pub fn uplink(exclude: u32) -> Result<Uplink> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::Networking::WinSock::*;
    unsafe {
        let mut table = std::ptr::null_mut();
        let error = GetIpForwardTable2(AF_INET, &mut table);
        if error != 0 { bail!("GetIpForwardTable2: {error}"); }
        struct Table(*mut MIB_IPFORWARD_TABLE2);
        impl Drop for Table { fn drop(&mut self) { unsafe { FreeMibTable(self.0.cast()); } } }
        let table = Table(table);
        let rows = std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize);
        let mut choices = Vec::new();
        for route in rows {
            if route.InterfaceIndex == exclude || route.DestinationPrefix.PrefixLength != 0 || route.Loopback != 0 || route.ValidLifetime == 0 { continue; }
            let mut iface: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            iface.Family = AF_INET;
            iface.InterfaceIndex = route.InterfaceIndex;
            if GetIpInterfaceEntry(&mut iface) != 0 || iface.Connected == 0 { continue; }
            let mut dest: SOCKADDR_INET = std::mem::zeroed();
            dest.Ipv4.sin_family = AF_INET;
            dest.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([1, 1, 1, 1]);
            let mut best = std::mem::zeroed();
            let mut source: SOCKADDR_INET = std::mem::zeroed();
            if GetBestRoute2(std::ptr::null(), route.InterfaceIndex, std::ptr::null(), &dest, 0, &mut best, &mut source) != 0 { continue; }
            choices.push((route.Metric as u64 + iface.Metric as u64, Uplink {
                index: route.InterfaceIndex, gateway: route.NextHop.Ipv4.sin_addr.S_un.S_addr,
                source: source.Ipv4.sin_addr.S_un.S_addr,
            }));
        }
        choices.sort_by_key(|(metric, uplink)| (*metric, uplink.index));
        choices.into_iter().next().map(|(_, u)| u).ok_or_else(|| anyhow::anyhow!("no connected non-TUN IPv4 default route"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wifi() -> Uplink { Uplink { index: 7, gateway: 1, source: 2 } }
    #[test]
    fn reconnect_resume_and_address_change_require_recovery() {
        let original = wifi();
        let mut r = Recovery::new(original.clone());
        assert!(!r.needed(Some(&original), false));
        assert!(!r.needed(None, false));
        assert!(r.needed(Some(&original), false));
        assert!(r.needed(Some(&original), false), "failed recovery must be retried");
        r.applied(original.clone());
        assert!(!r.needed(Some(&original), false));
        assert!(r.needed(Some(&original), true));
        r.applied(original.clone());
        let changed = Uplink { source: 3, ..original };
        assert!(r.needed(Some(&changed), false));
        r.applied(changed.clone());
        assert!(!r.needed(Some(&changed), false));
        assert!(r.needed(Some(&Uplink { index: 9, ..changed }), false));
    }
    #[cfg(windows)]
    #[test]
    fn reads_route_table_without_changing_network() {
        // Disconnected machines may have no route; errors must be recoverable.
        if let Ok(u) = uplink(0) { assert_ne!(u.index, 0); }
    }
}
