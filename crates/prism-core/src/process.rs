//! Which program owns a connection, for PROCESS-NAME / PROCESS-PATH rules
//! (Windows). Connections arrive with the application's own socket address
//! as source (`127.0.0.1:port` on the mixed port, the TUN address in TUN
//! mode); the owning process is looked up in the system TCP / UDP tables.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Serialize;

use crate::tunnel::Network;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// File name, e.g. `chrome.exe`.
    pub name: String,
    /// Full image path (empty when the process can't be opened).
    pub path: String,
}

/// Owner of the socket bound to `local` (the connection source).
pub fn find(network: Network, local: SocketAddr) -> Option<Arc<ProcessInfo>> {
    imp::find(network, local)
}

/// Running processes with a known image path, one entry per path.
pub fn list() -> Vec<ProcessInfo> {
    imp::list()
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn find(_: Network, _: SocketAddr) -> Option<Arc<ProcessInfo>> {
        None
    }
    pub fn list() -> Vec<ProcessInfo> {
        Vec::new()
    }
}

/// macOS: the kernel's socket lists (`net.inet.{tcp,udp}.pcblist_n`), whose
/// `xsocket_n` records carry the last pid that used each socket; paths
/// from proc_pidpath. The record layout follows XNU's in_pcblist.c (each
/// part rounded up to 8 bytes), as mihomo reads it.
#[cfg(target_os = "macos")]
mod imp {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;

    fn sysctl(name: &str) -> Option<Vec<u8>> {
        let c = std::ffi::CString::new(name).ok()?;
        unsafe {
            let mut len = 0usize;
            if libc::sysctlbyname(c.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
                return None;
            }
            // The list can grow between the two calls.
            len += len / 4 + 4096;
            let mut buf = vec![0u8; len];
            if libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr() as *mut _, &mut len, std::ptr::null_mut(), 0) != 0 {
                return None;
            }
            buf.truncate(len);
            Some(buf)
        }
    }

    /// Size of one pcblist_n record without the TCP part: darwin 22
    /// (macOS 13) grew xsocket_n.
    fn record_size() -> usize {
        let release = sysctl("kern.osrelease").map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let major: u32 = release.split('.').next().and_then(|m| m.trim_matches('\0').parse().ok()).unwrap_or(0);
        if major >= 22 {
            408
        } else {
            384
        }
    }

    pub fn owner(network: Network, local: SocketAddr) -> Option<u32> {
        let (name, extra) = match network {
            // rup8(sizeof(xtcpcb_n))
            Network::Tcp => ("net.inet.tcp.pcblist_n", 208),
            Network::Udp => ("net.inet.udp.pcblist_n", 0),
        };
        let buf = sysctl(name)?;
        let item = record_size() + extra;
        let mut wildcard = None;
        // The list starts with an xinpgen header (24 bytes).
        let mut i = 24;
        while i + item <= buf.len() {
            let (inp, so) = (i, i + 104);
            i += item;
            let port = u16::from_be_bytes([buf[inp + 18], buf[inp + 19]]);
            if port != local.port() {
                continue;
            }
            // xinpcb_n.inp_vflag: 1 = IPv4, 2 = IPv6
            let flag = buf[inp + 44];
            let ip = match local {
                SocketAddr::V4(_) if flag & 1 != 0 => IpAddr::V4(Ipv4Addr::new(buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79])),
                SocketAddr::V6(_) if flag & 2 != 0 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[inp + 64..inp + 80]).ok()?)),
                _ => continue,
            };
            // xsocket_n.so_last_pid
            let pid = u32::from_ne_bytes(buf[so + 68..so + 72].try_into().ok()?);
            if ip == local.ip() {
                return Some(pid);
            }
            // UDP sockets are usually bound to the wildcard address.
            if network == Network::Udp && ip.is_unspecified() {
                wildcard = Some(pid);
            }
        }
        wildcard
    }

    fn image_path(pid: u32) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }

    static CACHE: Mutex<Option<HashMap<u32, (Arc<ProcessInfo>, Instant)>>> = Mutex::new(None);

    fn info(pid: u32) -> Option<Arc<ProcessInfo>> {
        if let Some((p, at)) = CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&pid) {
            if at.elapsed() < Duration::from_secs(30) {
                return Some(p.clone());
            }
        }
        if pid == 0 {
            return None;
        }
        let path = image_path(pid)?;
        let info = Arc::new(ProcessInfo { pid, name: file_name(&path), path });
        let mut cache = CACHE.lock().unwrap();
        let map = cache.get_or_insert_with(HashMap::new);
        if map.len() > 1024 {
            map.clear();
        }
        map.insert(pid, (info.clone(), Instant::now()));
        Some(info)
    }

    pub fn find(network: Network, local: SocketAddr) -> Option<Arc<ProcessInfo>> {
        let local = match local {
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                None => local,
            },
            v4 => v4,
        };
        info(owner(network, local)?)
    }

    pub fn list() -> Vec<ProcessInfo> {
        let mut pids = vec![0 as libc::c_int; 8192];
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut _, (pids.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int) };
        let mut out: Vec<ProcessInfo> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for &pid in pids.iter().take(n.max(0) as usize) {
            if pid <= 0 {
                continue;
            }
            if let Some(path) = image_path(pid as u32) {
                if seen.insert(path.clone()) {
                    out.push(ProcessInfo { pid: pid as u32, name: file_name(&path), path });
                }
            }
        }
        out.sort_by_key(|p| p.name.to_lowercase());
        out
    }
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, UNICODE_STRING};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

    use super::*;

    /// Calls a Get*Table function with a growing buffer (u32-aligned).
    fn table(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u32>> {
        let mut size = 0u32;
        call(std::ptr::null_mut(), &mut size);
        for _ in 0..4 {
            let mut buf = vec![0u32; size as usize / 4 + 64];
            let mut len = (buf.len() * 4) as u32;
            match call(buf.as_mut_ptr().cast(), &mut len) {
                0 => return Some(buf),
                122 => size = len, // ERROR_INSUFFICIENT_BUFFER: the table grew
                _ => return None,
            }
        }
        None
    }

    fn port(p: u32) -> u16 {
        u16::from_be(p as u16)
    }

    /// Picks the owner: exact address match first, then (UDP only, where
    /// sockets are usually bound to 0.0.0.0) a wildcard bind. Connected TCP
    /// sockets always have a concrete address.
    fn pick(rows: impl Iterator<Item = (IpAddr, u16, u32)>, local: SocketAddr, wildcard_ok: bool) -> Option<u32> {
        let mut wildcard = None;
        for (ip, p, pid) in rows {
            if p != local.port() {
                continue;
            }
            if ip == local.ip() {
                return Some(pid);
            }
            if wildcard_ok && ip.is_unspecified() {
                wildcard = Some(pid);
            }
        }
        wildcard
    }

    fn owner(network: Network, local: SocketAddr) -> Option<u32> {
        unsafe {
            match (network, local) {
                (Network::Tcp, SocketAddr::V4(_)) => {
                    let buf = table(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0))?;
                    let t = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                    let rows: &[MIB_TCPROW_OWNER_PID] = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
                    pick(rows.iter().map(|r| (IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())), port(r.dwLocalPort), r.dwOwningPid)), local, false)
                }
                (Network::Tcp, SocketAddr::V6(_)) => {
                    let buf = table(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0))?;
                    let t = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                    let rows: &[MIB_TCP6ROW_OWNER_PID] = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
                    pick(rows.iter().map(|r| (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort), r.dwOwningPid)), local, false)
                }
                (Network::Udp, SocketAddr::V4(_)) => {
                    let buf = table(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0))?;
                    let t = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                    let rows: &[MIB_UDPROW_OWNER_PID] = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
                    pick(rows.iter().map(|r| (IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())), port(r.dwLocalPort), r.dwOwningPid)), local, true)
                }
                (Network::Udp, SocketAddr::V6(_)) => {
                    let buf = table(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0))?;
                    let t = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                    let rows: &[MIB_UDP6ROW_OWNER_PID] = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
                    pick(rows.iter().map(|r| (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort), r.dwOwningPid)), local, true)
                }
            }
        }
    }

    #[repr(C)]
    struct SystemProcessIdInformation {
        pid: usize,
        image_name: UNICODE_STRING,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(class: u32, info: *mut core::ffi::c_void, len: u32, returned: *mut u32) -> i32;
    }

    /// `\Device\HarddiskVolume3\x\a.exe` to `C:\x\a.exe`; other devices stay as they are.
    fn dos_path(nt: &str) -> String {
        for letter in b'A'..=b'Z' {
            let drive = [letter as u16, b':' as u16, 0];
            let mut buf = [0u16; 512];
            let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n == 0 {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
            let device = String::from_utf16_lossy(&buf[..end]);
            if let Some(rest) = nt.strip_prefix(device.as_str()).filter(|r| r.starts_with('\\')) {
                return format!("{}:{rest}", letter as char);
            }
        }
        nt.to_string()
    }

    /// The image of a process this user may not open (services, elevated
    /// programs): SystemProcessIdInformation needs no handle or privilege.
    fn image_path_unopened(pid: u32) -> Option<String> {
        const SYSTEM_PROCESS_ID_INFORMATION: u32 = 88;
        let mut buf = [0u16; 2048];
        let mut info = SystemProcessIdInformation {
            pid: pid as usize,
            image_name: UNICODE_STRING { Length: 0, MaximumLength: (buf.len() * 2) as u16, Buffer: buf.as_mut_ptr() },
        };
        let status = unsafe {
            NtQuerySystemInformation(SYSTEM_PROCESS_ID_INFORMATION, (&raw mut info).cast(), size_of::<SystemProcessIdInformation>() as u32, std::ptr::null_mut())
        };
        let len = info.image_name.Length as usize / 2;
        (status >= 0 && len > 0).then(|| dos_path(&String::from_utf16_lossy(&buf[..len])))
    }

    fn image_path(pid: u32) -> Option<String> {
        image_path_opened(pid).or_else(|| image_path_unopened(pid))
    }

    fn image_path_opened(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    static CACHE: Mutex<Option<HashMap<u32, (Arc<ProcessInfo>, Instant)>>> = Mutex::new(None);

    fn info(pid: u32) -> Option<Arc<ProcessInfo>> {
        if let Some((p, at)) = CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&pid) {
            if at.elapsed() < Duration::from_secs(30) {
                return Some(p.clone());
            }
        }
        let info = match pid {
            0 => return None,
            4 => ProcessInfo { pid, name: "System".into(), path: String::new() },
            _ => {
                let path = image_path(pid)?;
                ProcessInfo { pid, name: file_name(&path), path }
            }
        };
        let info = Arc::new(info);
        let mut cache = CACHE.lock().unwrap();
        let map = cache.get_or_insert_with(HashMap::new);
        if map.len() > 1024 {
            map.clear();
        }
        map.insert(pid, (info.clone(), Instant::now()));
        Some(info)
    }

    pub fn find(network: Network, local: SocketAddr) -> Option<Arc<ProcessInfo>> {
        let local = match local {
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                None => local,
            },
            v4 => v4,
        };
        info(owner(network, local)?)
    }

    pub fn list() -> Vec<ProcessInfo> {
        let mut out: Vec<ProcessInfo> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() || snap as isize == -1 {
                return out;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut e);
            while ok != 0 {
                let pid = e.th32ProcessID;
                if let Some(path) = image_path(pid) {
                    if seen.insert(path.to_ascii_lowercase()) {
                        out.push(ProcessInfo { pid, name: file_name(&path), path });
                    }
                }
                ok = Process32NextW(snap, &mut e);
            }
            CloseHandle(snap);
        }
        out.sort_by_key(|p| p.name.to_ascii_lowercase());
        out
    }
}

#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use super::*;

    /// The test binary's path; macOS reports the resolved path.
    fn me() -> String {
        let p = std::env::current_exe().unwrap();
        std::fs::canonicalize(&p).unwrap_or(p).to_string_lossy().trim_start_matches(r"\\?\").to_ascii_lowercase()
    }

    #[test]
    fn finds_own_tcp_and_udp_sockets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let p = find(Network::Tcp, client.local_addr().unwrap()).expect("tcp owner");
        assert_eq!(p.pid, std::process::id());
        assert_eq!(p.path.to_ascii_lowercase(), me());

        let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let p = find(Network::Udp, format!("127.0.0.1:{port}").parse().unwrap()).expect("udp owner");
        assert_eq!(p.pid, std::process::id());

        assert!(find(Network::Tcp, "127.0.0.1:1".parse().unwrap()).is_none());
        assert!(list().iter().any(|x| x.path.to_ascii_lowercase() == me()));
    }

    /// services.exe runs as SYSTEM: an unelevated caller can't open it.
    #[cfg(windows)]
    #[test]
    fn names_processes_it_cannot_open() {
        let all = list();
        let s = all.iter().find(|x| x.name.eq_ignore_ascii_case("services.exe")).expect("services.exe listed");
        assert!(s.path.to_ascii_lowercase().ends_with(r":\windows\system32\services.exe"), "{}", s.path);
    }
}
