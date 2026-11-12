//! Windows can query DNS on multiple adapters, including the LAN router,
//! whose connected route is more specific than the TUN's split default.
//! Enforce DNS interception independently of the optional internet kill switch.
use anyhow::{bail, Context, Result};
use std::path::Path;
use windows_sys::core::GUID;
use windows_sys::Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*};

fn check(api: &str, code: u32) -> Result<()> {
    if code != 0 {
        bail!("DNS protection: {api}: 0x{code:08x}");
    }
    Ok(())
}
fn condition(
    field: GUID,
    ty: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: ty,
            Anonymous: value,
        },
    }
}
fn port() -> FWPM_FILTER_CONDITION0 {
    condition(
        FWPM_CONDITION_IP_REMOTE_PORT,
        FWP_UINT16,
        FWP_CONDITION_VALUE0_0 { uint16: 53 },
    )
}

pub(crate) struct DnsGuard {
    engine: HANDLE,
    #[cfg(test)]
    ids: Vec<u64>,
}
// Owned by the TUN pump; WFP handles may move between threads.
unsafe impl Send for DnsGuard {}
impl Drop for DnsGuard {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.engine);
        }
    }
}
impl DnsGuard {
    pub(crate) fn enable(index: u32) -> Result<Self> {
        let mut row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2 =
            unsafe { std::mem::zeroed() };
        row.InterfaceIndex = index;
        check("TUN interface identity", unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::GetIfEntry2(&mut row)
        })?;
        let exe = std::env::current_exe().context("DNS protection executable")?;
        Self::install(index, &exe)
    }
    fn install(index: u32, exe: &Path) -> Result<Self> {
        anyhow::ensure!(index != 0, "DNS protection requires a TUN interface");
        let mut engine = std::ptr::null_mut();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..unsafe { std::mem::zeroed() }
        };
        check("open engine", unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                0xffff_ffff,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        #[allow(unused_mut)] // Test builds retain IDs for native inspection.
        let mut guard = Self {
            engine,
            #[cfg(test)]
            ids: vec![],
        };
        check("begin transaction", unsafe {
            FwpmTransactionBegin0(engine, 0)
        })?;
        let sublayer = GUID::from_u128(uuid::Uuid::new_v4().as_u128());
        let mut name: Vec<u16> = "Prism TUN DNS protection\0".encode_utf16().collect();
        let sub = FWPM_SUBLAYER0 {
            subLayerKey: sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            weight: 0xffff,
            ..unsafe { std::mem::zeroed() }
        };
        check("add sublayer", unsafe {
            FwpmSubLayerAdd0(engine, &sub, std::ptr::null_mut())
        })?;
        let path: Vec<u16> = exe
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut app = std::ptr::null_mut();
        check("core AppID", unsafe {
            FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app)
        })?;
        let result = (|| -> Result<()> {
            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ] {
                // Every permit is restricted to DNS. It cannot open any other
                // internet traffic through an existing kill-switch policy.
                let rules = [
                    (FWP_ACTION_BLOCK, 10, vec![port()]),
                    (
                        FWP_ACTION_PERMIT,
                        14,
                        vec![
                            port(),
                            condition(
                                FWPM_CONDITION_ALE_APP_ID,
                                FWP_BYTE_BLOB_TYPE,
                                FWP_CONDITION_VALUE0_0 { byteBlob: app },
                            ),
                        ],
                    ),
                    (
                        FWP_ACTION_PERMIT,
                        14,
                        vec![
                            port(),
                            // The SDK aliases LOCAL_INTERFACE_INDEX to this
                            // condition. Match the routed interface index,
                            // rather than the source address's interface LUID.
                            condition(
                                FWPM_CONDITION_INTERFACE_INDEX,
                                FWP_UINT32,
                                FWP_CONDITION_VALUE0_0 { uint32: index },
                            ),
                        ],
                    ),
                ];
                for (action, weight, mut conditions) in rules {
                    let filter = FWPM_FILTER0 {
                        displayData: FWPM_DISPLAY_DATA0 {
                            name: name.as_mut_ptr(),
                            description: std::ptr::null_mut(),
                        },
                        layerKey: layer,
                        subLayerKey: sublayer,
                        weight: FWP_VALUE0 {
                            r#type: FWP_UINT8,
                            Anonymous: FWP_VALUE0_0 { uint8: weight },
                        },
                        action: FWPM_ACTION0 {
                            r#type: action,
                            ..unsafe { std::mem::zeroed() }
                        },
                        numFilterConditions: conditions.len() as u32,
                        filterCondition: conditions.as_mut_ptr(),
                        ..unsafe { std::mem::zeroed() }
                    };
                    let mut id = 0;
                    check("add filter", unsafe {
                        FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id)
                    })?;
                    #[cfg(test)]
                    guard.ids.push(id);
                }
            }
            Ok(())
        })();
        unsafe {
            let mut memory = app.cast();
            FwpmFreeMemory0(&mut memory);
        }
        result?;
        check("commit filters", unsafe { FwpmTransactionCommit0(engine) })?;
        tracing::info!("DNS protection: Windows IPv4/IPv6 TCP/UDP 53 restricted to TUN interface {index} and core upstream sockets");
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
        process::Command,
        time::Duration,
    };
    fn same_guid(a: GUID, b: GUID) -> bool {
        (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
    }
    fn external_probe(host: &str, port: u16, tcp: bool) -> String {
        // A different executable must not inherit the core AppID exception.
        // All probes stay on loopback; no DNS names or packets leave the runner.
        let family = if host.contains(':') {
            "InterNetworkV6"
        } else {
            "InterNetwork"
        };
        let script = if tcp {
            format!("$c=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::{family});try{{$t=$c.ConnectAsync('{host}',{port});if(!$t.Wait(3000)){{'timeout'}}else{{[void]$t.GetAwaiter().GetResult();'allowed'}}}}catch{{$e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};$e.NativeErrorCode}}finally{{$c.Dispose()}}")
        } else {
            format!("$c=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::{family});try{{[void]$c.Send([byte[]]@(0),1,'{host}',{port});'allowed'}}catch{{$e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};$e.NativeErrorCode}}finally{{$c.Dispose()}}")
        };
        let out = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            ["allowed", "10013", "timeout"].contains(&result.as_str()),
            "unexpected probe failure: {result}"
        );
        result
    }
    struct Receiver {
        host: &'static str,
        udp: UdpSocket,
        tcp: TcpListener,
    }
    impl Receiver {
        fn new(host: &'static str) -> Self {
            let addr = SocketAddr::new(host.parse().unwrap(), 53);
            let udp = UdpSocket::bind(addr).unwrap();
            udp.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let tcp = TcpListener::bind(addr).unwrap();
            tcp.set_nonblocking(true).unwrap();
            Self { host, udp, tcp }
        }
        fn check_udp(&self, delivered: bool) {
            let result = self.udp.recv(&mut [0u8; 16]);
            if delivered {
                assert_eq!(result.unwrap(), 1, "{} UDP must arrive", self.host);
            } else {
                assert!(
                    matches!(
                        result.unwrap_err().kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ),
                    "{} UDP must be blocked",
                    self.host
                );
            }
        }
        fn check_tcp(&self, delivered: bool) {
            let result = self.tcp.accept();
            if delivered {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    io::ErrorKind::WouldBlock,
                    "{} TCP must be blocked",
                    self.host
                );
            }
        }
        fn external(&self, delivered: bool) {
            external_probe(self.host, 53, false);
            self.check_udp(delivered);
            external_probe(self.host, 53, true);
            self.check_tcp(delivered);
        }
    }
    #[test]
    fn native_dns_blocks_other_apps_and_cleans_up() {
        // Global DNS rules: explicitly opted-in disposable Windows CI only.
        if std::env::var("PRISM_DNS_GUARD_TEST").as_deref() != Ok("1") {
            return;
        }
        let receivers = [Receiver::new("127.0.0.1"), Receiver::new("::1")];
        for r in &receivers {
            r.external(true);
        }
        let guard = DnsGuard::install(777, &std::env::current_exe().unwrap()).unwrap();
        assert_eq!(guard.ids.len(), 6);
        let mut families = [0, 0];
        for id in &guard.ids {
            unsafe {
                let mut raw = std::ptr::null_mut();
                assert_eq!(FwpmFilterGetById0(guard.engine, *id, &mut raw), 0);
                let filter = &*raw;
                if same_guid(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) {
                    families[0] += 1;
                } else {
                    assert!(same_guid(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6));
                    families[1] += 1;
                }
                let conditions = std::slice::from_raw_parts(
                    filter.filterCondition,
                    filter.numFilterConditions as usize,
                );
                let dns_port = conditions
                    .iter()
                    .find(|c| same_guid(c.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT))
                    .unwrap();
                assert_eq!(dns_port.conditionValue.Anonymous.uint16, 53);
                if filter.action.r#type == FWP_ACTION_BLOCK {
                    assert_eq!(conditions.len(), 1);
                } else {
                    assert_eq!(filter.action.r#type, FWP_ACTION_PERMIT);
                    assert_eq!(conditions.len(), 2);
                    if let Some(interface) = conditions
                        .iter()
                        .find(|c| same_guid(c.fieldKey, FWPM_CONDITION_INTERFACE_INDEX))
                    {
                        assert_eq!(interface.conditionValue.Anonymous.uint32, 777);
                    } else {
                        assert!(conditions
                            .iter()
                            .any(|c| same_guid(c.fieldKey, FWPM_CONDITION_ALE_APP_ID)));
                    }
                }
                let mut memory = raw.cast();
                FwpmFreeMemory0(&mut memory);
            }
        }
        assert_eq!(families, [3, 3]);
        for r in &receivers {
            r.external(false);
            let ip: IpAddr = r.host.parse().unwrap();
            let other = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
            other
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(
                external_probe(r.host, other.local_addr().unwrap().port(), false),
                "allowed"
            );
            assert_eq!(
                other.recv(&mut [0u8; 16]).unwrap(),
                1,
                "ordinary traffic is unaffected"
            );
            // The core can still resolve configured bootstrap endpoints.
            let own = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
            own.send_to(&[0], SocketAddr::new(ip, 53)).unwrap();
            r.check_udp(true);
            let _tcp = TcpStream::connect(SocketAddr::new(ip, 53)).unwrap();
            r.check_tcp(true);
        }
        drop(guard);
        for r in &receivers {
            r.external(true);
        }
        let mut index = 0;
        let addr = socket2::SockAddr::from("127.0.0.1:53".parse::<SocketAddr>().unwrap());
        check("loopback route", unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx(
                addr.as_ptr().cast(),
                &mut index,
            )
        })
        .unwrap();
        let on_interface = DnsGuard::enable(index).unwrap();
        for r in &receivers {
            r.external(true);
        }
        drop(on_interface);
    }
}
