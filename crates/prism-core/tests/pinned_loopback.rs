//! In TUN mode the core pins its sockets to the physical interface so they
//! don't loop back into the TUN. A pinned socket can't reach 127.0.0.1
//! (WSAEADDRNOTAVAIL), which broke proxies running on this machine.
#![cfg(windows)]

use prism_core::net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn pinned_sockets_still_reach_loopback() {
    let mut index = 0u32;
    let dest = u32::from_ne_bytes([1, 1, 1, 1]);
    if unsafe { windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface(dest, &mut index) } != 0 {
        eprintln!("skipped: no default interface");
        return;
    }
    net::set_bind_interface(index);

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let accept = tokio::spawn(async move {
        let (mut s, _) = tcp.accept().await.unwrap();
        s.write_all(b"hi").await.unwrap();
    });
    let mut c = net::tcp_connect("127.0.0.1", port).await.expect("TCP to loopback while pinned");
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    accept.await.unwrap();

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = server.local_addr().unwrap();
    let u = net::udp_socket(peer).await.unwrap();
    u.send_to(b"ping", peer).await.expect("UDP to loopback while pinned");
    let mut buf = [0u8; 8];
    let (n, _) = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping");

    net::set_bind_interface(0);
}
