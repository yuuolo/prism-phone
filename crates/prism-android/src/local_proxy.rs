//! Explicit, session-bound mixed service; never started by importing a profile.
use anyhow::{ensure, Result};
use prism_core::{hub::Hub, inbound};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
#[cfg(test)]
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Loopback,
    Lan,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Status {},
    Start {
        #[serde(rename = "sessionId")]
        session_id: String,
        port: u16,
        #[serde(default)]
        scope: Scope,
    },
    Stop {
        #[serde(rename = "sessionId")]
        session_id: String,
    },
}
impl Request {
    pub fn parse(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= 2048, "代理控制参数过长");
        let request: Self = serde_json::from_str(raw)?;
        if let Self::Start { port, .. } = request {
            ensure!(port == 0 || port >= 1024, "端口须为 0 或 1024–65535");
        }
        Ok(request)
    }
    pub fn session(&self) -> Option<&str> {
        match self {
            Self::Status {} => None,
            Self::Start { session_id, .. } | Self::Stop { session_id } => Some(session_id),
        }
    }
}
pub struct LocalProxy {
    pub address: SocketAddr,
    pub scope: Scope,
    stop: CancellationToken,
    tcp: Option<JoinHandle<()>>,
    udp: Option<JoinHandle<()>>,
}
impl LocalProxy {
    pub async fn start(
        hub: Arc<Hub>,
        root: &CancellationToken,
        port: u16,
        scope: Scope,
    ) -> Result<Self> {
        ensure!(!root.is_cancelled(), "VPN 会话已结束");
        ensure!(port == 0 || port >= 1024, "代理端口无效");
        let ip = if scope == Scope::Loopback {
            Ipv4Addr::LOCALHOST
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let mut bound = None;
        let mut last_error = None;
        // Port 0 must find a port available for BOTH transports; platforms can
        // reserve different TCP/UDP ephemeral ranges. Explicit ports never change.
        for _ in 0..if port == 0 { 16 } else { 1 } {
            let tcp = prism_core::net::mobile_tcp_listener(SocketAddr::from((ip, port))).await?;
            match prism_core::net::mobile_udp_listener(tcp.local_addr()?).await {
                Ok(udp) => {
                    bound = Some((tcp, udp));
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }
        let (tcp, udp) = match bound {
            Some(pair) => pair,
            None => return Err(last_error.unwrap().into()),
        };
        let address = tcp.local_addr()?;
        ensure!(!root.is_cancelled(), "VPN 会话已结束");
        let stop = root.child_token();
        let associations = inbound::UdpAssociations::new(stop.clone());
        let tcp = tokio::spawn(inbound::serve_managed(
            tcp,
            hub.clone(),
            stop.clone(),
            associations.clone(),
        ));
        let udp = tokio::spawn(inbound::serve_udp_managed(
            udp,
            hub,
            stop.clone(),
            associations,
        ));
        Ok(Self {
            address,
            scope,
            stop,
            tcp: Some(tcp),
            udp: Some(udp),
        })
    }
    pub fn alive(&self) -> bool {
        !self.stop.is_cancelled()
            && self.tcp.as_ref().is_some_and(|t| !t.is_finished())
            && self.udp.as_ref().is_some_and(|t| !t.is_finished())
    }
    pub fn status(&self) -> Value {
        json!({"running":self.alive(),"address":self.address.ip().to_string(),"port":self.address.port(),"scope":self.scope,
        "protocols":["HTTP","SOCKS5 TCP","SOCKS5 UDP"]})
    }
    pub async fn stop(mut self) {
        self.stop.cancel();
        if let Some(t) = self.tcp.take() {
            let _ = t.await;
        }
        if let Some(t) = self.udp.take() {
            let _ = t.await;
        }
    }
}
impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(t) = &self.tcp {
            t.abort();
        }
        if let Some(t) = &self.udp {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::{
        common::Address,
        tunnel::{Metadata, Network},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn hub() -> Arc<Hub> {
        let p = prism_core::config::parse_any(
            "proxies: []\nrules: ['MATCH,DIRECT']\nfind-process-mode: off",
        )
        .unwrap();
        Hub::new(Default::default(), std::path::PathBuf::from("."), p)
            .await
            .unwrap()
    }
    #[test]
    fn rejects_unsupported_scope_and_privileged_ports() {
        assert!(Request::parse(r#"{"action":"start","sessionId":"s","port":0}"#).is_ok());
        assert!(Request::parse(r#"{"action":"start","sessionId":"s","port":80}"#).is_err());
        assert!(Request::parse(
            r#"{"action":"start","sessionId":"s","port":7890,"scope":"internet"}"#
        )
        .is_err());
        assert!(Request::parse(r#"{"action":"status","extra":"unused"}"#).is_err());
    }
    #[tokio::test]
    async fn forwards_http_and_udp_then_releases_ports_without_stopping_hub() {
        let hub = hub().await;
        let root = CancellationToken::new();
        let proxy = LocalProxy::start(hub.clone(), &root, 0, Scope::Loopback)
            .await
            .unwrap();
        let address = proxy.address;
        assert!(address.ip().is_loopback());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let n = s.read(&mut bytes).await.unwrap();
            assert!(String::from_utf8_lossy(&bytes[..n]).starts_with("GET /fixture HTTP/1.1"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(format!("GET http://127.0.0.1:{port}/fixture HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = vec![];
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with(b"OK"));
        drop(client);
        server.await.unwrap();
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut b = [0; 64];
            let (n, p) = echo.recv_from(&mut b).await.unwrap();
            echo.send_to(&b[..n], p).await.unwrap();
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut association = tokio::net::TcpStream::connect(address).await.unwrap();
        association.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        association.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 3, 0];
        Address::Ip(udp.local_addr().unwrap()).write_socks(&mut request);
        association.write_all(&request).await.unwrap();
        let mut bound = [0; 10];
        association.read_exact(&mut bound).await.unwrap();
        assert_eq!(bound[1], 0);
        let mut packet = vec![0, 0, 0];
        Address::Ip(destination).write_socks(&mut packet);
        packet.extend_from_slice(b"proxy-udp");
        udp.send_to(&packet, address).await.unwrap();
        let mut answer = [0; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), udp.recv_from(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert!(answer[..n].ends_with(b"proxy-udp"));
        echo_task.await.unwrap();
        drop(association);
        tokio::time::timeout(Duration::from_secs(3), async {
            while !hub.core().tunnel.stats.snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
        })
        .await
        .unwrap();
        proxy.stop().await;
        let _tcp = TcpListener::bind(address).await.unwrap();
        let _udp = UdpSocket::bind(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !hub.core().tunnel.stats.snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
        })
        .await
        .unwrap();
        // Ordinary routing remains available after stopping only the proxy service.
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let mut meta = Metadata::new(
            Network::Tcp,
            "Test",
            "127.0.0.1:1".parse().unwrap(),
            Address::Ip(target),
            None,
        );
        assert!(hub.core().tunnel.dial(&mut meta).await.is_ok());
        assert!(!root.is_cancelled());
        hub.core().shutdown.cancel();
    }
    #[tokio::test]
    async fn udp_bind_failure_does_not_leave_tcp_listener() {
        let hub = hub().await;
        let root = CancellationToken::new();
        let probe = LocalProxy::start(hub.clone(), &root, 0, Scope::Loopback)
            .await
            .unwrap();
        let address = probe.address;
        probe.stop().await;
        let _held = UdpSocket::bind(address).await.unwrap();
        assert!(
            LocalProxy::start(hub.clone(), &root, address.port(), Scope::Loopback)
                .await
                .is_err()
        );
        let _tcp = TcpListener::bind(address).await.unwrap();
        hub.core().shutdown.cancel();
    }
    #[tokio::test]
    async fn stopping_aborts_held_tcp_clients_and_removes_connection_rows() {
        let hub = hub().await;
        let root = CancellationToken::new();
        let proxy = LocalProxy::start(hub.clone(), &root, 0, Scope::Loopback)
            .await
            .unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = origin.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(proxy.address).await.unwrap();
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = vec![];
        tokio::time::timeout(Duration::from_secs(3), async {
            while !head.ends_with(b"\r\n\r\n") {
                head.push(client.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        let (_held_origin, _) = origin.accept().await.unwrap();
        assert!(!hub.core().tunnel.stats.snapshot().is_empty());
        proxy.stop().await;
        assert!(hub.core().tunnel.stats.snapshot().is_empty());
        let mut byte = [0];
        let ended = tokio::time::timeout(Duration::from_secs(3), client.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(ended, Ok(0) | Err(_)));
        assert!(!root.is_cancelled());
        hub.core().shutdown.cancel();
    }
}
