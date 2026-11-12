//! Trojan over TLS (optionally over WebSocket, HTTPUpgrade or gRPC):
//! hex(sha224(password)) CRLF cmd addr CRLF payload...

use std::io;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use super::tls::Tls;
use super::transport::Transport;
use super::{Dialer, Outbound};
use crate::common::{udp_over_stream, Address, BoxedStream, Framing, UdpPipe};
use crate::config::ProxyConfig;

pub struct Trojan {
    name: String,
    server: String,
    port: u16,
    hash: String,
    tls: Tls,
    transport: Transport,
    host: String,
    dialer: Dialer,
}

impl Trojan {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let transport = Transport::from_config(p)?;
        let alpn = if p.alpn.is_empty() { transport.alpn() } else { p.alpn.clone() };
        let sni = p.sni.clone().unwrap_or_else(|| p.server.clone());
        Ok(Trojan {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            hash: hex::encode(Sha224::digest(p.password.as_deref().unwrap_or("").as_bytes())),
            tls: Tls::new(&sni, p.skip_cert_verify, &alpn, p.fingerprint.as_deref())?,
            host: p.ws_host.clone().unwrap_or(sni),
            transport,
            dialer,
        })
    }
}

impl Trojan {
    /// TLS connection with the Trojan request header (cmd 1 = TCP, 3 = UDP).
    async fn open(&self, cmd: u8, target: &Address) -> io::Result<BoxedStream> {
        let s = self.tls.connect(&self.dialer, &self.server, self.port).await?;
        let mut s = self.transport.wrap(s, &self.host).await?;
        let mut head = Vec::with_capacity(128);
        head.extend_from_slice(self.hash.as_bytes());
        head.extend_from_slice(b"\r\n");
        head.push(cmd);
        target.write_socks(&mut head);
        head.extend_from_slice(b"\r\n");
        s.write_all(&head).await?;
        s.flush().await?;
        Ok(s)
    }
}

#[async_trait]
impl Outbound for Trojan {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Trojan"
    }
    fn udp(&self) -> bool {
        true
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        Ok(Box::new(self.open(1, target).await?))
    }
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let s = self.open(3, target).await?;
        Ok(udp_over_stream(s, Framing::Trojan(target.clone())))
    }
}
