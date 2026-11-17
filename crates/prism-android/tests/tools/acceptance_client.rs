//! Opt-in acceptance executable, never part of an APK. Ordinary unprotected
//! sockets must enter the running VPN. Fixed target, normal TLS verification.
use anyhow::{ensure, Context, Result};
use prism_core::outbound::tls::Tls;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let started = Instant::now();
    timeout(Duration::from_secs(15),async {
        let phase=std::env::args().nth(1).unwrap_or_else(||"before".into());
        let host=match phase.as_str(){"before"|"resumed"=>"one.one.one.one","idle"=>"cloudflare-dns.com",_=>anyhow::bail!("unknown acceptance phase")};
        let nonce=SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name=format!("acceptance-{nonce}.prism.invalid");
        let addresses=tokio::net::lookup_host((name.as_str(),443)).await.context("system DNS phase")?.collect::<Vec<_>>();
        ensure!(!addresses.is_empty(),"system DNS returned no address");
        ensure!(addresses.iter().all(|a|matches!(a.ip(),std::net::IpAddr::V4(ip) if ip.octets()[0]==198 && (ip.octets()[1]==18 || ip.octets()[1]==19))),"system DNS did not pass through the VPN fake-IP resolver");
        // Do not use prism_core::net or Dialer: these are client sockets, not
        // protected VPN outbounds. The OS must route them through the TUN.
        let targets=tokio::net::lookup_host((host,443)).await.context("target DNS phase")?.collect::<Vec<_>>();
        ensure!(!targets.is_empty() && targets.iter().all(|a|matches!(a.ip(),std::net::IpAddr::V4(ip) if ip.octets()[0]==198 && (ip.octets()[1]==18 || ip.octets()[1]==19))),"target DNS bypassed VPN fake-IP");
        let tcp=TcpStream::connect(targets[0]).await.context("application TCP phase")?;
        ensure!(tcp.local_addr()?.ip()=="172.19.0.1".parse::<std::net::IpAddr>()?,"client TCP bypassed the VPN interface");
        let tls=Tls::new(host,false,&[],None)?;
        let mut stream=tls.wrap(tcp).await.context("verified application TLS phase")?;
        let request=format!("GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut first=[0;12];stream.read_exact(&mut first).await.context("HTTP response phase")?;
        ensure!(&first[..9]==b"HTTP/1.1 ","unexpected HTTP response");
        let status=std::str::from_utf8(&first[9..])?.parse::<u16>()?;
        ensure!(status==200,"HTTP response was not successful");
        println!("{}",serde_json::json!({"clientVersion":2,"phase":phase,"ok":true,"systemDns":"vpn-fake-ip","tls":"verified","httpStatus":status,"elapsedMs":started.elapsed().as_millis()}));
        Ok::<(),anyhow::Error>(())
    }).await.context("acceptance client timed out")??;
    Ok(())
}
