//! DNS fallback: a "main" server that returns polluted answers for some
//! names and a "fallback" server with the real ones.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use prism_core::config::{DnsConfig, FallbackFilter};
use prism_core::dns::{self, wire};

/// A UDP DNS server answering A queries from `table` (missing = empty answer),
/// after `delay_ms`. Counts the queries it gets.
async fn server(table: &[(&str, &str)], delay_ms: u64) -> (String, Arc<Mutex<u32>>) {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap().to_string();
    let table: HashMap<String, IpAddr> = table.iter().map(|(n, ip)| (n.to_string(), ip.parse().unwrap())).collect();
    let hits = Arc::new(Mutex::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            // Windows reports an earlier reply's ICMP "port unreachable" here
            // (the client stopped waiting): not fatal for a server.
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
            *h.lock().unwrap() += 1;
            let q = buf[..n].to_vec();
            let (sock, table) = (sock.clone(), table.clone());
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let (question, _) = wire::question(&q).unwrap();
                let ans: Vec<(IpAddr, u32)> = table.get(&question.name).map(|ip| vec![(*ip, 60)]).unwrap_or_default();
                let _ = sock.send_to(&wire::response(&q, wire::RCODE_NOERROR, &ans).unwrap(), peer).await;
            });
        }
    });
    (addr, hits)
}

async fn ask(r: &dns::Resolver, name: &str) -> Vec<IpAddr> {
    let q = wire::query(7, name, wire::TYPE_A);
    let resp = r.handle(&q).await.unwrap();
    wire::answers(&resp).unwrap().0.into_iter().map(|(ip, _)| ip).collect()
}

#[tokio::test]
async fn uses_fallback_for_filtered_answers() {
    // Main: fast but poisons blocked.test into 203.0.113.0/24.
    let (main, main_hits) = server(&[("ok.test", "114.114.114.114"), ("blocked.test", "203.0.113.9"), ("mixed.test", "1.1.1.1")], 0).await;
    // Fallback: slower, honest.
    let (fb, _) = server(&[("ok.test", "9.9.9.9"), ("blocked.test", "142.250.1.1"), ("empty.test", "5.5.5.5"), ("forced.test", "6.6.6.6"), ("mixed.test", "7.7.7.7")], 80).await;
    let cfg = DnsConfig {
        enable: true,
        enhanced_mode: "normal".into(),
        nameserver: vec![format!("udp://{main}")],
        fallback: vec![format!("udp://{fb}")],
        fallback_filter: FallbackFilter { geoip: false, geoip_code: String::new(), ipcidr: vec!["203.0.113.0/24".into()], domain: vec!["+.forced.test".into()] },
        ..Default::default()
    };
    let cell = Arc::new(OnceLock::new());
    let (r, warnings) = dns::build(&cfg, &[], std::path::Path::new("."), cell, &Mutex::new(None));
    assert!(warnings.is_empty(), "{warnings:?}");
    let r = r.unwrap();

    let t = std::time::Instant::now();
    assert_eq!(ask(&r, "ok.test").await, ["114.114.114.114".parse::<IpAddr>().unwrap()], "clean main answer kept");
    assert!(t.elapsed().as_millis() < 70, "didn't wait for the slower fallback: {:?}", t.elapsed());
    assert_eq!(ask(&r, "blocked.test").await, ["142.250.1.1".parse::<IpAddr>().unwrap()], "polluted answer replaced");
    assert_eq!(ask(&r, "empty.test").await, ["5.5.5.5".parse::<IpAddr>().unwrap()], "empty main answer: fallback");
    let before = *main_hits.lock().unwrap();
    assert_eq!(ask(&r, "www.forced.test").await, Vec::<IpAddr>::new(), "fallback-filter domain: fallback only (no record)");
    assert_eq!(ask(&r, "forced.test").await, ["6.6.6.6".parse::<IpAddr>().unwrap()]);
    assert_eq!(*main_hits.lock().unwrap(), before, "main not asked for fallback-filter domains");
    // Lookups for the core's own connections get the same treatment.
    assert_eq!(r.lookup("blocked.test").await.unwrap(), ["142.250.1.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(r.lookup("mixed.test").await.unwrap(), ["1.1.1.1".parse::<IpAddr>().unwrap()]);
}

/// With geoip on, an address outside the country is polluted. Opt-in: needs geoip.dat.
#[tokio::test]
async fn geoip_filter() {
    let Ok(home) = std::env::var("PRISM_GEO_HOME") else { return };
    let (main, _) = server(&[("cn.test", "223.5.5.5"), ("foreign.test", "8.8.8.8")], 0).await;
    let (fb, _) = server(&[("cn.test", "1.0.0.1"), ("foreign.test", "8.8.4.4")], 30).await;
    let cfg = DnsConfig {
        enable: true,
        enhanced_mode: "normal".into(),
        nameserver: vec![format!("udp://{main}")],
        fallback: vec![format!("udp://{fb}")],
        fallback_filter: FallbackFilter::default(),
        ..Default::default()
    };
    let (r, warnings) = dns::build(&cfg, &[], std::path::Path::new(&home), Arc::new(OnceLock::new()), &Mutex::new(None));
    assert!(warnings.is_empty(), "{warnings:?}");
    let r = r.unwrap();
    assert_eq!(ask(&r, "cn.test").await, ["223.5.5.5".parse::<IpAddr>().unwrap()]);
    assert_eq!(ask(&r, "foreign.test").await, ["8.8.4.4".parse::<IpAddr>().unwrap()]);
}

/// Opt-in (network): DNS over QUIC and over HTTP/3 against public servers.
///   PRISM_DNS_LIVE=quic://dns.alidns.com,https://dns.alidns.com/dns-query#h3=true
#[tokio::test]
async fn quic_and_h3_upstreams_live() {
    let Ok(list) = std::env::var("PRISM_DNS_LIVE") else { return };
    for server in list.split(',') {
        let cfg = DnsConfig {
            enable: true,
            enhanced_mode: "normal".into(),
            default_nameserver: vec!["223.5.5.5".into()],
            nameserver: vec![server.to_string()],
            ..Default::default()
        };
        let (r, warnings) = dns::build(&cfg, &[], std::path::Path::new("."), Arc::new(OnceLock::new()), &Mutex::new(None));
        assert!(warnings.is_empty(), "{server}: {warnings:?}");
        let r = r.unwrap();
        for name in ["www.baidu.com", "www.example.com", "github.com"] {
            let t = std::time::Instant::now();
            let ips = ask(&r, name).await;
            println!("{server} {name}: {ips:?} in {:?}", t.elapsed());
            assert!(!ips.is_empty() || name == "www.baidu.com", "{server} {name}");
        }
    }
}

#[tokio::test]
async fn upstream_error_detail() {
    let Ok(server) = std::env::var("PRISM_DNS_DEBUG") else { return };
    let boot = Arc::new(vec!["223.5.5.5:53".parse().unwrap()]);
    let u = dns::upstream::Upstream::parse(&server, boot, Arc::new(OnceLock::new())).unwrap();
    let q = wire::query(9, "www.example.com", wire::TYPE_A);
    match u.exchange(&q).await {
        Ok(r) => println!("rcode {} answers {:?}", wire::rcode(&r), wire::answers(&r)),
        Err(e) => println!("error: {e}"),
    }
}
