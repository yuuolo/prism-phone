//! mrs rule-sets made by `mihomo convert-ruleset` from tests/data/{dom,ip}.yaml.

use std::path::Path;

use prism_core::common::Address;
use prism_core::tunnel::{Metadata, Network};

fn data(f: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(f).to_string_lossy().replace('\\', "/")
}

#[test]
fn decodes_mihomo_files() {
    let (b, mut d) = prism_core::mrs::decode(&std::fs::read(data("dom.mrs")).unwrap()).unwrap();
    assert_eq!(b, "domain");
    d.sort();
    // `+.x` in the source becomes x plus `+.x` (subdomains); `.x` only `+.x`.
    assert_eq!(d, ["*.ggpht.com", "+.co", "+.googlevideo.com", "+.youtube.com", "a.*.example.org", "co", "google.com", "www.example.net", "youtube.com"]);
    let (b, ip) = prism_core::mrs::decode(&std::fs::read(data("ip.mrs")).unwrap()).unwrap();
    assert_eq!(b, "ipcidr");
    assert_eq!(ip, ["1.0.0.0/23", "8.8.8.8/32", "10.0.0.0/8", "2001:db8::/32", "2400:cb00::/32"]);
}

#[tokio::test]
async fn routes_with_mrs_providers() {
    let yaml = format!(
        "proxies: []\nproxy-groups:\n  - {{name: DOM, type: select, proxies: [DIRECT]}}\n  - {{name: IP, type: select, proxies: [DIRECT]}}\n  - {{name: OTHER, type: select, proxies: [DIRECT]}}\nrule-providers:\n  dom: {{type: file, behavior: domain, format: mrs, path: '{}'}}\n  ip: {{type: file, behavior: ipcidr, format: mrs, path: '{}'}}\n  wrong: {{type: file, behavior: ipcidr, format: mrs, path: '{}'}}\nrules:\n  - RULE-SET,dom,DOM\n  - RULE-SET,ip,IP\n  - MATCH,OTHER\n",
        data("dom.mrs"),
        data("ip.mrs"),
        data("dom.mrs"),
    );
    let profile = prism_core::config::parse_any(&yaml).unwrap();
    let (router, warnings) = prism_core::rules::tester(&profile, Path::new("/")).await;
    assert!(warnings.iter().any(|w| w.contains("wrong") && w.contains("domain rule-set")), "{warnings:?}");
    // a.*.example.org: a wildcard in the middle isn't supported.
    assert!(warnings.iter().any(|w| w.contains("dom: 1 unsupported")), "{warnings:?}");
    let hit = |host: &str, ip: Option<&str>| {
        let m = Metadata::new(Network::Tcp, "HTTP", "127.0.0.1:1".parse().unwrap(), Address::new(host, 443), None);
        router.test(&m, ip.map(|i| i.parse().unwrap())).target
    };
    assert_eq!(hit("google.com", None), "DOM");
    assert_eq!(hit("www.google.com", None), "OTHER", "google.com was exact");
    assert_eq!(hit("youtube.com", None), "DOM");
    assert_eq!(hit("m.youtube.com", None), "DOM");
    assert_eq!(hit("googlevideo.com", None), "OTHER", ".googlevideo.com is subdomains only");
    assert_eq!(hit("r1.googlevideo.com", None), "DOM");
    assert_eq!(hit("yt3.ggpht.com", None), "DOM");
    assert_eq!(hit("WWW.EXAMPLE.NET", None), "DOM");
    assert_eq!(hit("1.0.1.200", None), "IP");
    assert_eq!(hit("x.test", Some("10.9.9.9")), "IP");
    assert_eq!(hit("2400:cb00::1", None), "IP");
    assert_eq!(hit("9.9.9.9", None), "OTHER");
}
