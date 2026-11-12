//! Readers for v2ray-format `geosite.dat` / `geoip.dat` (as shipped by
//! MetaCubeX/meta-rules-dat). Only the categories referenced by rules are
//! decoded. The protobuf schema is tiny, so it is parsed by hand:
//!
//! GeoSiteList { repeated GeoSite entry = 1 }
//! GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//! Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//!             Type: 0 keyword, 1 regex, 2 domain (suffix), 3 full
//! Attribute   { string key = 1; ... }
//! GeoIPList   { repeated GeoIP entry = 1 }
//! GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//! CIDR        { bytes ip = 1; uint32 prefix = 2 }

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::Path;

use regex::Regex;

struct Pb<'a> {
    buf: &'a [u8],
    pos: usize,
}

enum Val<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Skip,
}

impl<'a> Pb<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Pb { buf, pos: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn next(&mut self) -> Option<(u64, Val<'a>)> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let key = self.varint()?;
        let val = match key & 7 {
            0 => Val::Varint(self.varint()?),
            1 => {
                self.pos += 8;
                Val::Skip
            }
            2 => {
                let len = self.varint()? as usize;
                let b = self.buf.get(self.pos..self.pos + len)?;
                self.pos += len;
                Val::Bytes(b)
            }
            5 => {
                self.pos += 4;
                Val::Skip
            }
            _ => return None,
        };
        Some((key >> 3, val))
    }
}

/// Reads the country_code of a GeoSite / GeoIP entry without decoding the rest.
fn entry_code(entry: &[u8]) -> Option<String> {
    let mut pb = Pb::new(entry);
    while let Some((f, v)) = pb.next() {
        if let (1, Val::Bytes(b)) = (f, v) {
            return Some(String::from_utf8_lossy(b).to_ascii_lowercase());
        }
    }
    None
}

fn entries(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut pb = Pb::new(data);
    std::iter::from_fn(move || loop {
        match pb.next()? {
            (1, Val::Bytes(b)) => return Some(b),
            _ => continue,
        }
    })
}

#[derive(Default)]
pub struct DomainSet {
    full: HashSet<String>,
    suffix: HashSet<String>,
    keyword: Vec<String>,
    regex: Vec<Regex>,
}

impl DomainSet {
    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn matches(&self, host: &str) -> bool {
        if self.full.contains(host) {
            return true;
        }
        let mut h = host;
        loop {
            if self.suffix.contains(h) {
                return true;
            }
            match h.find('.') {
                Some(i) => h = &h[i + 1..],
                None => break,
            }
        }
        self.keyword.iter().any(|k| host.contains(k.as_str())) || self.regex.iter().any(|r| r.is_match(host))
    }
}

/// Loads the requested geosite categories. A code may carry an attribute
/// filter, e.g. `google@cn`.
pub fn load_geosite(path: &Path, codes: &[String]) -> io::Result<HashMap<String, DomainSet>> {
    let data = std::fs::read(path)?;
    let mut wanted: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
    for c in codes {
        let lc = c.to_ascii_lowercase();
        let (base, attr) = match lc.split_once('@') {
            Some((b, a)) => (b.to_string(), Some(a.to_string())),
            None => (lc.clone(), None),
        };
        wanted.entry(base).or_default().push((c.clone(), attr));
    }
    let mut out: HashMap<String, DomainSet> = HashMap::new();
    for entry in entries(&data) {
        let Some(code) = entry_code(entry) else { continue };
        let Some(targets) = wanted.get(&code) else { continue };
        for (orig, attr) in targets {
            let set = out.entry(orig.clone()).or_default();
            let mut pb = Pb::new(entry);
            while let Some((f, v)) = pb.next() {
                let (2, Val::Bytes(dom)) = (f, v) else { continue };
                let (mut ty, mut value, mut attrs) = (0u64, String::new(), Vec::new());
                let mut d = Pb::new(dom);
                while let Some((f, v)) = d.next() {
                    match (f, v) {
                        (1, Val::Varint(t)) => ty = t,
                        (2, Val::Bytes(b)) => value = String::from_utf8_lossy(b).to_ascii_lowercase(),
                        (3, Val::Bytes(b)) => {
                            if let Some(k) = entry_code(b) {
                                attrs.push(k);
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(a) = attr {
                    if !attrs.iter().any(|k| k == a) {
                        continue;
                    }
                }
                match ty {
                    0 => set.keyword.push(value),
                    1 => {
                        if let Ok(r) = Regex::new(&value) {
                            set.regex.push(r);
                        }
                    }
                    2 => {
                        set.suffix.insert(value);
                    }
                    _ => {
                        set.full.insert(value);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Sorted, merged IP ranges for fast lookup.
#[derive(Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    reverse: bool,
}

fn merge<T: Ord + Copy + num_like::One>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if let Some(last) = out.last_mut() {
            if s <= last.1.saturating_inc() {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

mod num_like {
    pub trait One {
        fn saturating_inc(self) -> Self;
    }
    impl One for u32 {
        fn saturating_inc(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl One for u128 {
        fn saturating_inc(self) -> Self {
            self.saturating_add(1)
        }
    }
}

fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|(s, _)| *s <= x);
    i > 0 && x <= v[i - 1].1
}

impl IpSet {
    /// From a list of networks (rule-providers with `ipcidr` behavior).
    pub fn from_nets(nets: Vec<ipnet::IpNet>) -> IpSet {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for n in nets {
            match n {
                ipnet::IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
                ipnet::IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
            }
        }
        IpSet { v4: merge(v4), v6: merge(v6), reverse: false }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let hit = match ip {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(v6)),
            },
        };
        hit != self.reverse
    }
}

/// Every category code in a geosite / geoip file.
pub fn codes(path: &Path) -> io::Result<Vec<String>> {
    let data = std::fs::read(path)?;
    Ok(entries(&data).filter_map(entry_code).collect())
}

pub fn load_geoip(path: &Path, codes: &[String]) -> io::Result<HashMap<String, IpSet>> {
    let data = std::fs::read(path)?;
    let wanted: HashSet<String> = codes.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut out = HashMap::new();
    for entry in entries(&data) {
        let Some(code) = entry_code(entry) else { continue };
        if !wanted.contains(&code) {
            continue;
        }
        let (mut v4, mut v6, mut reverse) = (Vec::new(), Vec::new(), false);
        let mut pb = Pb::new(entry);
        while let Some((f, v)) = pb.next() {
            match (f, v) {
                (2, Val::Bytes(cidr)) => {
                    let (mut ip, mut prefix) = (&[][..], 0u32);
                    let mut c = Pb::new(cidr);
                    while let Some((f, v)) = c.next() {
                        match (f, v) {
                            (1, Val::Bytes(b)) => ip = b,
                            (2, Val::Varint(p)) => prefix = p as u32,
                            _ => {}
                        }
                    }
                    if ip.len() == 4 && prefix <= 32 {
                        let s = u32::from_be_bytes(ip.try_into().unwrap());
                        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                        v4.push((s & mask, (s & mask) | !mask));
                    } else if ip.len() == 16 && prefix <= 128 {
                        let s = u128::from_be_bytes(ip.try_into().unwrap());
                        let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                        v6.push((s & mask, (s & mask) | !mask));
                    }
                }
                (3, Val::Varint(r)) => reverse = r != 0,
                _ => {}
            }
        }
        out.insert(code, IpSet { v4: merge(v4), v6: merge(v6), reverse });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb_bytes(field: u64, b: &[u8], out: &mut Vec<u8>) {
        out.push(((field << 3) | 2) as u8);
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }

    #[test]
    fn decodes_geosite_and_geoip() {
        // Domain{type=2 value="cn"}, Domain{type=3 value="a.com"}
        let mut d1 = vec![0x08, 2];
        pb_bytes(2, b"cn", &mut d1);
        let mut d2 = vec![0x08, 3];
        pb_bytes(2, b"a.com", &mut d2);
        let mut site = Vec::new();
        pb_bytes(1, b"CN", &mut site);
        pb_bytes(2, &d1, &mut site);
        pb_bytes(2, &d2, &mut site);
        let mut list = Vec::new();
        pb_bytes(1, &site, &mut list);
        let dir = std::env::temp_dir().join(format!("prism-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geosite.dat"), &list).unwrap();
        let sets = load_geosite(&dir.join("geosite.dat"), &["cn".into()]).unwrap();
        let cn = &sets["cn"];
        assert!(cn.matches("www.baidu.cn") && cn.matches("a.com") && !cn.matches("b.a.com"));

        // CIDR{ip=1.0.1.0 prefix=24}
        let mut cidr = Vec::new();
        pb_bytes(1, &[1, 0, 1, 0], &mut cidr);
        cidr.extend_from_slice(&[0x10, 24]);
        let mut ip = Vec::new();
        pb_bytes(1, b"CN", &mut ip);
        pb_bytes(2, &cidr, &mut ip);
        let mut list = Vec::new();
        pb_bytes(1, &ip, &mut list);
        std::fs::write(dir.join("geoip.dat"), &list).unwrap();
        let ips = load_geoip(&dir.join("geoip.dat"), &["CN".into()]).unwrap();
        assert!(ips["cn"].contains("1.0.1.200".parse().unwrap()));
        assert!(!ips["cn"].contains("1.0.2.1".parse().unwrap()));
    }
}
