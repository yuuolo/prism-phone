//! fake-ip pool: hands out addresses from a private range (default
//! 198.18.0.1/16) for domains and maps them back when connections arrive.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use ipnet::Ipv4Net;

pub struct FakeIpPool {
    pub range: Ipv4Net,
    first: u32,
    last: u32,
    inner: Mutex<Inner>,
}

struct Inner {
    next: u32,
    by_domain: HashMap<String, u32>,
    by_ip: HashMap<u32, String>,
}

impl FakeIpPool {
    /// `range` like `198.18.0.1/16`; the network address and the first host
    /// (gateway) are never handed out.
    pub fn new(range: &str) -> Option<Self> {
        let net: Ipv4Net = range.trim().parse().ok()?;
        let base = u32::from(net.network());
        let first = base + 2;
        let last = u32::from(net.broadcast()).saturating_sub(1);
        if net.prefix_len() > 29 || first > last {
            return None;
        }
        Some(FakeIpPool {
            range: net,
            first,
            last,
            inner: Mutex::new(Inner { next: first, by_domain: HashMap::new(), by_ip: HashMap::new() }),
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.range.contains(&v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| self.range.contains(&v4)),
        }
    }

    /// The fake address for `domain`, allocating one if needed. When the
    /// range is exhausted the oldest addresses are reused.
    pub fn get(&self, domain: &str) -> Ipv4Addr {
        let mut g = self.inner.lock().unwrap();
        if let Some(ip) = g.by_domain.get(domain) {
            return Ipv4Addr::from(*ip);
        }
        let ip = g.next;
        g.next = if ip >= self.last { self.first } else { ip + 1 };
        if let Some(old) = g.by_ip.insert(ip, domain.to_string()) {
            g.by_domain.remove(&old);
        }
        g.by_domain.insert(domain.to_string(), ip);
        Ipv4Addr::from(ip)
    }

    pub fn domain(&self, ip: IpAddr) -> Option<String> {
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => v6.to_ipv4_mapped()?,
        };
        self.inner.lock().unwrap().by_ip.get(&u32::from(v4)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_and_wraps() {
        let p = FakeIpPool::new("198.18.0.1/29").unwrap(); // hosts .2 .. .6
        let a = p.get("a.com");
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(p.get("a.com"), a);
        assert_eq!(p.domain(a.into()).as_deref(), Some("a.com"));
        for d in ["b", "c", "d", "e"] {
            p.get(d);
        }
        // pool of 5 is full; next allocation reuses .2 and forgets a.com
        assert_eq!(p.get("f"), Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(p.domain(a.into()).as_deref(), Some("f"));
        assert!(p.contains("198.18.0.4".parse().unwrap()) && !p.contains("1.1.1.1".parse().unwrap()));
    }
}
