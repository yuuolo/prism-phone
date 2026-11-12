//! Domain patterns as used by mihomo (`fake-ip-filter`, `nameserver-policy`,
//! domain rule-providers):
//!
//! * `example.com`   — exactly this name
//! * `+.example.com` — the name and all subdomains
//! * `.example.com`  — all subdomains, not the name itself
//! * `*.example.com` — exactly one extra label (`a.example.com`)
//! * geosite categories (added as [`DomainSet`]s by the caller)

use std::collections::HashSet;
use std::sync::Arc;

use crate::geo::DomainSet;

#[derive(Default)]
pub struct DomainMatcher {
    full: HashSet<String>,
    suffix: HashSet<String>,
    sub_only: HashSet<String>,
    one_level: HashSet<String>,
    sets: Vec<Arc<DomainSet>>,
}

impl DomainMatcher {
    /// Adds a pattern; returns false if it isn't understood.
    pub fn add(&mut self, pattern: &str) -> bool {
        let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if p.is_empty() {
            return false;
        }
        if let Some(rest) = p.strip_prefix("+.") {
            self.suffix.insert(rest.to_string());
        } else if let Some(rest) = p.strip_prefix("*.") {
            if rest.contains('*') {
                return false;
            }
            self.one_level.insert(rest.to_string());
        } else if let Some(rest) = p.strip_prefix('.') {
            self.sub_only.insert(rest.to_string());
        } else if p.contains('*') {
            return false;
        } else {
            self.full.insert(p);
        }
        true
    }

    pub fn add_set(&mut self, set: Arc<DomainSet>) {
        self.sets.push(set);
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.sub_only.len() + self.one_level.len() + self.sets.iter().map(|s| s.len()).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if self.full.contains(host) || self.suffix.contains(host) {
            return true;
        }
        if let Some((_, parent)) = host.split_once('.') {
            if self.one_level.contains(parent) {
                return true;
            }
            let mut h = parent;
            loop {
                if self.suffix.contains(h) || self.sub_only.contains(h) {
                    return true;
                }
                match h.split_once('.') {
                    Some((_, rest)) => h = rest,
                    None => break,
                }
            }
        }
        self.sets.iter().any(|s| s.matches(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mihomo_patterns() {
        let mut m = DomainMatcher::default();
        for p in ["exact.com", "+.plus.com", ".dot.com", "*.star.com", "*.lan"] {
            assert!(m.add(p));
        }
        assert!(!m.add("a.*.com"));
        assert!(m.matches("exact.com") && !m.matches("a.exact.com"));
        assert!(m.matches("plus.com") && m.matches("a.b.plus.com"));
        assert!(!m.matches("dot.com") && m.matches("a.dot.com") && m.matches("a.b.dot.com"));
        assert!(!m.matches("star.com") && m.matches("a.star.com") && !m.matches("a.b.star.com"));
        assert!(m.matches("router.lan") && !m.matches("notplus.com"));
    }
}
