//! mihomo's binary rule-set format (`format: mrs`), decoded into the same
//! entries a yaml / text rule-set would have.
//!
//! zstd( "MRS" 1 | behavior u8 (0 domain, 1 ipcidr) | count i64 |
//!       extra-length i64 | extra | payload ), integers big-endian.
//!
//! domain payload: version 1 | leaves (i64 n, n × u64) | label bitmap
//! (i64 n, n × u64) | labels (i64 n, n bytes): a LOUDS succinct trie of the
//! reversed domains, built breadth-first. Each node's children are a run of
//! 0 bits ended by a 1 bit; the n-th 0 bit carries labels[n].
//!
//! ipcidr payload: version 1 | i64 n | n × (from [16] | to [16]) ranges.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, ensure, Result};

const MAGIC: &[u8; 4] = b"MRS\x01";

struct Cur<'a>(&'a [u8]);

impl Cur<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(self.0.len() >= n, "mrs: truncated");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn len(&mut self) -> Result<usize> {
        let n = self.i64()?;
        ensure!(n >= 0 && (n as u64) < (1 << 32), "mrs: bad length {n}");
        Ok(n as usize)
    }
    fn u64s(&mut self) -> Result<Vec<u64>> {
        let n = self.len()?;
        let raw = self.take(n.checked_mul(8).ok_or_else(|| anyhow!("mrs: bad length"))?)?;
        Ok(raw.chunks_exact(8).map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect())
    }
}

fn bit(words: &[u64], i: usize) -> bool {
    words.get(i >> 6).is_some_and(|w| (w >> (i & 63)) & 1 == 1)
}

/// The rule-set entries in an mrs file, and its behavior (`domain` / `ipcidr`).
pub fn decode(data: &[u8]) -> Result<(String, Vec<String>)> {
    let mut raw = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(data)
        .map_err(|e| anyhow!("mrs: not zstd: {e}"))?
        .read_to_end(&mut raw)
        .map_err(|e| anyhow!("mrs: zstd: {e}"))?;
    let mut c = Cur(&raw);
    ensure!(c.take(4)? == MAGIC, "mrs: bad magic (not an mrs v1 file)");
    let behavior = c.u8()?;
    let count = c.i64()?;
    let extra = c.len()?;
    c.take(extra)?;
    let entries = match behavior {
        0 => domains(&mut c)?,
        1 => cidrs(&mut c)?,
        b => bail!("mrs: behavior {b} is not supported"),
    };
    let name = if behavior == 0 { "domain" } else { "ipcidr" };
    if count >= 0 && entries.len() as i64 != count && behavior == 1 {
        tracing::debug!("mrs: header says {count} entries, decoded {}", entries.len());
    }
    Ok((name.to_string(), entries))
}

fn domains(c: &mut Cur) -> Result<Vec<String>> {
    ensure!(c.u8()? == 1, "mrs: unknown domain set version");
    let leaves = c.u64s()?;
    let bitmap = c.u64s()?;
    let labels = c.len()?;
    let labels = c.take(labels)?;
    let total_bits = bitmap.len() * 64;
    // Node n's parent and the label on the edge into it (root: none).
    let mut parent: Vec<u32> = vec![u32::MAX];
    let mut label: Vec<u8> = vec![0];
    let (mut li, mut next_label) = (0usize, 0usize);
    let mut out = Vec::new();
    let mut node = 0usize;
    while node < parent.len() {
        if bit(&leaves, node) {
            // Walk up to the root: the reversed key, read leaf to root, is the domain.
            let mut key = Vec::new();
            let mut n = node;
            while n != 0 {
                key.push(label[n]);
                n = parent[n] as usize;
            }
            out.push(String::from_utf8_lossy(&key).into_owned());
        }
        loop {
            ensure!(li < total_bits, "mrs: domain trie is truncated");
            let end = bit(&bitmap, li);
            li += 1;
            if end {
                break;
            }
            let l = *labels.get(next_label).ok_or_else(|| anyhow!("mrs: missing label"))?;
            next_label += 1;
            parent.push(node as u32);
            label.push(l);
        }
        node += 1;
    }
    Ok(out)
}

fn cidrs(c: &mut Cur) -> Result<Vec<String>> {
    ensure!(c.u8()? == 1, "mrs: unknown ipcidr set version");
    let n = c.len()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let from = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16)?).unwrap());
        let to = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16)?).unwrap());
        match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
            (Some(a), Some(b)) => range_cidrs(u32::from(a) as u128, u32::from(b) as u128, 32, &mut out),
            _ => range_cidrs(u128::from(from), u128::from(to), 128, &mut out),
        }
    }
    Ok(out)
}

/// The fewest CIDRs covering `[from, to]` in a `bits`-wide address space.
fn range_cidrs(mut from: u128, to: u128, bits: u32, out: &mut Vec<String>) {
    while from <= to {
        // Largest block aligned at `from` that stays within `to`.
        let mut size = if from == 0 { bits } else { from.trailing_zeros().min(bits) };
        while size > 0 && (size >= 128 || from + ((1u128 << size) - 1) > to) {
            size -= 1;
        }
        let ip: IpAddr = if bits == 32 { Ipv4Addr::from(from as u32).into() } else { Ipv6Addr::from(from).into() };
        out.push(format!("{ip}/{}", bits - size));
        let step = if size >= 128 { return } else { 1u128 << size };
        match from.checked_add(step) {
            Some(n) => from = n,
            None => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_to_cidrs() {
        let mut v = Vec::new();
        range_cidrs(u32::from(Ipv4Addr::new(1, 0, 0, 0)) as u128, u32::from(Ipv4Addr::new(1, 0, 1, 255)) as u128, 32, &mut v);
        assert_eq!(v, ["1.0.0.0/23"]);
        v.clear();
        range_cidrs(u32::from(Ipv4Addr::new(10, 0, 0, 1)) as u128, u32::from(Ipv4Addr::new(10, 0, 0, 6)) as u128, 32, &mut v);
        assert_eq!(v, ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
        v.clear();
        range_cidrs(0, u32::MAX as u128, 32, &mut v);
        assert_eq!(v, ["0.0.0.0/0"]);
    }

    /// Files made by `mihomo convert-ruleset` (see tests/mrs.rs for the opt-in check).
    #[test]
    fn rejects_garbage() {
        assert!(decode(b"not zstd").is_err());
    }
}
