//! Minimal DNS message handling: questions, A/AAAA answers, response
//! building. Enough for a forwarding / fake-ip resolver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Lower-case, without the trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub fn id(msg: &[u8]) -> u16 {
    if msg.len() < 2 {
        return 0;
    }
    u16::from_be_bytes([msg[0], msg[1]])
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

pub fn rcode(msg: &[u8]) -> u8 {
    msg.get(3).map(|b| b & 0x0f).unwrap_or(RCODE_SERVFAIL)
}

/// Reads a (possibly compressed) name starting at `pos`; returns the name
/// and the offset just after it in the original position.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            let name = labels.join(".").to_ascii_lowercase();
            return Some((name, end.unwrap_or(pos + 1)));
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
    None
}

fn write_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        let l = &label.as_bytes()[..label.len().min(63)];
        buf.push(l.len() as u8);
        buf.extend_from_slice(l);
    }
    buf.push(0);
}

/// First question of a message, plus the offset where the question ends.
pub fn question(msg: &[u8]) -> Option<(Question, usize)> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let (name, pos) = read_name(msg, 12)?;
    let qtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*msg.get(pos + 2)?, *msg.get(pos + 3)?]);
    Some((Question { name, qtype, qclass }, pos + 4))
}

/// A recursive query for `name`.
pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + name.len());
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    write_name(&mut m, name);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m
}

/// Builds a response to `query` (same id and question) with the given
/// address answers.
pub fn response(query: &[u8], rcode: u8, answers: &[(IpAddr, u32)]) -> Option<Vec<u8>> {
    let (_, qend) = question(query)?;
    let mut m = Vec::with_capacity(qend + answers.len() * 28);
    m.extend_from_slice(&query[..2]);
    let rd = query[2] & 0x01;
    m.push(0x80 | rd); // QR, RD copied
    m.push(0x80 | (rcode & 0x0f)); // RA
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&query[12..qend]);
    for (ip, ttl) in answers {
        m.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to the question
        match ip {
            IpAddr::V4(v4) => {
                m.extend_from_slice(&TYPE_A.to_be_bytes());
                m.extend_from_slice(&1u16.to_be_bytes());
                m.extend_from_slice(&ttl.to_be_bytes());
                m.extend_from_slice(&4u16.to_be_bytes());
                m.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                m.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                m.extend_from_slice(&1u16.to_be_bytes());
                m.extend_from_slice(&ttl.to_be_bytes());
                m.extend_from_slice(&16u16.to_be_bytes());
                m.extend_from_slice(&v6.octets());
            }
        }
    }
    Some(m)
}

/// A/AAAA records in the answer section with their TTLs, and the smallest
/// TTL of all answer records (None if there are no answers).
pub fn answers(msg: &[u8]) -> Option<(Vec<(IpAddr, u32)>, Option<u32>)> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(msg, pos)?;
        pos = p + 4;
    }
    let mut out = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..an {
        let (_, p) = read_name(msg, pos)?;
        let ty = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
        let ttl = u32::from_be_bytes([*msg.get(p + 4)?, *msg.get(p + 5)?, *msg.get(p + 6)?, *msg.get(p + 7)?]);
        let rdlen = u16::from_be_bytes([*msg.get(p + 8)?, *msg.get(p + 9)?]) as usize;
        let rdata = msg.get(p + 10..p + 10 + rdlen)?;
        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
        match (ty, rdlen) {
            (TYPE_A, 4) => out.push((IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])), ttl)),
            (TYPE_AAAA, 16) => {
                let b: [u8; 16] = rdata.try_into().ok()?;
                out.push((IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            _ => {}
        }
        pos = p + 10 + rdlen;
    }
    Some((out, min_ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_response_roundtrip() {
        let q = query(0x1234, "WWW.Example.com.", TYPE_A);
        let (qq, _) = question(&q).unwrap();
        assert_eq!(qq, Question { name: "www.example.com".into(), qtype: TYPE_A, qclass: 1 });
        let r = response(&q, RCODE_NOERROR, &[("1.2.3.4".parse().unwrap(), 60), ("::1".parse().unwrap(), 30)]).unwrap();
        assert_eq!(id(&r), 0x1234);
        assert_eq!(rcode(&r), 0);
        let (ans, min) = answers(&r).unwrap();
        assert_eq!(ans.len(), 2);
        assert_eq!(ans[0].0, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(min, Some(30));
        assert_eq!(question(&r).unwrap().0.name, "www.example.com");
    }

    #[test]
    fn compressed_cname_chain() {
        // Response for a.example: CNAME b.example (compressed), A 9.9.9.9
        let q = query(7, "a.example", TYPE_A);
        let mut r = response(&q, 0, &[]).unwrap();
        r[7] = 2; // two answers
        // CNAME record: name ptr to question, type 5, class 1, ttl 100, rdata "b" + ptr(offset of "example" in question)
        let example_off = 12 + 2; // after "\x01a"
        r.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 100, 0, 4, 1, b'b', 0xc0, example_off as u8]);
        let cname_off = r.len() - 4;
        r.extend_from_slice(&[0xc0, cname_off as u8, 0, 1, 0, 1, 0, 0, 0, 50, 0, 4, 9, 9, 9, 9]);
        let (ans, min) = answers(&r).unwrap();
        assert_eq!(ans, vec![("9.9.9.9".parse().unwrap(), 50)]);
        assert_eq!(min, Some(50));
    }
}
