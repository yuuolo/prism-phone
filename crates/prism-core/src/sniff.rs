//! Recovers the destination domain from the first bytes of a connection
//! (TLS ClientHello SNI or HTTP Host), so TUN connections that arrive as bare
//! IPs can still be routed by domain rules and resolved by the proxy server.

/// Returns `Some(host)` when the data is a complete TLS ClientHello with SNI
/// or an HTTP request head with a Host header.
pub fn domain(data: &[u8]) -> Option<String> {
    tls_sni(data).or_else(|| http_host(data))
}

/// For a TLS record header, the number of bytes the full first record needs.
pub fn tls_record_len(data: &[u8]) -> Option<usize> {
    if data.len() >= 5 && data[0] == 0x16 && data[1] == 3 {
        Some(5 + u16::from_be_bytes([data[3], data[4]]) as usize)
    } else {
        None
    }
}

fn tls_sni(data: &[u8]) -> Option<String> {
    let rec_len = tls_record_len(data)?;
    let body = data.get(5..rec_len.min(data.len()))?;
    // Handshake: type(1)=ClientHello, len(3), version(2), random(32)
    if *body.first()? != 1 {
        return None;
    }
    let mut p = 4 + 2 + 32;
    let sid = *body.get(p)? as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs;
    let comp = *body.get(p)? as usize;
    p += 1 + comp;
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_total).min(body.len());
    while p + 4 <= end {
        let ty = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if ty == 0 {
            // server_name_list: len(2), [type(1)=0, len(2), name]
            let ext = body.get(p..p + len)?;
            let name_len = u16::from_be_bytes([*ext.get(3)?, *ext.get(4)?]) as usize;
            if *ext.get(2)? != 0 {
                return None;
            }
            let name = std::str::from_utf8(ext.get(5..5 + name_len)?).ok()?;
            return valid(name);
        }
        p += len;
    }
    None
}

fn http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(&data[..data.len().min(4096)]).ok()?;
    let method = text.split(' ').next()?;
    if !["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT"].contains(&method) {
        return None;
    }
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                if v.starts_with('[') {
                    return None; // IPv6 literal
                }
                let host = match v.rsplit_once(':') {
                    Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
                    _ => v,
                };
                return valid(host);
            }
        }
    }
    None
}

fn valid(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() < 254
        && n.parse::<std::net::IpAddr>().is_err()
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    ok.then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        let name = sni.as_bytes();
        let list_len = (3 + name.len()) as u16;
        ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
        ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[1, 0]); // compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&hello);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sniffs_tls_and_http() {
        let ch = client_hello("www.Google.com");
        assert_eq!(tls_record_len(&ch), Some(ch.len()));
        assert_eq!(domain(&ch).as_deref(), Some("www.google.com"));
        assert_eq!(domain(&ch[..20]), None); // incomplete
        assert_eq!(domain(b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n").as_deref(), Some("example.com"));
        assert_eq!(domain(b"GET / HTTP/1.1\r\nhost: a.b.cn\r\n\r\n").as_deref(), Some("a.b.cn"));
        assert_eq!(domain(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"), None);
        assert_eq!(domain(b"\x00\x01binary"), None);
    }
}
