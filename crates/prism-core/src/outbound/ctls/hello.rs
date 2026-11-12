//! A ClientHello shaped like current Chrome's (BoringSSL): GREASE values,
//! shuffled extension order, X25519MLKEM768 + X25519 key shares, ALPS,
//! certificate compression and an ECH GREASE extension.

use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_P256: u16 = 0x0017;
pub const GROUP_P384: u16 = 0x0018;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

/// Chrome's cipher suites after the GREASE one.
const CIPHERS: [u16; 15] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
const SIG_ALGS: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

/// A random GREASE value (0x?a?a), RFC 8701.
pub fn grease(rng: &mut impl Rng) -> u16 {
    let n = rng.gen_range(0..16u16);
    (n << 12) | 0x0a00 | (n << 4) | 0x0a
}

/// One offered key share: group and its public value.
pub struct Share {
    pub group: u16,
    pub public: Vec<u8>,
}

pub struct Params<'a> {
    pub server_name: Option<&'a str>,
    pub alpn: &'a [String],
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub shares: &'a [Share],
    /// HelloRetryRequest cookie to echo.
    pub cookie: Option<&'a [u8]>,
}

fn u16be(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn with_len16(v: &mut Vec<u8>, body: &[u8]) {
    u16be(v, body.len() as u16);
    v.extend_from_slice(body);
}

fn ext(ty: u16, body: Vec<u8>) -> (u16, Vec<u8>) {
    (ty, body)
}

/// The ClientHello handshake message (type, length, body). The session id
/// sits at bytes 39..71 (Reality writes its auth data there).
pub fn build(p: &Params, rng: &mut (impl Rng + RngCore)) -> Vec<u8> {
    let g_cipher = grease(rng);
    let g_group = grease(rng);
    let g_version = grease(rng);
    let g_ext1 = grease(rng);
    let mut g_ext2 = grease(rng);
    while g_ext2 == g_ext1 {
        g_ext2 = grease(rng);
    }

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    if let Some(name) = p.server_name.filter(|n| n.parse::<std::net::IpAddr>().is_err()) {
        let mut list = vec![0u8];
        with_len16(&mut list, name.as_bytes());
        let mut body = Vec::new();
        with_len16(&mut body, &list);
        exts.push(ext(0x0000, body));
    }
    exts.push(ext(0x0017, vec![])); // extended_master_secret
    exts.push(ext(0xff01, vec![0])); // renegotiation_info
    {
        let mut groups = Vec::new();
        for g in [g_group, GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_P256, GROUP_P384] {
            u16be(&mut groups, g);
        }
        let mut body = Vec::new();
        with_len16(&mut body, &groups);
        exts.push(ext(0x000a, body));
    }
    exts.push(ext(0x000b, vec![1, 0])); // ec_point_formats: uncompressed
    exts.push(ext(0x0023, vec![])); // session_ticket
    if !p.alpn.is_empty() {
        let mut list = Vec::new();
        for a in p.alpn {
            list.push(a.len() as u8);
            list.extend_from_slice(a.as_bytes());
        }
        let mut body = Vec::new();
        with_len16(&mut body, &list);
        exts.push(ext(0x0010, body));
    }
    exts.push(ext(0x0005, vec![1, 0, 0, 0, 0])); // status_request (OCSP)
    {
        let mut algs = Vec::new();
        for a in SIG_ALGS {
            u16be(&mut algs, a);
        }
        let mut body = Vec::new();
        with_len16(&mut body, &algs);
        exts.push(ext(0x000d, body));
    }
    exts.push(ext(0x0012, vec![])); // signed_certificate_timestamp
    {
        let mut shares = Vec::new();
        u16be(&mut shares, g_group);
        with_len16(&mut shares, &[0]);
        for s in p.shares {
            u16be(&mut shares, s.group);
            with_len16(&mut shares, &s.public);
        }
        let mut body = Vec::new();
        with_len16(&mut body, &shares);
        exts.push(ext(0x0033, body));
    }
    exts.push(ext(0x002d, vec![1, 1])); // psk_key_exchange_modes: psk_dhe_ke
    {
        let mut body = vec![6];
        for v in [g_version, 0x0304, 0x0303] {
            u16be(&mut body, v);
        }
        exts.push(ext(0x002b, body));
    }
    exts.push(ext(0x001b, vec![2, 0, 2])); // compress_certificate: brotli
    if p.alpn.iter().any(|a| a == "h2") {
        // application_settings (ALPS) for h2, new codepoint.
        let mut list = vec![2];
        list.extend_from_slice(b"h2");
        let mut body = Vec::new();
        with_len16(&mut body, &list);
        exts.push(ext(0x44cd, body));
    }
    {
        // ECH GREASE: outer hello, HKDF-SHA256 / AES-128-GCM, random config.
        let mut body = vec![0u8, 0, 1, 0, 1, rng.gen()];
        let mut enc = [0u8; 32];
        rng.fill_bytes(&mut enc);
        with_len16(&mut body, &enc);
        let mut payload = vec![0u8; *[144usize, 176, 208, 240].choose(rng).unwrap()];
        rng.fill_bytes(&mut payload);
        with_len16(&mut body, &payload);
        exts.push(ext(0xfe0d, body));
    }
    if let Some(cookie) = p.cookie {
        let mut body = Vec::new();
        with_len16(&mut body, cookie);
        exts.push(ext(0x002c, body));
    }
    // Chrome shuffles everything between the two GREASE extensions.
    exts.shuffle(rng);
    exts.insert(0, (g_ext1, vec![]));
    exts.push((g_ext2, vec![0]));

    let mut ext_bytes = Vec::new();
    for (ty, body) in &exts {
        u16be(&mut ext_bytes, *ty);
        with_len16(&mut ext_bytes, body);
    }

    let mut body = Vec::with_capacity(512 + ext_bytes.len());
    u16be(&mut body, 0x0303);
    body.extend_from_slice(&p.random);
    body.push(32);
    body.extend_from_slice(&p.session_id);
    let mut ciphers = Vec::new();
    u16be(&mut ciphers, g_cipher);
    for c in CIPHERS {
        u16be(&mut ciphers, c);
    }
    with_len16(&mut body, &ciphers);
    body.extend_from_slice(&[1, 0]); // compression: null
    with_len16(&mut body, &ext_bytes);

    let mut msg = vec![1u8];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Parsed view of a ClientHello for checks: (cipher suites, extension
    /// types in order, groups, ALPN).
    pub fn inspect(msg: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u16>) {
        let b = &msg[4..];
        let mut i = 2 + 32;
        let sid = b[i] as usize;
        i += 1 + sid;
        let cl = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        let ciphers = b[i + 2..i + 2 + cl].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        i += 2 + cl;
        i += 1 + b[i] as usize;
        let el = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        let mut exts = Vec::new();
        let mut groups = Vec::new();
        let mut j = i + 2;
        while j < i + 2 + el {
            let ty = u16::from_be_bytes([b[j], b[j + 1]]);
            let len = u16::from_be_bytes([b[j + 2], b[j + 3]]) as usize;
            if ty == 0x000a {
                groups = b[j + 6..j + 4 + len].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            exts.push(ty);
            j += 4 + len;
        }
        (ciphers, exts, groups)
    }

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
    }

    /// JA4's first part (`t13d1516h2` for Chrome).
    pub fn ja4_a(msg: &[u8]) -> String {
        let (ciphers, exts, _) = inspect(msg);
        let c = ciphers.iter().filter(|c| !is_grease(**c)).count();
        let e = exts.iter().filter(|e| !is_grease(**e)).count();
        let sni = if exts.contains(&0) { 'd' } else { 'i' };
        format!("t13{sni}{c:02}{e:02}h2")
    }

    /// JA4's third part: sorted extensions (no SNI / ALPN / GREASE) and
    /// signature algorithms, hashed.
    pub fn ja4_c(msg: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let (_, exts, _) = inspect(msg);
        let mut e: Vec<String> = exts.iter().filter(|x| !is_grease(**x) && **x != 0 && **x != 0x10).map(|x| format!("{x:04x}")).collect();
        e.sort();
        let sigs: Vec<String> = SIG_ALGS.iter().map(|x| format!("{x:04x}")).collect();
        let h = Sha256::digest(format!("{}_{}", e.join(","), sigs.join(",")).as_bytes());
        h.iter().take(6).map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn looks_like_chrome() {
        let mut rng = rand::thread_rng();
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let shares = [Share { group: GROUP_X25519_MLKEM768, public: vec![1; 1216] }, Share { group: GROUP_X25519, public: vec![2; 32] }];
        let p = Params { server_name: Some("www.example.com"), alpn: &alpn, random: [3; 32], session_id: [4; 32], shares: &shares, cookie: None };
        let a = build(&p, &mut rng);
        let b = build(&p, &mut rng);
        assert_eq!(ja4_a(&a), "t13d1516h2");
        // Chrome 131+ (ALPS 0x44cd): t13d1516h2_8daaf6152771_d8a2da3f94cd
        assert_eq!(ja4_c(&a), "d8a2da3f94cd");
        let (ciphers, exts, groups) = inspect(&a);
        assert!(is_grease(ciphers[0]) && ciphers[1..] == CIPHERS);
        assert!(is_grease(exts[0]) && is_grease(*exts.last().unwrap()));
        assert_eq!(groups[1..], [GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_P256, GROUP_P384]);
        // Order differs between connections; the set doesn't.
        let (_, exts_b, _) = inspect(&b);
        let set = |e: &[u16]| {
            let mut v: Vec<u16> = e.iter().copied().filter(|x| !is_grease(*x)).collect();
            v.sort();
            v
        };
        assert_eq!(set(&exts), set(&exts_b));
        // The session id is where Reality expects it.
        assert_eq!(&a[39..71], &[4u8; 32]);
        // An IP address gets no SNI (JA4 'i').
        let p_ip = Params { server_name: Some("1.2.3.4"), ..p };
        assert!(ja4_a(&build(&p_ip, &mut rng)).starts_with("t13i"));
    }
}
