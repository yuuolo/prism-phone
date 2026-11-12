//! A TLS 1.3 client whose ClientHello looks like Chrome's (`client-fingerprint`),
//! also used for VLESS REALITY, which hides its authentication in the
//! ClientHello (session id) and needs the client's X25519 key.
//!
//! TLS 1.3 only: a server that answers with TLS 1.2 makes the handshake fail
//! with `ErrorKind::Unsupported`, and `Tls::connect` falls back to rustls.
//! Either direction can be switched to raw TCP (VLESS Vision's direct copy).

mod cert;
pub mod hello;
mod keys;

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::{invalid, other};
use hello::{Share, GROUP_P256, GROUP_P384, GROUP_X25519, GROUP_X25519_MLKEM768};
use keys::{Cipher, HashAlg, Suite};

const MAX_RECORD: usize = 16384;

#[derive(Clone, Debug)]
pub struct Reality {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

impl Reality {
    /// From the base64url public key and hex short id of a profile.
    pub fn parse(public_key: &str, short_id: &str) -> Option<Self> {
        use base64::Engine;
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key.trim().trim_end_matches('=')).ok()?;
        let public_key: [u8; 32] = pk.try_into().ok()?;
        let sid = short_id.trim();
        if sid.len() > 16 || sid.len() % 2 != 0 {
            return None;
        }
        let mut short = [0u8; 8];
        for i in 0..sid.len() / 2 {
            short[i] = u8::from_str_radix(&sid[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Reality { public_key, short_id: short })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub skip_verify: bool,
    pub reality: Option<Reality>,
}

/// Client version REALITY servers see (Xray reads it as x.y.z).
const REALITY_VERSION: [u8; 3] = [25, 9, 11];

struct Keys {
    x25519: x25519_dalek::StaticSecret,
    mlkem: <ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey,
    mlkem_public: Vec<u8>,
}

fn alert_error(desc: u8) -> io::Error {
    let name = match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "alert",
    };
    other(format!("TLS alert from server: {name} ({desc})"))
}

/// Reads whole records from the socket during the handshake.
struct RecordReader {
    raw: Vec<u8>,
}

impl RecordReader {
    async fn next<S: AsyncRead + Unpin>(&mut self, io: &mut S) -> io::Result<([u8; 5], Vec<u8>)> {
        loop {
            if self.raw.len() >= 5 {
                let len = u16::from_be_bytes([self.raw[3], self.raw[4]]) as usize;
                if len > MAX_RECORD + 256 {
                    return Err(invalid("TLS record too large"));
                }
                if self.raw.len() >= 5 + len {
                    let hdr: [u8; 5] = self.raw[..5].try_into().unwrap();
                    let body = self.raw[5..5 + len].to_vec();
                    self.raw.drain(..5 + len);
                    return Ok((hdr, body));
                }
            }
            let mut buf = [0u8; 8192];
            let n = io.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed the connection during the TLS handshake"));
            }
            self.raw.extend_from_slice(&buf[..n]);
        }
    }
}

/// Handshake messages from records, split at message boundaries.
struct Messages {
    buf: Vec<u8>,
}

impl Messages {
    /// Next complete message (type, whole message bytes).
    fn pop(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if self.buf.len() < 4 + len {
            return None;
        }
        let msg: Vec<u8> = self.buf.drain(..4 + len).collect();
        Some((msg[0], msg))
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(invalid("truncated TLS message"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> io::Result<usize> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }
    fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
}

/// SHA-256 of "HelloRetryRequest": the ServerHello random of an HRR.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33,
    0x9c,
];

struct ServerHello {
    suite: Suite,
    hrr: bool,
    group: u16,
    key: Vec<u8>,
    cookie: Option<Vec<u8>>,
    tls13: bool,
}

fn parse_server_hello(msg: &[u8]) -> io::Result<ServerHello> {
    let mut c = Cursor(&msg[4..]);
    let _legacy = c.u16()?;
    let random = c.take(32)?;
    let _sid = c.vec8()?;
    let suite_id = c.u16()?;
    let _comp = c.u8()?;
    let mut sh = ServerHello { suite: Suite::Aes128Gcm, hrr: random == HRR_RANDOM, group: 0, key: vec![], cookie: None, tls13: false };
    let mut exts = Cursor(if c.0.is_empty() { &[] } else { c.vec16()? });
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let body = exts.vec16()?;
        let mut b = Cursor(body);
        match ty {
            0x002b => sh.tls13 = b.u16()? == 0x0304,
            0x0033 => {
                sh.group = b.u16()?;
                if !sh.hrr {
                    sh.key = b.vec16()?.to_vec();
                }
            }
            0x002c => sh.cookie = Some(b.vec16()?.to_vec()),
            _ => {}
        }
    }
    if !sh.tls13 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "server negotiated TLS 1.2"));
    }
    sh.suite = Suite::from_id(suite_id).ok_or_else(|| invalid(format!("server chose unknown cipher suite {suite_id:#06x}")))?;
    Ok(sh)
}

fn record(ty: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut r = vec![ty];
    r.extend_from_slice(&version.to_be_bytes());
    r.extend_from_slice(&(body.len() as u16).to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// REALITY's session id: AES-256-GCM over version/time/short id, keyed by
/// ECDH(our X25519 key, server's REALITY key), with the zeroed hello as AAD.
fn reality_session_id(r: &Reality, x25519: &x25519_dalek::StaticSecret, random: &[u8; 32], hello: &[u8]) -> io::Result<(Vec<u8>, [u8; 32])> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let shared = x25519.diffie_hellman(&x25519_dalek::PublicKey::from(r.public_key));
    let mut auth = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&random[..20]), shared.as_bytes())
        .expand(b"REALITY", &mut auth)
        .map_err(|_| other("REALITY key derivation failed"))?;
    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&REALITY_VERSION);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as u32;
    plain[4..8].copy_from_slice(&now.to_be_bytes());
    plain[8..].copy_from_slice(&r.short_id);
    let sealed = aes_gcm::Aes256Gcm::new_from_slice(&auth)
        .unwrap()
        .encrypt((&random[20..32]).into(), Payload { msg: &plain, aad: hello })
        .map_err(|_| other("REALITY seal failed"))?;
    Ok((sealed, auth))
}

/// Runs the TLS 1.3 handshake over `io`.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, cfg: &Config) -> io::Result<TlsStream<S>> {
    use ml_kem::{EncodedSizeUser, KemCore};
    use rand::SeedableRng;
    // Not thread_rng(): the handshake future must stay Send.
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    let keys = Keys { x25519: x25519_dalek::StaticSecret::from(secret), mlkem_public: ek.as_bytes().to_vec(), mlkem: dk };
    let x_pub = x25519_dalek::PublicKey::from(&keys.x25519).to_bytes();
    let mut hybrid = keys.mlkem_public.clone();
    hybrid.extend_from_slice(&x_pub);
    let shares = [Share { group: GROUP_X25519_MLKEM768, public: hybrid }, Share { group: GROUP_X25519, public: x_pub.to_vec() }];

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    if cfg.reality.is_none() {
        rng.fill_bytes(&mut session_id);
    }
    let sni = (!cfg.server_name.is_empty()).then_some(cfg.server_name.as_str());
    let params = hello::Params { server_name: sni, alpn: &cfg.alpn, random, session_id, shares: &shares, cookie: None };
    let mut ch = hello::build(&params, &mut rng);
    let mut auth_key = None;
    if let Some(r) = &cfg.reality {
        let (sid, auth) = reality_session_id(r, &keys.x25519, &random, &ch)?;
        ch[39..71].copy_from_slice(&sid);
        auth_key = Some(auth);
    }
    io.write_all(&record(0x16, 0x0301, &ch)).await?;

    let mut reader = RecordReader { raw: Vec::new() };
    let mut msgs = Messages { buf: Vec::new() };
    let mut transcript = ch.clone();
    let mut retried = false;
    let mut p_key: Option<ring::agreement::EphemeralPrivateKey> = None;

    // ServerHello (maybe after one HelloRetryRequest).
    let sh = loop {
        let msg = loop {
            if let Some(m) = msgs.pop() {
                break m;
            }
            let (hdr, body) = reader.next(&mut io).await?;
            match hdr[0] {
                0x16 => msgs.buf.extend_from_slice(&body),
                0x15 => return Err(alert_error(*body.get(1).unwrap_or(&0))),
                0x14 => {}
                _ => return Err(invalid("unexpected TLS record before ServerHello")),
            }
        };
        if msg.0 != 2 {
            return Err(invalid("expected ServerHello"));
        }
        let sh = parse_server_hello(&msg.1)?;
        if !sh.hrr {
            transcript.extend_from_slice(&msg.1);
            break sh;
        }
        // HelloRetryRequest: the server wants a share we didn't send.
        if retried || cfg.reality.is_some() || !matches!(sh.group, GROUP_P256 | GROUP_P384) {
            return Err(invalid(format!("server asked for key share group {:#06x}", sh.group)));
        }
        retried = true;
        let alg = if sh.group == GROUP_P256 { &ring::agreement::ECDH_P256 } else { &ring::agreement::ECDH_P384 };
        let k = ring::agreement::EphemeralPrivateKey::generate(alg, &ring::rand::SystemRandom::new()).map_err(|_| other("ECDH keygen"))?;
        let public = k.compute_public_key().map_err(|_| other("ECDH keygen"))?.as_ref().to_vec();
        p_key = Some(k);
        let h = sh.suite.hash();
        let mut synthetic = vec![254, 0, 0, h.len() as u8];
        synthetic.extend_from_slice(&h.hash(&transcript));
        transcript = synthetic;
        transcript.extend_from_slice(&msg.1);
        let retry_shares = [Share { group: sh.group, public }];
        let p2 = hello::Params { shares: &retry_shares, cookie: sh.cookie.as_deref(), ..params };
        ch = hello::build(&p2, &mut rng);
        transcript.extend_from_slice(&ch);
        io.write_all(&record(0x16, 0x0303, &ch)).await?;
    };

    let shared = match sh.group {
        GROUP_X25519 => {
            let pk: [u8; 32] = sh.key.as_slice().try_into().map_err(|_| invalid("bad X25519 share"))?;
            let s = keys.x25519.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
            if !s.was_contributory() {
                return Err(invalid("bad X25519 share"));
            }
            s.as_bytes().to_vec()
        }
        GROUP_X25519_MLKEM768 => {
            use ml_kem::kem::Decapsulate;
            if sh.key.len() != 1088 + 32 {
                return Err(invalid("bad X25519MLKEM768 share"));
            }
            let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(&sh.key[..1088]).map_err(|_| invalid("bad ML-KEM ciphertext"))?;
            let ss = keys.mlkem.decapsulate(&ct).map_err(|_| invalid("ML-KEM decapsulation failed"))?;
            let pk: [u8; 32] = sh.key[1088..].try_into().unwrap();
            let x = keys.x25519.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
            let mut s = ss.to_vec();
            s.extend_from_slice(x.as_bytes());
            s
        }
        GROUP_P256 | GROUP_P384 => {
            let k = p_key.take().ok_or_else(|| invalid("unexpected key share group"))?;
            let alg = if sh.group == GROUP_P256 { &ring::agreement::ECDH_P256 } else { &ring::agreement::ECDH_P384 };
            ring::agreement::agree_ephemeral(k, &ring::agreement::UnparsedPublicKey::new(alg, &sh.key), |s| s.to_vec())
                .map_err(|_| invalid("bad ECDH share"))?
        }
        g => return Err(invalid(format!("server chose key share group {g:#06x}"))),
    };

    // Key schedule up to the handshake traffic secrets.
    let h: HashAlg = sh.suite.hash();
    let early = h.extract(&[], &vec![0u8; h.len()]);
    let derived = h.derive_secret(&early, "derived", &h.hash(&[]));
    let hs = h.extract(&derived, &shared);
    let th = h.hash(&transcript);
    let c_hs = h.derive_secret(&hs, "c hs traffic", &th);
    let s_hs = h.derive_secret(&hs, "s hs traffic", &th);
    let mut rd = Cipher::new(sh.suite, &s_hs);
    let mut wr = Cipher::new(sh.suite, &c_hs);

    let mut alpn = None;
    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut cert_requested: Option<Vec<u8>> = None;
    let mut verified = false;
    loop {
        let (ty, msg) = loop {
            if let Some(m) = msgs.pop() {
                break m;
            }
            let (hdr, body) = reader.next(&mut io).await?;
            match hdr[0] {
                0x14 => continue,
                0x15 => return Err(alert_error(*body.get(1).unwrap_or(&0))),
                0x17 => {
                    let (inner, data) = rd.open(&hdr, &body).ok_or_else(|| invalid("TLS handshake decryption failed"))?;
                    match inner {
                        0x16 => msgs.buf.extend_from_slice(&data),
                        0x15 => return Err(alert_error(*data.get(1).unwrap_or(&0))),
                        _ => return Err(invalid("unexpected TLS content during handshake")),
                    }
                }
                _ => return Err(invalid("unexpected TLS record during handshake")),
            }
        };
        match ty {
            8 => {
                // EncryptedExtensions: ALPN.
                let mut c = Cursor(&msg[4..]);
                let mut exts = Cursor(c.vec16()?);
                while !exts.0.is_empty() {
                    let ety = exts.u16()?;
                    let body = exts.vec16()?;
                    if ety == 0x0010 {
                        let mut b = Cursor(body);
                        let mut list = Cursor(b.vec16()?);
                        alpn = Some(String::from_utf8_lossy(list.vec8()?).into_owned());
                    }
                }
                transcript.extend_from_slice(&msg);
            }
            13 => {
                let mut c = Cursor(&msg[4..]);
                cert_requested = Some(c.vec8()?.to_vec());
                transcript.extend_from_slice(&msg);
            }
            11 | 25 => {
                let body = if ty == 25 {
                    // CompressedCertificate (RFC 8879): brotli only, as offered.
                    let mut c = Cursor(&msg[4..]);
                    if c.u16()? != 2 {
                        return Err(invalid("unsupported certificate compression"));
                    }
                    let len = c.u24()?;
                    if len > 1 << 20 {
                        return Err(invalid("certificate too large"));
                    }
                    let compressed = c.vec24()?;
                    let mut out = Vec::with_capacity(len);
                    brotli_decompressor::BrotliDecompress(&mut &compressed[..], &mut out).map_err(|_| invalid("bad compressed certificate"))?;
                    if out.len() != len {
                        return Err(invalid("bad compressed certificate"));
                    }
                    out
                } else {
                    msg[4..].to_vec()
                };
                let mut c = Cursor(&body);
                let _ctx = c.vec8()?;
                let mut list = Cursor(c.vec24()?);
                while !list.0.is_empty() {
                    chain.push(list.vec24()?.to_vec());
                    let _exts = list.vec16()?;
                }
                transcript.extend_from_slice(&msg);
            }
            15 => {
                let mut c = Cursor(&msg[4..]);
                let scheme = c.u16()?;
                let sig = c.vec16()?;
                let th = h.hash(&transcript);
                match &auth_key {
                    Some(auth) => cert::verify_reality(&chain, auth, scheme, sig, &th)?,
                    None => cert::verify_webpki(&chain, &cfg.server_name, scheme, sig, &th, cfg.skip_verify)?,
                }
                verified = true;
                transcript.extend_from_slice(&msg);
            }
            20 => {
                if !verified {
                    return Err(invalid("server finished without authenticating"));
                }
                let finished_key = h.expand_label(&s_hs, "finished", &[], h.len());
                let expected = h.hmac(&finished_key, &h.hash(&transcript));
                if msg[4..] != expected[..] {
                    return Err(invalid("server Finished doesn't verify"));
                }
                transcript.extend_from_slice(&msg);
                break;
            }
            _ => return Err(invalid(format!("unexpected handshake message {ty}"))),
        }
    }

    let derived2 = h.derive_secret(&hs, "derived", &h.hash(&[]));
    let master = h.extract(&derived2, &vec![0u8; h.len()]);
    let th = h.hash(&transcript);
    let c_ap = h.derive_secret(&master, "c ap traffic", &th);
    let s_ap = h.derive_secret(&master, "s ap traffic", &th);

    // Our second flight: compatibility CCS, (empty) Certificate, Finished.
    let mut flight = record(0x14, 0x0303, &[1]);
    if let Some(ctx) = cert_requested {
        let mut m = vec![11u8, 0, 0, 0];
        m.push(ctx.len() as u8);
        m.extend_from_slice(&ctx);
        m.extend_from_slice(&[0, 0, 0]);
        let len = (m.len() - 4) as u32;
        m[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        flight.extend_from_slice(&wr.seal(0x16, &m));
        transcript.extend_from_slice(&m);
    }
    let c_finished_key = h.expand_label(&c_hs, "finished", &[], h.len());
    let verify = h.hmac(&c_finished_key, &h.hash(&transcript));
    let mut fin = vec![20u8, 0, 0, verify.len() as u8];
    fin.extend_from_slice(&verify);
    flight.extend_from_slice(&wr.seal(0x16, &fin));
    io.write_all(&flight).await?;
    io.flush().await?;

    Ok(TlsStream {
        io,
        rd: Cipher::new(sh.suite, &s_ap),
        wr: Cipher::new(sh.suite, &c_ap),
        raw: std::mem::take(&mut reader.raw),
        plain: Vec::new(),
        plain_pos: 0,
        out: Vec::new(),
        out_pos: 0,
        eof: false,
        closed: false,
        alpn,
        read_direct: false,
        write_direct: false,
        post: Vec::new(),
    })
}

/// An established TLS 1.3 connection.
pub struct TlsStream<S> {
    io: S,
    rd: Cipher,
    wr: Cipher,
    /// Bytes from the socket not yet consumed as records.
    raw: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
    /// Encrypted bytes waiting to go out.
    out: Vec<u8>,
    out_pos: usize,
    eof: bool,
    closed: bool,
    pub alpn: Option<String>,
    read_direct: bool,
    write_direct: bool,
    /// Post-handshake handshake messages (tickets, KeyUpdate) in progress.
    post: Vec<u8>,
}

impl<S> TlsStream<S> {
    /// From now on reads return raw socket bytes (after what was already
    /// decrypted, and bytes received but not yet decrypted).
    pub fn set_read_direct(&mut self) {
        self.read_direct = true;
    }
    /// From now on writes bypass TLS (pending records go out first).
    pub fn set_write_direct(&mut self) {
        self.write_direct = true;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    fn handle_post_handshake(&mut self) -> io::Result<()> {
        let mut m = Messages { buf: std::mem::take(&mut self.post) };
        while let Some((ty, msg)) = m.pop() {
            if ty == 24 {
                // KeyUpdate: their key moves on; answer if asked.
                self.rd.update();
                if msg.get(4) == Some(&1) {
                    let rec = self.wr.seal(0x16, &[24, 0, 0, 1, 0]);
                    self.out.extend_from_slice(&rec);
                    self.wr.update();
                }
            }
            // NewSessionTicket (4) and others: nothing to do.
        }
        self.post = m.buf;
        Ok(())
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                if this.plain_pos == this.plain.len() {
                    this.plain.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_direct {
                if !this.raw.is_empty() {
                    let n = this.raw.len().min(buf.remaining());
                    buf.put_slice(&this.raw[..n]);
                    this.raw.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            // A whole record buffered?
            if this.raw.len() >= 5 {
                let len = u16::from_be_bytes([this.raw[3], this.raw[4]]) as usize;
                if len > MAX_RECORD + 256 {
                    return Poll::Ready(Err(invalid("TLS record too large")));
                }
                if this.raw.len() >= 5 + len {
                    let hdr: [u8; 5] = this.raw[..5].try_into().unwrap();
                    let body: Vec<u8> = this.raw[5..5 + len].to_vec();
                    this.raw.drain(..5 + len);
                    match hdr[0] {
                        0x17 => {
                            let (ty, data) = this.rd.open(&hdr, &body).ok_or_else(|| invalid("TLS record authentication failed"))?;
                            match ty {
                                0x17 => {
                                    this.plain = data;
                                    this.plain_pos = 0;
                                }
                                0x16 => {
                                    this.post.extend_from_slice(&data);
                                    this.handle_post_handshake()?;
                                }
                                0x15 => {
                                    if data.get(1) == Some(&0) {
                                        this.eof = true;
                                    } else {
                                        return Poll::Ready(Err(alert_error(*data.get(1).unwrap_or(&0))));
                                    }
                                }
                                _ => return Poll::Ready(Err(invalid("unexpected TLS content type"))),
                            }
                        }
                        0x14 => {}
                        0x15 => {
                            this.eof = true;
                        }
                        _ => return Poll::Ready(Err(invalid("unexpected TLS record"))),
                    }
                    continue;
                }
            }
            let mut tmp = [0u8; 16 * 1024 + 512];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                // EOF without close_notify: treat as end of stream.
                this.eof = true;
                return Poll::Ready(Ok(()));
            }
            this.raw.extend_from_slice(rb.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        if this.write_direct {
            return Pin::new(&mut this.io).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_RECORD);
        let rec = this.wr.seal(0x17, &data[..n]);
        this.out = rec;
        this.out_pos = 0;
        // The record is ours to send now; a pending socket just means later.
        if let Poll::Ready(Err(e)) = this.poll_flush_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        if !this.closed && !this.write_direct {
            this.closed = true;
            this.out = this.wr.seal(0x15, &[1, 0]);
            this.out_pos = 0;
            ready!(this.poll_flush_out(cx))?;
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_keys_parse() {
        let r = Reality::parse("Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "6ba85179e30d4fc2").unwrap();
        assert_eq!(r.short_id, [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]);
        assert_eq!(Reality::parse("Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "ab").unwrap().short_id, [0xab, 0, 0, 0, 0, 0, 0, 0]);
        assert!(Reality::parse("short", "").is_none());
        assert!(Reality::parse("Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "abc").is_none());
    }
}
