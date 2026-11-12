//! TLS 1.3 key schedule (RFC 8446 §7) and record protection.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

impl Suite {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Suite::Aes128Gcm),
            0x1302 => Some(Suite::Aes256Gcm),
            0x1303 => Some(Suite::Chacha20),
            _ => None,
        }
    }
    pub fn hash(self) -> HashAlg {
        if self == Suite::Aes256Gcm {
            HashAlg::Sha384
        } else {
            HashAlg::Sha256
        }
    }
    fn key_len(self) -> usize {
        if self == Suite::Aes128Gcm {
            16
        } else {
            32
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashAlg::Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let zeros = vec![0u8; self.len()];
        self.hmac(if salt.is_empty() { &zeros } else { salt }, ikm)
    }
    fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut t: Vec<u8> = Vec::new();
        let mut i = 1u8;
        while out.len() < len {
            let mut input = t.clone();
            input.extend_from_slice(info);
            input.push(i);
            t = self.hmac(prk, &input);
            out.extend_from_slice(&t);
            i += 1;
        }
        out.truncate(len);
        out
    }
    pub fn expand_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let full = format!("tls13 {label}");
        let mut info = Vec::with_capacity(4 + full.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(secret, &info, len)
    }
    pub fn derive_secret(self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.len())
    }
}

/// One direction's record protection.
pub struct Cipher {
    suite: Suite,
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Cipher {
    pub fn new(suite: Suite, secret: &[u8]) -> Self {
        let h = suite.hash();
        let key = h.expand_label(secret, "key", &[], suite.key_len());
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&h.expand_label(secret, "iv", &[], 12));
        Cipher { suite, secret: secret.to_vec(), key, iv, seq: 0 }
    }

    /// KeyUpdate: next generation of this direction's secret.
    pub fn update(&mut self) {
        let next = self.suite.hash().expand_label(&self.secret, "traffic upd", &[], self.suite.hash().len());
        *self = Cipher::new(self.suite, &next);
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// Protects one record: `content || type`, returns the full record.
    pub fn seal(&mut self, content_type: u8, content: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(content.len() + 1 + 16 + 5);
        buf.extend_from_slice(content);
        buf.push(content_type);
        let len = (buf.len() + 16) as u16;
        let aad = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let nonce = self.nonce();
        let tag = match self.suite {
            Suite::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(&self.key).unwrap().encrypt_in_place_detached(&nonce.into(), &aad, &mut buf),
            Suite::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(&self.key).unwrap().encrypt_in_place_detached(&nonce.into(), &aad, &mut buf),
            Suite::Chacha20 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                .unwrap()
                .encrypt_in_place_detached(&nonce.into(), &aad, &mut buf),
        }
        .expect("seal");
        self.seq += 1;
        let mut rec = aad.to_vec();
        rec.extend_from_slice(&buf);
        rec.extend_from_slice(&tag);
        rec
    }

    /// Unprotects a record body; returns (content type, content).
    pub fn open(&mut self, header: &[u8; 5], body: &[u8]) -> Option<(u8, Vec<u8>)> {
        if body.len() < 17 {
            return None;
        }
        let (ct, tag) = body.split_at(body.len() - 16);
        let mut buf = ct.to_vec();
        let nonce = self.nonce();
        let ok = match self.suite {
            Suite::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(&self.key).unwrap().decrypt_in_place_detached(&nonce.into(), header, &mut buf, tag.into()),
            Suite::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(&self.key).unwrap().decrypt_in_place_detached(&nonce.into(), header, &mut buf, tag.into()),
            Suite::Chacha20 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                .unwrap()
                .decrypt_in_place_detached(&nonce.into(), header, &mut buf, tag.into()),
        };
        ok.ok()?;
        self.seq += 1;
        // Strip zero padding; the last non-zero byte is the real type.
        let pos = buf.iter().rposition(|&b| b != 0)?;
        let ty = buf[pos];
        buf.truncate(pos);
        Some((ty, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 8448 §3 (simple 1-RTT handshake) key schedule values.
    #[test]
    fn rfc8448_schedule() {
        let h = HashAlg::Sha256;
        let early = h.extract(&[], &[0u8; 32]);
        assert_eq!(early, hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
        let derived = h.derive_secret(&early, "derived", &h.hash(&[]));
        assert_eq!(derived, hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
        let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let hs = h.extract(&derived, &shared);
        assert_eq!(hs, hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"));
        // Transcript hash of ClientHello..ServerHello from the RFC.
        let th = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let c_hs = h.derive_secret(&hs, "c hs traffic", &th);
        assert_eq!(c_hs, hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
        let s_hs = h.derive_secret(&hs, "s hs traffic", &th);
        assert_eq!(s_hs, hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"));
        let c = Cipher::new(Suite::Aes128Gcm, &s_hs);
        assert_eq!(c.key, hex("3fce516009c21727d0f2e4e86ee403bc"));
        assert_eq!(c.iv.to_vec(), hex("5d313eb2671276ee13000b30"));
    }

    #[test]
    fn seal_open_round_trip() {
        for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::Chacha20] {
            let secret = vec![7u8; suite.hash().len()];
            let (mut a, mut b) = (Cipher::new(suite, &secret), Cipher::new(suite, &secret));
            for msg in [&b"hello"[..], &[0u8; 3000][..]] {
                let rec = a.seal(0x17, msg);
                let hdr: [u8; 5] = rec[..5].try_into().unwrap();
                assert_eq!(b.open(&hdr, &rec[5..]), Some((0x17, msg.to_vec())));
            }
            let mut rec = a.seal(0x17, b"x");
            rec[7] ^= 1;
            let hdr: [u8; 5] = rec[..5].try_into().unwrap();
            assert_eq!(b.open(&hdr, &rec[5..]), None, "tampered record must fail");
        }
    }
}
