//! Server authentication: WebPKI chain + name (webpki-roots), the TLS 1.3
//! CertificateVerify signature, and REALITY's HMAC-signed certificate.

use std::io;

use rustls::pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};

use crate::common::{invalid, other};

/// Content signed by the server in CertificateVerify (RFC 8446 §4.4.3).
pub fn verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    m.extend_from_slice(transcript_hash);
    m
}

fn scheme_alg(scheme: u16) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    use webpki::ring as alg;
    Some(match scheme {
        0x0403 => alg::ECDSA_P256_SHA256,
        0x0503 => alg::ECDSA_P384_SHA384,
        0x0804 => alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => alg::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => alg::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => alg::ED25519,
        _ => return None,
    })
}

/// Checks the chain against the bundled roots and the name, then the
/// CertificateVerify signature over the transcript.
pub fn verify_webpki(chain: &[Vec<u8>], name: &str, scheme: u16, sig: &[u8], transcript_hash: &[u8], skip_chain: bool) -> io::Result<()> {
    let leaf = chain.first().ok_or_else(|| invalid("server sent no certificate"))?;
    let der = CertificateDer::from(leaf.as_slice());
    let ee = webpki::EndEntityCert::try_from(&der).map_err(|e| invalid(format!("bad server certificate: {e:?}")))?;
    if !skip_chain {
        let anchors = webpki_roots::TLS_SERVER_ROOTS;
        let inter: Vec<CertificateDer> = chain[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
        ee.verify_for_usage(webpki::ALL_VERIFICATION_ALGS, anchors, &inter, UnixTime::now(), webpki::KeyUsage::server_auth(), None, None)
            .map_err(|e| invalid(format!("server certificate not trusted: {e:?}")))?;
        let sn = ServerName::try_from(name).map_err(|_| invalid(format!("bad server name {name}")))?;
        ee.verify_is_valid_for_subject_name(&sn).map_err(|e| invalid(format!("certificate not valid for {name}: {e:?}")))?;
    }
    let alg = scheme_alg(scheme).ok_or_else(|| invalid(format!("unsupported signature scheme {scheme:#06x}")))?;
    ee.verify_signature(alg, &verify_content(transcript_hash), sig)
        .map_err(|e| invalid(format!("bad CertificateVerify signature: {e:?}")))
}

// ------------------------------------------------------------- tiny DER

/// (tag, content, rest)
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 3 || input.len() < 2 + n {
            return None;
        }
        (input[2..2 + n].iter().fold(0usize, |a, b| (a << 8) | *b as usize), 2 + n)
    };
    if input.len() < hdr + len {
        return None;
    }
    Some((tag, &input[hdr..hdr + len], &input[hdr + len..]))
}

/// (Ed25519 public key, signature value) of a certificate, if its key is Ed25519.
pub fn ed25519_parts(cert: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let (_, outer, _) = der(cert)?;
    let (_, tbs, rest) = der(outer)?;
    let (_, _alg, rest) = der(rest)?;
    let (tag, sig, _) = der(rest)?;
    if tag != 0x03 || sig.first() != Some(&0) {
        return None;
    }
    // SubjectPublicKeyInfo: SEQ { SEQ { OID 1.3.101.112 }, BIT STRING 00 || key }
    const SPKI: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let at = tbs.windows(SPKI.len()).position(|w| w == SPKI)?;
    let key: [u8; 32] = tbs.get(at + SPKI.len()..at + SPKI.len() + 32)?.try_into().ok()?;
    Some((key, sig[1..].to_vec()))
}

/// REALITY: the server proves it knows the shared auth key by signing its
/// temporary Ed25519 certificate with HMAC-SHA512(auth_key, public key).
pub fn verify_reality(chain: &[Vec<u8>], auth_key: &[u8], scheme: u16, sig: &[u8], transcript_hash: &[u8]) -> io::Result<()> {
    use hmac::{Hmac, Mac};
    let leaf = chain.first().ok_or_else(|| invalid("server sent no certificate"))?;
    let (key, cert_sig) = ed25519_parts(leaf).ok_or_else(|| other("REALITY: server certificate isn't REALITY's (wrong public key or short id?)"))?;
    let mut m = <Hmac<sha2::Sha512> as Mac>::new_from_slice(auth_key).unwrap();
    m.update(&key);
    if m.finalize().into_bytes().as_slice() != cert_sig.as_slice() {
        return Err(other("REALITY: authentication failed (check public-key and short-id)"));
    }
    if scheme != 0x0807 {
        return Err(invalid("REALITY: unexpected signature scheme"));
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&verify_content(transcript_hash), sig)
        .map_err(|_| invalid("REALITY: bad CertificateVerify signature"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_reads_ed25519_certificate() {
        // A minimal certificate-shaped structure with an Ed25519 SPKI.
        let key = [9u8; 32];
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        spki.extend_from_slice(&key);
        let mut tbs = vec![0x30, spki.len() as u8];
        tbs.extend_from_slice(&spki);
        let alg = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let sigval = [5u8; 64];
        let mut bits = vec![0x03, 65, 0];
        bits.extend_from_slice(&sigval);
        let body: Vec<u8> = [tbs.as_slice(), &alg, &bits].concat();
        let mut cert = vec![0x30, 0x81, body.len() as u8];
        cert.extend_from_slice(&body);
        assert_eq!(ed25519_parts(&cert), Some((key, sigval.to_vec())));
        assert_eq!(ed25519_parts(&cert[..20]), None);
    }
}
