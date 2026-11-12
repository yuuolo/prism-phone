use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Pre-built TLS client settings for one outbound. With a
/// `client-fingerprint` the handshake looks like Chrome's (see `ctls`);
/// servers that only speak TLS 1.2 get rustls instead.
#[derive(Clone)]
pub struct Tls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    chrome: Option<super::ctls::Config>,
    /// The server answered the Chrome hello with TLS 1.2 once.
    tls12_only: Arc<AtomicBool>,
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS 1.3 rustls client config (QUIC needs 1.3), with the bundled
/// roots or no verification.
pub fn tls13_config(skip_verify: bool, alpn: &[String]) -> io::Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| crate::common::other(e.to_string()))?;
    let mut cfg = if skip_verify {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider()))).with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(cfg)
}

impl Tls {
    pub fn new(server_name: &str, skip_verify: bool, alpn: &[String], fingerprint: Option<&str>) -> io::Result<Self> {
        let chrome = fingerprint.filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("none")).map(|_| super::ctls::Config {
            server_name: server_name.to_string(),
            // Chrome offers h2 and http/1.1 unless told otherwise.
            alpn: if alpn.is_empty() { vec!["h2".into(), "http/1.1".into()] } else { alpn.to_vec() },
            skip_verify,
            reality: None,
        });
        let builder = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::common::other(e.to_string()))?;
        let mut cfg = if skip_verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider())))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| crate::common::invalid(format!("bad TLS server name {server_name}")))?;
        Ok(Tls { connector: TlsConnector::from(Arc::new(cfg)), server_name, chrome, tls12_only: Default::default() })
    }

    /// Dials `host:port` and completes the TLS handshake.
    pub async fn connect(&self, dialer: &super::Dialer, host: &str, port: u16) -> io::Result<crate::common::BoxedStream> {
        let tcp = dialer.tcp(host, port).await?;
        if let Some(cfg) = self.chrome.as_ref().filter(|_| !self.tls12_only.load(Ordering::Relaxed)) {
            match super::ctls::connect(tcp, cfg).await {
                Ok(s) => return Ok(Box::new(s)),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                    tracing::info!("{host}:{port} only speaks TLS 1.2; using the default TLS client");
                    self.tls12_only.store(true, Ordering::Relaxed);
                    let tcp = dialer.tcp(host, port).await?;
                    return Ok(Box::new(self.wrap(tcp).await?));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Box::new(self.wrap(tcp).await?))
    }

    pub async fn wrap<S: AsyncRead + AsyncWrite + Unpin>(&self, s: S) -> io::Result<TlsStream<S>> {
        self.connector.connect(self.server_name.clone(), s).await
    }
}
