//! XTLS Vision (`flow: xtls-rprx-vision`) on top of a VLESS connection over
//! TLS / REALITY, following Xray-core's proxy.go:
//!
//! - The first packets each way are padded: `[uuid once] cmd len(2)
//!   padlen(2) content padding`, cmd 0 = more padding, 1 = padding ends,
//!   2 = padding ends and the sender switches to direct copy.
//! - Both directions watch the inner TLS handshake; once the inner TLS 1.3
//!   connection carries application data, a direction may stop wrapping it
//!   in the outer TLS and copy raw bytes instead ("direct").

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ctls::TlsStream;

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;
/// Xray's buffer size; a padded block never exceeds it.
const BUF_SIZE: usize = 8192;

/// What Vision learned about the inner traffic (Xray's TrafficState).
#[derive(Debug)]
pub struct Traffic {
    pub packets_to_filter: i32,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub enable_xtls: bool,
    remaining_server_hello: i32,
    cipher: u16,
}

impl Default for Traffic {
    fn default() -> Self {
        Traffic { packets_to_filter: 8, is_tls: false, is_tls12_or_above: false, enable_xtls: false, remaining_server_hello: -1, cipher: 0 }
    }
}

impl Traffic {
    /// Xray's XtlsFilterTls over one buffer.
    pub fn filter(&mut self, b: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == [0x16, 0x03, 0x03] && b[5] == 0x02 {
                self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid = b[43] as usize;
                    if b.len() >= 43 + sid + 3 {
                        self.cipher = u16::from_be_bytes([b[43 + sid + 1], b[43 + sid + 2]]);
                    }
                }
            } else if b[..2] == [0x16, 0x03] && b[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if b[..end].windows(6).any(|w| w == [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]) {
                // Inner TLS 1.3: direct copy is safe unless the cipher is CCM_8.
                if matches!(self.cipher, 0x1301..=0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

/// A buffer made only of whole TLS application-data records.
fn complete_app_records(mut b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    while !b.is_empty() {
        if b.len() < 5 || b[..3] != [0x17, 0x03, 0x03] {
            return false;
        }
        let len = u16::from_be_bytes([b[3], b[4]]) as usize;
        if b.len() < 5 + len {
            return false;
        }
        b = &b[5 + len..];
    }
    true
}

/// Xray's XtlsPadding.
pub fn pad(content: &[u8], cmd: u8, uuid: Option<&[u8; 16]>, long: bool, rng: &mut impl RngCore) -> Vec<u8> {
    let len = content.len();
    let mut padding = if len < 900 && long { rng.gen_range(0..500) + 900 - len } else { rng.gen_range(0..256) };
    padding = padding.min(BUF_SIZE.saturating_sub(21 + len));
    let mut out = Vec::with_capacity(21 + len + padding);
    if let Some(u) = uuid {
        out.extend_from_slice(u);
    }
    out.extend_from_slice(&[cmd, (len >> 8) as u8, len as u8, (padding >> 8) as u8, padding as u8]);
    out.extend_from_slice(content);
    let start = out.len();
    out.resize(start + padding, 0);
    rng.fill_bytes(&mut out[start..]);
    out
}

/// Xray's XtlsUnpadding state machine (persists across reads).
pub struct Unpad {
    uuid: [u8; 16],
    /// Start of the stream, held until it's clear whether it is padded.
    head: Vec<u8>,
    rem_cmd: i32,
    rem_content: i32,
    rem_padding: i32,
    pub current: i32,
}

impl Unpad {
    pub fn new(uuid: [u8; 16]) -> Self {
        Unpad { uuid, head: Vec::new(), rem_cmd: -1, rem_content: -1, rem_padding: -1, current: 0 }
    }

    pub fn feed(&mut self, b: &[u8], out: &mut Vec<u8>) {
        let joined;
        let mut b = b;
        if !self.head.is_empty() {
            self.head.extend_from_slice(b);
            joined = std::mem::take(&mut self.head);
            b = &joined;
        }
        if self.rem_cmd == -1 && self.rem_content == -1 && self.rem_padding == -1 {
            // A padded block starts with our uuid; wait for enough bytes to tell.
            let n = b.len().min(16);
            if b.len() < 21 && b[..n] == self.uuid[..n] {
                self.head = b.to_vec();
                return;
            }
            if b.len() >= 21 && b[..16] == self.uuid {
                b = &b[16..];
                self.rem_cmd = 5;
            } else {
                out.extend_from_slice(b);
                return;
            }
        }
        while !b.is_empty() {
            if self.rem_cmd > 0 {
                let d = b[0] as i32;
                b = &b[1..];
                match self.rem_cmd {
                    5 => self.current = d,
                    4 => self.rem_content = d << 8,
                    3 => self.rem_content |= d,
                    2 => self.rem_padding = d << 8,
                    1 => self.rem_padding |= d,
                    _ => {}
                }
                self.rem_cmd -= 1;
            } else if self.rem_content > 0 {
                let n = (self.rem_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.rem_content -= n as i32;
            } else {
                let n = (self.rem_padding.max(0) as usize).min(b.len());
                b = &b[n..];
                self.rem_padding -= n as i32;
            }
            if self.rem_cmd <= 0 && self.rem_content <= 0 && self.rem_padding <= 0 {
                if self.current == 0 {
                    self.rem_cmd = 5;
                } else {
                    self.rem_cmd = -1;
                    self.rem_content = -1;
                    self.rem_padding = -1;
                    out.extend_from_slice(b);
                    break;
                }
            }
        }
    }

    /// Still inside padded blocks after this buffer.
    fn within(&self) -> bool {
        self.rem_content > 0 || self.rem_padding > 0 || self.current == 0
    }
}

/// A VLESS + Vision connection: reads skip the VLESS response header and
/// unpad; writes pad; either side may switch to direct copy.
pub struct VisionStream<S> {
    inner: TlsStream<S>,
    uuid: [u8; 16],
    traffic: Traffic,
    // write side
    padding: bool,
    uuid_sent: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    pending_len: usize,
    switch_write_direct: bool,
    // read side
    header_left: Option<usize>,
    header_buf: Vec<u8>,
    unpad: Unpad,
    within_padding: bool,
    ready: Vec<u8>,
    ready_pos: usize,
    rng: rand::rngs::StdRng,
}

impl<S> VisionStream<S> {
    pub fn new(inner: TlsStream<S>, uuid: [u8; 16]) -> Self {
        use rand::SeedableRng;
        VisionStream {
            inner,
            uuid,
            traffic: Traffic::default(),
            padding: true,
            uuid_sent: false,
            pending: Vec::new(),
            pending_pos: 0,
            pending_len: 0,
            switch_write_direct: false,
            header_left: None,
            header_buf: Vec::new(),
            unpad: Unpad::new(uuid),
            within_padding: true,
            ready: Vec::new(),
            ready_pos: 0,
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.ready_pos < this.ready.len() {
                let n = (this.ready.len() - this.ready_pos).min(buf.remaining());
                buf.put_slice(&this.ready[this.ready_pos..this.ready_pos + n]);
                this.ready_pos += n;
                return Poll::Ready(Ok(()));
            }
            this.ready.clear();
            this.ready_pos = 0;
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let data = rb.filled();
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            // VLESS response header: version, addons length, addons.
            if this.header_left != Some(0) {
                this.header_buf.extend_from_slice(data);
                if this.header_buf.len() < 2 {
                    continue;
                }
                let need = 2 + this.header_buf[1] as usize;
                if this.header_buf.len() < need {
                    continue;
                }
                this.header_left = Some(0);
                let rest = this.header_buf.split_off(need);
                this.header_buf.clear();
                if !rest.is_empty() {
                    this.process_incoming(&rest);
                }
                continue;
            }
            let owned = data.to_vec();
            this.process_incoming(&owned);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
    /// The VLESS request header goes out unpadded, before any payload.
    pub async fn write_header(&mut self, h: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.inner.write_all(h).await?;
        self.inner.flush().await
    }
}

impl<S> VisionStream<S> {
    fn process_incoming(&mut self, data: &[u8]) {
        let mut out = Vec::with_capacity(data.len());
        if self.within_padding || self.traffic.packets_to_filter > 0 {
            self.unpad.feed(data, &mut out);
            if self.unpad.within() {
                self.within_padding = true;
            } else if self.unpad.current == CMD_END as i32 {
                self.within_padding = false;
            } else if self.unpad.current == CMD_DIRECT as i32 {
                self.within_padding = false;
                // The server sends raw bytes from here on.
                tracing::debug!("vision: server switched to direct copy");
                self.inner.set_read_direct();
            }
        } else {
            out.extend_from_slice(data);
        }
        if self.traffic.packets_to_filter > 0 {
            self.traffic.filter(&out);
        }
        self.ready.extend_from_slice(&out);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Finish a padded block first; it stands for `pending_len` bytes.
        if this.pending_pos < this.pending.len() {
            while this.pending_pos < this.pending.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_pos..]))?;
                this.pending_pos += n;
            }
            ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
            if this.switch_write_direct {
                this.switch_write_direct = false;
                tracing::debug!("vision: switched to direct copy");
                this.inner.set_write_direct();
            }
            let n = this.pending_len;
            this.pending.clear();
            this.pending_pos = 0;
            return Poll::Ready(Ok(n));
        }
        if !this.padding {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        let chunk = &data[..data.len().min(BUF_SIZE - 21 - 16)];
        if this.traffic.packets_to_filter > 0 {
            this.traffic.filter(chunk);
        }
        let mut long = this.traffic.is_tls;
        let cmd = if this.traffic.is_tls && chunk.len() >= 6 && complete_app_records(chunk) {
            this.padding = false;
            long = true;
            if this.traffic.enable_xtls {
                this.switch_write_direct = true;
                CMD_DIRECT
            } else {
                CMD_END
            }
        } else if !this.traffic.is_tls12_or_above && this.traffic.packets_to_filter <= 1 {
            this.padding = false;
            CMD_END
        } else {
            CMD_CONTINUE
        };
        let uuid = (!this.uuid_sent).then_some(&this.uuid);
        this.uuid_sent = true;
        this.pending = pad(chunk, cmd, uuid, long, &mut this.rng);
        this.pending_pos = 0;
        this.pending_len = chunk.len();
        // Drive it out now; report the bytes once the block is written.
        self.poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_round_trip() {
        let uuid = [7u8; 16];
        let mut rng = rand::thread_rng();
        let mut wire = pad(b"hello", CMD_CONTINUE, Some(&uuid), true, &mut rng);
        assert!(wire.len() >= 16 + 5 + 5 + 400, "long padding for short TLS content");
        wire.extend(pad(b" world", CMD_END, None, false, &mut rng));
        wire.extend_from_slice(b" and raw");
        // Feed in awkward pieces.
        let mut u = Unpad::new(uuid);
        let mut out = Vec::new();
        for piece in wire.chunks(7) {
            u.feed(piece, &mut out);
        }
        assert_eq!(out, b"hello world and raw");
        assert_eq!(u.current, CMD_END as i32);
        assert!(!u.within());
        // Data without the uuid prefix isn't padded.
        let mut plain = Vec::new();
        Unpad::new(uuid).feed(b"not padded at all, longer than 21 bytes", &mut plain);
        assert_eq!(plain, b"not padded at all, longer than 21 bytes");
    }

    #[test]
    fn filter_sees_inner_tls13() {
        let mut t = Traffic::default();
        t.filter(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0, 0]); // ClientHello
        assert!(t.is_tls && !t.is_tls12_or_above);
        // ServerHello with supported_versions = TLS 1.3, cipher 0x1301.
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0, 0, 0x76, 0x03, 0x03];
        sh.extend_from_slice(&[0u8; 32]);
        sh.push(32);
        sh.extend_from_slice(&[0u8; 32]);
        sh.extend_from_slice(&[0x13, 0x01, 0x00]);
        sh.extend_from_slice(&[0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        sh.resize(127, 0);
        t.filter(&sh);
        assert!(t.is_tls12_or_above && t.enable_xtls && t.packets_to_filter == 0);
        assert!(complete_app_records(&[0x17, 0x03, 0x03, 0x00, 0x02, 1, 2, 0x17, 0x03, 0x03, 0x00, 0x00]));
        assert!(!complete_app_records(&[0x17, 0x03, 0x03, 0x00, 0x05, 1]));
    }
}
