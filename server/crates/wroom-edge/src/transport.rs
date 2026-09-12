//! One browser peer connection's protocol stack: ICE-lite + DTLS + SRTP.
//!
//! `PeerTransport` is a Sans-IO state machine like the modules it
//! composes: the runtime feeds it datagrams and drains events; media is
//! decrypted in place inside the caller's buffer. It performs no IO,
//! takes no locks, and allocates only on the handshake path.

use std::net::SocketAddr;
use std::time::Instant;

use rand::Rng;
use rand::distr::Alphanumeric;

use crate::dtls::{DtlsIdentity, DtlsTransport, Output as DtlsOutput};
use crate::ice::{IceEvent, IceLiteAgent, MAX_RESPONSE_LEN, is_stun_datagram};
use crate::srtp::{Srtp, SrtpError};

/// What [`PeerTransport::handle_datagram`] and friends yield.
#[derive(Debug)]
pub enum PeerEvent {
    /// Emit this datagram to `to`. Handshake/control traffic only —
    /// media egress goes through [`PeerTransport::protect_rtp`].
    Send { to: SocketAddr, data: Vec<u8> },
    /// The peer nominated this remote address (ICE USE-CANDIDATE).
    Nominated(SocketAddr),
    /// DTLS connected, fingerprint verified, SRTP installed. Media may
    /// now flow in both directions.
    Connected,
    /// Inbound media was decrypted in place: the caller's buffer holds
    /// plaintext RTP (or RTCP) in `buf[..len]`.
    Media { len: usize, rtcp: bool },
    /// Fatal failure (e.g. DTLS fingerprint mismatch). Tear down.
    Failed(&'static str),
    /// DTLS close_notify.
    Closed,
}

/// The peer's role in DTLS-SRTP key export decides which half of the
/// keying material protects which direction. We are the DTLS server, so
/// rx is the client half — baked into `Srtp::from_keying_material`.
pub struct PeerTransport {
    ice: IceLiteAgent,
    /// Our local ICE password (the agent keeps it private).
    local_pwd: String,
    dtls: DtlsTransport,
    srtp: Option<Srtp>,
    /// Nominated remote address, once ICE selects a pair.
    nominated: Option<SocketAddr>,
    /// The sha-256 fingerprint the offer advertised — the peer cert must
    /// match it once the handshake completes.
    expected_fingerprint: Option<String>,
    connected: bool,
    /// Pending DTLS timer deadline, last reported by the engine.
    dtls_deadline: Option<Instant>,
}

fn gen_token(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

impl PeerTransport {
    /// A fresh transport in the DTLS-server role with fresh ICE
    /// credentials. `remote_ufrag`/`expected_fingerprint` come from the
    /// peer's SDP offer when already known (subscriber leg: known at
    /// answer time).
    pub fn new(
        identity: &DtlsIdentity,
        now: Instant,
        remote_ufrag: Option<&str>,
        expected_fingerprint: Option<String>,
    ) -> Self {
        // RFC 8445 §5.4/§15: ufrag ≥ 24 bits, pwd ≥ 128 bits of entropy.
        // 8/24 alphanumeric chars comfortably exceed both.
        let local_ufrag = gen_token(8);
        let local_pwd = gen_token(24);
        Self {
            ice: IceLiteAgent::new(&local_ufrag, &local_pwd, remote_ufrag),
            local_pwd,
            dtls: DtlsTransport::new(identity, now),
            srtp: None,
            nominated: None,
            expected_fingerprint,
            connected: false,
            dtls_deadline: None,
        }
    }

    /// Our ICE username fragment — goes into the SDP answer/offer.
    pub fn local_ufrag(&self) -> &str {
        self.ice.local_ufrag()
    }

    /// Our ICE password — goes into the SDP answer/offer.
    pub fn local_pwd(&self) -> &str {
        &self.local_pwd
    }

    /// The nominated remote address, if ICE has selected a pair.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.nominated
    }

    /// True once DTLS connected and SRTP is installed.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Record the remote ufrag once known (answer on the offerer leg).
    pub fn set_remote_ufrag(&mut self, ufrag: &str) {
        self.ice.set_remote_ufrag(ufrag);
    }

    /// Record the fingerprint the peer's SDP advertised — checked when
    /// the DTLS handshake completes (subscriber leg learns it late).
    pub fn set_expected_fingerprint(&mut self, fingerprint: String) {
        self.expected_fingerprint = Some(fingerprint);
    }

    /// Feed one received UDP datagram. `buf` is mutable so SRTP media is
    /// decrypted in place — on [`PeerEvent::Media`], `buf[..len]` is
    /// plaintext.
    pub fn handle_datagram(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        now: Instant,
    ) -> Vec<PeerEvent> {
        let mut events = Vec::new();
        if is_stun_datagram(buf) {
            let mut resp = [0u8; MAX_RESPONSE_LEN];
            let out = self.ice.handle_datagram(buf, from, now, &mut resp);
            if let Some(n) = out.response {
                events.push(PeerEvent::Send {
                    to: from,
                    data: resp[..n].to_vec(),
                });
            }
            if let Some(IceEvent::Nominated(addr)) = out.event {
                self.nominated = Some(addr);
                events.push(PeerEvent::Nominated(addr));
            }
            return events;
        }

        match buf[0] {
            // RFC 7983: DTLS records begin 20..=63.
            20..=63 => {
                if let Err(e) = self.dtls.handle_packet(buf, now) {
                    tracing::debug!(error = %e, "dtls input error");
                    return events;
                }
                self.drain_dtls(&mut events);
            }
            // RTP/RTCP share 128..=191; RTCP is told apart by its packet
            // type field (RFC 5761 §8): 192..=223 on the wire is RTCP.
            128..=255 => {
                if let Some(srtp) = self.srtp.as_mut() {
                    let rtcp = (192..=223).contains(&buf[1]);
                    let res = if rtcp {
                        srtp.decrypt_rtcp(buf)
                    } else {
                        srtp.decrypt_rtp(buf)
                    };
                    match res {
                        Ok(len) => events.push(PeerEvent::Media { len, rtcp }),
                        Err(SrtpError::AuthFailed) | Err(SrtpError::Replayed) => {}
                        Err(_) => {}
                    }
                }
            }
            _ => {}
        }
        events
    }

    fn drain_dtls(&mut self, events: &mut Vec<PeerEvent>) {
        while let Some(out) = self.dtls.poll_output() {
            match out {
                DtlsOutput::Packet(data) => {
                    if let Some(to) = self.nominated {
                        events.push(PeerEvent::Send { to, data });
                    }
                }
                DtlsOutput::Timeout(t) => self.dtls_deadline = Some(t),
                DtlsOutput::PeerCert(_) => {}
                DtlsOutput::KeyingMaterial { material, profile } => {
                    match Srtp::from_keying_material(profile, &material) {
                        Ok(srtp) => self.srtp = Some(srtp),
                        Err(_) => events.push(PeerEvent::Failed("srtp key install")),
                    }
                }
                DtlsOutput::Connected => {
                    let ok = match (&self.expected_fingerprint, self.dtls.peer_fingerprint_sha256()) {
                        (Some(expected), Some(actual)) => actual.eq_ignore_ascii_case(expected),
                        (None, _) => true,
                        (Some(_), None) => false,
                    };
                    if ok {
                        self.connected = true;
                        events.push(PeerEvent::Connected);
                    } else {
                        events.push(PeerEvent::Failed("dtls fingerprint mismatch"));
                    }
                }
                DtlsOutput::ApplicationData(_) => {}
                DtlsOutput::Closed => events.push(PeerEvent::Closed),
            }
        }
    }

    /// Protect one plaintext RTP packet for this peer: copies `plain`
    /// into `out` and encrypts in place. `out` needs `plain.len() + 16`
    /// spare. Returns the nominated remote and wire length.
    pub fn protect_rtp(&mut self, plain: &[u8], out: &mut [u8]) -> Option<(SocketAddr, usize)> {
        let to = self.nominated?;
        let srtp = self.srtp.as_mut()?;
        out[..plain.len()].copy_from_slice(plain);
        srtp.encrypt_rtp(out, plain.len()).ok().map(|n| (to, n))
    }

    /// Same for RTCP (+20 byte trailer).
    pub fn protect_rtcp(&mut self, plain: &[u8], out: &mut [u8]) -> Option<(SocketAddr, usize)> {
        let to = self.nominated?;
        let srtp = self.srtp.as_mut()?;
        out[..plain.len()].copy_from_slice(plain);
        srtp.encrypt_rtcp(out, plain.len()).ok().map(|n| (to, n))
    }

    /// Next deadline the runtime must honour (ICE pair expiry, DTLS
    /// flight retransmit).
    pub fn poll_timeout(&self) -> Option<Instant> {
        [self.ice.poll_timeout(), self.dtls_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    /// Advance timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<PeerEvent> {
        self.ice.handle_timeout(now);
        if self.dtls_deadline.is_some_and(|d| now >= d) {
            self.dtls_deadline = None;
            let _ = self.dtls.handle_timeout(now);
        }
        let mut events = Vec::new();
        self.drain_dtls(&mut events);
        events
    }
}
