//! DTLS transport security for the WebRTC edge, built on `dimpl`'s Sans-IO
//! DTLS 1.2/1.3 state machine.
//!
//! Browsers run a DTLS handshake with us over the ICE-nominated UDP pair.
//! The handshake yields two things the rest of the edge stack needs:
//!
//! * DTLS-SRTP keying material plus the negotiated protection profile, which
//!   the `srtp` module turns into SRTP master keys/salts (RFC 5764 §4.2).
//! * The peer's leaf certificate, whose SHA-256 fingerprint must match the
//!   SDP `a=fingerprint` attribute carried over signaling.
//!
//! Like the other modules in this crate, [`DtlsTransport`] performs no IO:
//! callers feed received datagrams and the current time in, and drain
//! packets, timers, and events out via [`DtlsTransport::poll_output`].
//! No per-packet allocation happens here — emitted packets borrow from a
//! buffer allocated once at construction. Allocation only occurs during the
//! handshake (key schedules inside `dimpl`, the stored peer certificate).
//!
//! # Fatal-error contract
//!
//! `dimpl` reports only fatal errors: any `Err` from
//! [`DtlsTransport::handle_packet`], [`DtlsTransport::handle_timeout`],
//! [`DtlsTransport::send_application_data`], or [`DtlsTransport::close`]
//! means the transport is dead and must be dropped. Malformed, replayed, or
//! out-of-window datagrams are discarded internally and never surface as
//! errors.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, DtlsCertificate, KeyingMaterial, SrtpProfile};
use tracing::{debug, warn};

pub use dimpl::ProtocolVersion;

/// Initial size of the internal output buffer used by
/// [`DtlsTransport::poll_output`]. Well above the default engine MTU
/// (1150); grown on demand if an engine output ever exceeds it, so growth
/// is at most a one-off handshake event.
const OUTPUT_BUF_INITIAL: usize = 2048;

/// The SRTP protection profiles this SFU supports, in preference order.
///
/// `dimpl` itself may additionally negotiate `AES128_CM_SHA1_80` if a peer
/// offers nothing else (the extension carries whatever the client lists).
/// Such a negotiation is surfaced faithfully through
/// [`Output::KeyingMaterial`]; the SRTP layer must reject a profile outside
/// this set. Real browsers always offer the AEAD profiles.
pub const SRTP_PROFILES: &[SrtpProfile] = &[
    SrtpProfile::AEAD_AES_256_GCM,
    SrtpProfile::AEAD_AES_128_GCM,
];

/// Errors reported by [`DtlsTransport`].
///
/// Every error is fatal for the connection — per `dimpl`'s contract there
/// are no recoverable engine errors. The only correct response is to drop
/// the transport (and start a fresh handshake if the connection is still
/// wanted).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DtlsError {
    /// The DTLS engine reported a fatal error (alert received, handshake
    /// timeout, protocol violation, ...).
    #[error("DTLS engine failed: {0}")]
    Engine(#[from] dimpl::Error),

    /// Self-signed certificate generation failed in
    /// [`DtlsIdentity::generate`].
    #[error("certificate generation failed")]
    CertificateGeneration,

    /// An operation was attempted on a transport that already failed
    /// fatally. The engine state is no longer trustworthy.
    #[error("DTLS transport already failed")]
    Failed,
}

/// Server identity: a certificate/private-key pair generated once per server
/// process and shared (cloned into) every connection's [`DtlsTransport`].
///
/// Generating ECDSA keys is the expensive part of DTLS setup; doing it once
/// keeps per-connection setup cheap.
pub struct DtlsIdentity {
    cert: DtlsCertificate,
    /// SHA-256 fingerprint of `cert`, formatted as the SDP `a=fingerprint`
    /// attribute wants it: colon-separated uppercase hex pairs.
    fingerprint: String,
}

impl DtlsIdentity {
    /// Generate a fresh self-signed ECDSA P-256 identity.
    ///
    /// Call once at server startup, then pass `&identity` to every
    /// [`DtlsTransport::new`].
    pub fn generate() -> Result<Self, DtlsError> {
        let cert = dimpl::certificate::generate_self_signed_certificate()
            .map_err(|_| DtlsError::CertificateGeneration)?;
        Ok(Self::from_cert(cert))
    }

    /// Wrap an externally generated certificate/private key (both DER).
    ///
    /// Useful for pinning an identity to disk or plugging in a provisioned
    /// certificate instead of a freshly generated self-signed one.
    pub fn from_der(certificate: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self::from_cert(DtlsCertificate {
            certificate,
            private_key,
        })
    }

    fn from_cert(cert: DtlsCertificate) -> Self {
        let fingerprint = cert.fingerprint_str();
        Self { cert, fingerprint }
    }

    /// The local certificate in DER form.
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert.certificate
    }

    /// SHA-256 fingerprint formatted for the SDP `a=fingerprint` attribute,
    /// e.g. `"AB:12:F6:…"` (32 colon-separated uppercase hex pairs).
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint
    }
}

impl fmt::Debug for DtlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsIdentity")
            .field("fingerprint_sha256", &self.fingerprint)
            .field("certificate_der_len", &self.cert.certificate.len())
            .finish()
    }
}

/// One unit of output drained from a [`DtlsTransport`].
///
/// All variants are owned: datagrams and certificates are copied out of the
/// engine's internal buffers. Copying happens only for handshake, control,
/// and (future) SCTP traffic — media never flows through DTLS — so this is
/// not on the repeated media path.
#[non_exhaustive]
pub enum Output {
    /// A DTLS datagram to transmit to the peer on the nominated UDP pair.
    Packet(Vec<u8>),

    /// Timer arm: call [`DtlsTransport::handle_timeout`] at or after this
    /// instant (drives flight retransmission and the handshake deadline).
    ///
    /// `Timeout` is always the **last** output of a drain cycle — the call
    /// after it yields `None` until new input or a timeout re-arms the
    /// engine.
    Timeout(Instant),

    /// The handshake completed; SRTP keys and the peer certificate are
    /// available via the accessors.
    Connected,

    /// The peer's leaf certificate in DER form.
    ///
    /// `dimpl` performs no PKI validation — verifying the SHA-256
    /// fingerprint against the signaled `a=fingerprint` value is the
    /// application's job (see [`DtlsTransport::peer_fingerprint_sha256`]).
    PeerCert(Vec<u8>),

    /// DTLS-SRTP keying material export and the negotiated protection
    /// profile (RFC 5764). Feed to the `srtp` layer.
    KeyingMaterial {
        /// Exporter output; length is `profile.keying_material_len()`
        /// (client‖server keys and salts concatenated).
        material: KeyingMaterial,
        /// The SRTP protection profile negotiated via `use_srtp`.
        profile: SrtpProfile,
    },

    /// Plaintext application data received over DTLS. This is where SCTP
    /// (data channels) would surface; unused by the media path today.
    ApplicationData(Vec<u8>),

    /// The peer sent `close_notify` (graceful shutdown).
    Closed,
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(p) => write!(f, "Packet({} bytes)", p.len()),
            Self::Timeout(t) => write!(f, "Timeout({t:?})"),
            Self::Connected => write!(f, "Connected"),
            Self::PeerCert(der) => write!(f, "PeerCert({} bytes)", der.len()),
            Self::KeyingMaterial { material, profile } => {
                write!(f, "KeyingMaterial({} bytes, {profile})", material.len())
            }
            Self::ApplicationData(d) => write!(f, "ApplicationData({} bytes)", d.len()),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

/// Sans-IO DTLS endpoint for one peer connection, wrapping `dimpl::Dtls`.
///
/// Instances start in the **server** role (our normal case: browsers are
/// the DTLS clients). [`set_active`](Self::set_active)`(true)` switches to
/// the client role for tests or future uses.
///
/// Drive it with:
///
/// 1. [`handle_packet`](Self::handle_packet) for each received UDP datagram
///    on the nominated pair.
/// 2. [`poll_output`](Self::poll_output) drained until [`Output::Timeout`]
///    after every input.
/// 3. [`handle_timeout`](Self::handle_timeout) when the reported timeout
///    instant is reached.
pub struct DtlsTransport {
    dtls: Dtls,
    /// Reusable scratch buffer for `Dtls::poll_output`; grown on demand.
    buf: Vec<u8>,
    /// SDP-formatted SHA-256 fingerprint of our own certificate.
    local_fingerprint: String,
    /// Peer leaf certificate (DER), captured when `PeerCert` is emitted.
    peer_cert: Option<Vec<u8>>,
    /// DTLS-SRTP export once the handshake negotiated it.
    keying_material: Option<(KeyingMaterial, SrtpProfile)>,
    /// Latched when `Connected` is drained.
    connected: bool,
    /// Latched on fatal engine error; further inputs are refused.
    failed: bool,
    /// Whether the current drain cycle already emitted its `Timeout`
    /// terminator. `poll_output` returns `None` once set; every input or
    /// timer call clears it.
    timeout_reported: bool,
}

impl DtlsTransport {
    /// Create a transport in the server role with default engine
    /// configuration (cookie exchange enabled, MTU 1150, 1 s initial flight
    /// RTO, 40 s handshake deadline).
    ///
    /// The engine auto-senses the DTLS version: it answers DTLS 1.3 clients
    /// natively and falls back to DTLS 1.2 for clients that do not offer
    /// 1.3 in `supported_versions`.
    ///
    /// `identity` is shared per-server; see [`DtlsIdentity`].
    pub fn new(identity: &DtlsIdentity, now: Instant) -> Self {
        Self::with_config(identity, Arc::new(Config::default()), now)
    }

    /// Create a server-role transport with an explicit [`dimpl::Config`],
    /// e.g. one shared across all connections via `Arc`.
    pub fn with_config(identity: &DtlsIdentity, config: Arc<Config>, now: Instant) -> Self {
        let dtls = Dtls::new_auto(config, identity.cert.clone(), now);
        Self::from_inner(dtls, identity.fingerprint.clone())
    }

    fn from_inner(dtls: Dtls, local_fingerprint: String) -> Self {
        Self {
            dtls,
            buf: vec![0; OUTPUT_BUF_INITIAL],
            local_fingerprint,
            peer_cert: None,
            keying_material: None,
            connected: false,
            failed: false,
            timeout_reported: false,
        }
    }

    /// Switch roles: `active = true` makes this a DTLS client (sends
    /// ClientHello once `handle_timeout` runs), `false` is the server
    /// default. Must be called before the handshake begins.
    pub fn set_active(&mut self, active: bool) {
        self.timeout_reported = false;
        self.dtls.set_active(active);
    }

    /// Whether this endpoint is in the client role.
    pub fn is_active(&self) -> bool {
        self.dtls.is_active()
    }

    /// Whether the handshake has completed (`Connected` was drained).
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether shutdown is in progress (close sent or `close_notify`
    /// received but not yet fully drained).
    pub fn is_closing(&self) -> bool {
        self.dtls.is_closing()
    }

    /// Whether shutdown is terminal — nothing left to send or report.
    pub fn is_closed(&self) -> bool {
        self.dtls.is_closed()
    }

    /// Whether a fatal engine error has been latched. A failed transport
    /// must be dropped.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// The negotiated DTLS version, or `None` while auto-sense is still
    /// waiting for the peer's ClientHello.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.dtls.protocol_version()
    }

    /// Our certificate's SHA-256 fingerprint, formatted for the SDP
    /// `a=fingerprint` attribute (`"AB:12:…"`).
    pub fn local_fingerprint(&self) -> &str {
        &self.local_fingerprint
    }

    /// The peer's leaf certificate (DER), once [`Output::PeerCert`] has
    /// been drained.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_cert.as_deref()
    }

    /// The peer certificate's SHA-256 fingerprint in SDP `a=fingerprint`
    /// format — compare against the value received over signaling.
    ///
    /// Computed on demand; call at handshake completion, not per packet.
    pub fn peer_fingerprint_sha256(&self) -> Option<String> {
        self.peer_cert.as_deref().map(|der| {
            dimpl::certificate::format_fingerprint(
                &dimpl::certificate::calculate_fingerprint(der),
            )
        })
    }

    /// The negotiated SRTP profile and exported DTLS-SRTP keying material,
    /// once [`Output::KeyingMaterial`] has been drained.
    ///
    /// The material is `profile.keying_material_len()` bytes laid out as
    /// `client_key ‖ server_key ‖ client_salt ‖ server_salt` — the shape
    /// the `srtp` module splits into send/receive contexts.
    pub fn srtp_keying_material(&self) -> Option<(SrtpProfile, &[u8])> {
        self.keying_material
            .as_ref()
            .map(|(material, profile)| (*profile, &material[..]))
    }

    /// Feed one UDP datagram received on the ICE-nominated pair.
    ///
    /// `now` refreshes the engine's retransmit clock before the datagram is
    /// processed, so emitted [`Output::Timeout`] instants are relative to
    /// real time. Malformed and replayed datagrams are discarded internally
    /// and yield `Ok(())`; a returned error is fatal — drop the transport.
    pub fn handle_packet(&mut self, datagram: &[u8], now: Instant) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Failed);
        }
        self.timeout_reported = false;
        if let Err(e) = self.dtls.handle_timeout(now) {
            warn!(error = %e, "DTLS engine failed while refreshing timers");
            self.failed = true;
            return Err(DtlsError::Engine(e));
        }
        if let Err(e) = self.dtls.handle_packet(datagram) {
            warn!(error = %e, "fatal DTLS error on incoming datagram");
            self.failed = true;
            return Err(DtlsError::Engine(e));
        }
        Ok(())
    }

    /// Drain the next pending output.
    ///
    /// Keep calling until [`Output::Timeout`] (which reports when
    /// [`handle_timeout`](Self::handle_timeout) should next run); the call
    /// after `Timeout` returns `None`. Any input — a handled datagram, a
    /// fired timer, queued app data, `close` — re-arms output for the next
    /// drain.
    ///
    /// Packet payloads are copied out of a reusable internal buffer
    /// (allocated once at construction, only ever grown), so draining
    /// allocates once per emitted datagram — handshake-phase traffic only,
    /// never media.
    pub fn poll_output(&mut self) -> Option<Output> {
        if self.timeout_reported {
            // Cycle already terminated at `Timeout`; nothing new can have
            // been queued — all engine inputs clear the flag.
            return None;
        }
        match self.dtls.poll_output(&mut self.buf) {
            dimpl::Output::BufferTooSmall { needed } => {
                // The pending output is retained until emitted; grow the
                // scratch buffer once and poll again.
                self.buf.resize(needed, 0);
                self.poll_output()
            }
            dimpl::Output::Packet(packet) => Some(Output::Packet(packet.to_vec())),
            dimpl::Output::Timeout(at) => {
                self.timeout_reported = true;
                Some(Output::Timeout(at))
            }
            dimpl::Output::Connected => {
                self.connected = true;
                debug!("DTLS handshake completed");
                Some(Output::Connected)
            }
            dimpl::Output::PeerCert(der) => {
                self.peer_cert = Some(der.to_vec());
                let stored = self.peer_cert.clone().expect("peer cert just stored");
                Some(Output::PeerCert(stored))
            }
            dimpl::Output::KeyingMaterial(material, profile) => {
                debug!(%profile, "DTLS-SRTP keying material exported");
                self.keying_material = Some((KeyingMaterial::new(&material), profile));
                Some(Output::KeyingMaterial { material, profile })
            }
            dimpl::Output::ApplicationData(data) => {
                Some(Output::ApplicationData(data.to_vec()))
            }
            dimpl::Output::CloseNotify => {
                debug!("DTLS close_notify received");
                Some(Output::Closed)
            }
            // `dimpl::Output` is non-exhaustive; skip variants we do not
            // model and keep draining.
            _ => self.poll_output(),
        }
    }

    /// Drive retransmission and deadline timers. Call when the `Instant`
    /// from [`Output::Timeout`] is reached.
    ///
    /// Also used to kick off the handshake when in the client role: the
    /// first call sends the ClientHello flight.
    ///
    /// A returned error is fatal — drop the transport.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Failed);
        }
        self.timeout_reported = false;
        self.dtls.handle_timeout(now).map_err(|e| {
            warn!(error = %e, "fatal DTLS timeout error");
            self.failed = true;
            DtlsError::Engine(e)
        })
    }

    /// Queue plaintext for sending over the established DTLS session
    /// (e.g. SCTP for data channels). Unused by the media path — media is
    /// SRTP, not DTLS application data.
    ///
    /// A returned error is fatal — drop the transport.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Failed);
        }
        self.timeout_reported = false;
        self.dtls.send_application_data(data).map_err(|e| {
            self.failed = true;
            DtlsError::Engine(e)
        })
    }

    /// Initiate graceful shutdown by queueing a `close_notify` alert.
    /// Drain [`poll_output`](Self::poll_output) afterwards to flush it onto
    /// the wire; the alert itself is not retransmitted.
    ///
    /// A returned error is fatal — drop the transport.
    pub fn close(&mut self) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Failed);
        }
        self.timeout_reported = false;
        self.dtls.close().map_err(|e| {
            self.failed = true;
            DtlsError::Engine(e)
        })
    }
}

impl fmt::Debug for DtlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsTransport")
            .field("dtls", &self.dtls)
            .field("connected", &self.connected)
            .field("failed", &self.failed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Outputs collected while draining a transport to `Output::Timeout`.
    #[derive(Default)]
    struct Drained {
        packets: Vec<Vec<u8>>,
        timeout: Option<Instant>,
    }

    /// Poll until `Timeout`, copying out datagrams to deliver.
    fn drain(t: &mut DtlsTransport) -> Drained {
        let mut d = Drained::default();
        loop {
            match t.poll_output() {
                Some(Output::Packet(p)) => d.packets.push(p),
                Some(Output::Connected)
                | Some(Output::PeerCert(_))
                | Some(Output::KeyingMaterial { .. })
                | Some(Output::ApplicationData(_))
                | Some(Output::Closed) => {}
                Some(Output::Timeout(at)) => {
                    d.timeout = Some(at);
                }
                None => break,
            }
        }
        d
    }

    /// Deliver `packets` to `dst`, failing the test on a fatal DTLS error.
    fn deliver(packets: &[Vec<u8>], dst: &mut DtlsTransport, now: Instant) {
        for p in packets {
            dst.handle_packet(p, now)
                .expect("handshake packet rejected fatally");
        }
    }

    /// Pump packets between both endpoints until both report connected.
    /// `client` must already have had `handle_timeout` called once to emit
    /// its first flight. `now` is a virtual clock we advance to the
    /// earliest pending timer whenever neither side has packets to send.
    fn drive_until_connected(
        client: &mut DtlsTransport,
        server: &mut DtlsTransport,
        mut now: Instant,
    ) {
        for _ in 0..100 {
            let c = drain(client);
            let s = drain(server);
            let progressed = !c.packets.is_empty() || !s.packets.is_empty();
            deliver(&s.packets, client, now);
            deliver(&c.packets, server, now);
            if client.is_connected() && server.is_connected() {
                return;
            }
            if !progressed {
                // Nothing in flight: jump to the earliest armed timer and
                // let retransmission/deadline logic run on both ends.
                let next = [c.timeout, s.timeout]
                    .into_iter()
                    .flatten()
                    .min()
                    .expect("engine must always report a timeout");
                now = next;
                client.handle_timeout(now).expect("client timeout");
                server.handle_timeout(now).expect("server timeout");
            }
        }
        panic!("handshake did not complete in 100 rounds");
    }

    /// Server + client pair using `DtlsTransport::new` (auto-sense version,
    /// server role for `server`, client role for `client`).
    fn auto_pair(now: Instant) -> (DtlsIdentity, DtlsIdentity, DtlsTransport, DtlsTransport) {
        let server_id = DtlsIdentity::generate().unwrap();
        let client_id = DtlsIdentity::generate().unwrap();
        let server = DtlsTransport::new(&server_id, now);
        let mut client = DtlsTransport::new(&client_id, now);
        client.set_active(true);
        (server_id, client_id, client, server)
    }

    /// The same assertions every successful handshake must satisfy,
    /// regardless of negotiated DTLS version.
    fn assert_handshake(
        server_id: &DtlsIdentity,
        client_id: &DtlsIdentity,
        client: &DtlsTransport,
        server: &DtlsTransport,
    ) {
        assert!(client.is_connected() && server.is_connected());
        assert!(!client.is_failed() && !server.is_failed());
        assert_eq!(client.protocol_version(), server.protocol_version());

        // Keying material exported on both ends, identical exporter output,
        // same profile, correct length for the profile.
        let (c_profile, c_material) = client
            .srtp_keying_material()
            .expect("client keying material");
        let (s_profile, s_material) = server
            .srtp_keying_material()
            .expect("server keying material");
        assert_eq!(c_profile, s_profile);
        assert_eq!(c_material, s_material);
        assert_eq!(c_material.len(), c_profile.keying_material_len());
        assert!(
            SRTP_PROFILES.contains(&c_profile),
            "negotiated profile {c_profile} outside supported set"
        );

        // Each side received and fingerprinted the other's leaf cert.
        assert_eq!(
            server.peer_certificate(),
            Some(client_id.certificate_der()),
            "server must see the client's certificate"
        );
        assert_eq!(
            client.peer_certificate(),
            Some(server_id.certificate_der()),
            "client must see the server's certificate"
        );
        assert_eq!(
            server.peer_fingerprint_sha256().as_deref(),
            Some(client_id.fingerprint_sha256())
        );
        assert_eq!(
            client.peer_fingerprint_sha256().as_deref(),
            Some(server_id.fingerprint_sha256())
        );
        assert_eq!(server.local_fingerprint(), server_id.fingerprint_sha256());
    }

    #[test]
    fn identity_fingerprint_matches_sdp_format() {
        let id = DtlsIdentity::generate().unwrap();
        let fp = id.fingerprint_sha256();
        // 32 bytes as "AB:CD:…" => 32*2 hex chars + 31 colons.
        assert_eq!(fp.len(), 95);
        for (i, ch) in fp.chars().enumerate() {
            if i % 3 == 2 {
                assert_eq!(ch, ':');
            } else {
                assert!(ch.is_ascii_hexdigit() && !ch.is_ascii_lowercase());
            }
        }
    }

    #[test]
    fn handshake_auto_sense_completes() {
        // Server + client both auto: negotiates DTLS 1.3.
        let now = Instant::now();
        let (server_id, client_id, mut client, mut server) = auto_pair(now);

        // Kick off the client's first flight (ClientHello).
        client.handle_timeout(now).unwrap();
        drive_until_connected(&mut client, &mut server, now);

        assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_3));
        assert_handshake(&server_id, &client_id, &client, &server);
    }

    #[test]
    fn handshake_dtls12_completes() {
        // Both ends pinned to DTLS 1.2 via the inner engine directly.
        let now = Instant::now();
        let server_id = DtlsIdentity::generate().unwrap();
        let client_id = DtlsIdentity::generate().unwrap();
        let config = || Arc::new(Config::default());
        let mut server = DtlsTransport::from_inner(
            Dtls::new_12(config(), server_id.cert.clone(), now),
            server_id.fingerprint.clone(),
        );
        let mut client = DtlsTransport::from_inner(
            Dtls::new_12(config(), client_id.cert.clone(), now),
            client_id.fingerprint.clone(),
        );
        client.set_active(true);
        assert!(client.is_active());
        assert!(!server.is_active());

        client.handle_timeout(now).unwrap();
        drive_until_connected(&mut client, &mut server, now);

        assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_2));
        assert_handshake(&server_id, &client_id, &client, &server);
    }

    #[test]
    fn lost_flight_is_retransmitted_on_timeout() {
        let now = Instant::now();
        let (_, _, mut client, mut server) = auto_pair(now);

        // Client sends its first flight; we drop every packet.
        client.handle_timeout(now).unwrap();
        let first = drain(&mut client);
        assert!(!first.packets.is_empty(), "client should emit ClientHello");
        let deadline = first.timeout.expect("flight timer must be armed");
        assert!(deadline > now);
        // Nothing delivered: the server stays unconnected.
        assert!(!server.is_connected());

        // Advance past the flight deadline: the client must retransmit.
        let now = deadline + Duration::from_millis(1);
        client.handle_timeout(now).unwrap();
        let second = drain(&mut client);
        assert!(
            !second.packets.is_empty(),
            "expected retransmitted flight after timeout"
        );

        // Delivering the retransmission lets the handshake proceed.
        deliver(&second.packets, &mut server, now);
        drive_until_connected(&mut client, &mut server, now);
        assert!(client.is_connected() && server.is_connected());
    }

    #[test]
    fn server_retransmits_flight_when_response_lost() {
        let now = Instant::now();
        let (_, _, mut client, mut server) = auto_pair(now);

        // Drive the cookie exchange, then drop the server's post-cookie
        // flight (ServerHello…Finished). The cookie response itself is
        // stateless and carries no retransmit timer, so it must be delivered.
        client.handle_timeout(now).unwrap();
        let ch = drain(&mut client);
        deliver(&ch.packets, &mut server, now);
        let cookie_response = drain(&mut server);
        assert!(!cookie_response.packets.is_empty());
        deliver(&cookie_response.packets, &mut client, now);
        let ch_cookie = drain(&mut client);
        deliver(&ch_cookie.packets, &mut server, now);
        let dropped = drain(&mut server);
        assert!(
            !dropped.packets.is_empty(),
            "server should have emitted its post-cookie flight"
        );

        // Arm the flight timer, then read the armed deadline.
        server.handle_timeout(now).unwrap();
        let armed = drain(&mut server);
        let deadline = armed.timeout.expect("server flight timer armed");
        assert!(deadline > now);

        // Past the deadline the server retransmits its flight. Records get
        // fresh record-sequence numbers (and ciphertext under them), so
        // compare flight shape: same packet count, content types, lengths.
        let now = deadline + Duration::from_millis(1);
        server.handle_timeout(now).unwrap();
        let resend = drain(&mut server);
        assert!(
            !resend.packets.is_empty(),
            "server should retransmit its flight"
        );
        assert_eq!(resend.packets.len(), dropped.packets.len());
        for (a, b) in resend.packets.iter().zip(&dropped.packets) {
            assert_eq!(a.len(), b.len());
            assert_eq!(a[0], b[0], "retransmitted record content type");
        }

        // Delivering the retransmission completes the handshake.
        deliver(&resend.packets, &mut client, now);
        drive_until_connected(&mut client, &mut server, now);
        assert!(client.is_connected() && server.is_connected());
    }

    #[test]
    fn garbage_input_never_panics_and_is_ignored() {
        let now = Instant::now();
        let server_id = DtlsIdentity::generate().unwrap();
        let client_id = DtlsIdentity::generate().unwrap();
        let mut server = DtlsTransport::new(&server_id, now);
        let mut client = DtlsTransport::new(&client_id, now);
        client.set_active(true);

        let garbage: &[&[u8]] = &[
            &[],
            &[0x00],
            &[0x16],                                 // content type only
            &[0x16, 0xfe, 0xfd],                     // truncated record header
            &[0xff; 64],                             // unknown content type
            &[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], // absurd length
            &[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],       // empty record
        ];
        // Garbage to the server must never panic and never fail fatally:
        // the engine discards malformed datagrams internally. (A *pending
        // auto-sense client* is different — an unparseable first server
        // response is a fatal `UnexpectedMessage`, so the client stays
        // clean until connected below.)
        for (i, g) in garbage.iter().enumerate() {
            let res = server.handle_packet(g, now);
            assert!(res.is_ok(), "server must discard garbage packet {i}");
        }
        assert!(!server.is_failed());

        // A handful of garbage datagrams must not poison the handshake:
        // the real ClientHello still goes through.
        client.handle_timeout(now).unwrap();
        drive_until_connected(&mut client, &mut server, now);
        assert!(client.is_connected() && server.is_connected());

        // On an established connection, garbage records are discarded too.
        for g in garbage {
            let _ = server.handle_packet(g, now);
            let _ = client.handle_packet(g, now);
        }
    }

    #[test]
    fn fatal_error_is_sticky() {
        let now = Instant::now();
        let id = DtlsIdentity::generate().unwrap();
        let mut server = DtlsTransport::new(&id, now);

        // Push the connect deadline past the 40 s handshake timeout.
        server.handle_timeout(now).unwrap();
        let far = now + Duration::from_secs(120);
        let res = server.handle_timeout(far);
        assert!(res.is_err(), "handshake deadline should be fatal");
        assert!(server.is_failed());

        // Everything afterwards reports the sticky failure.
        assert!(matches!(
            server.handle_packet(&[0x16], far),
            Err(DtlsError::Failed)
        ));
        assert!(matches!(
            server.handle_timeout(far),
            Err(DtlsError::Failed)
        ));
    }
}
