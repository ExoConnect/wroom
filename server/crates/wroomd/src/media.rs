//! The M0 media runtime: one UDP socket, per-connection transports,
//! forward-everything inside a room.
//!
//! Single task owns all forwarding state (`&mut`, no locks) — the
//! share-nothing shape the worker model formalizes (AGENTS §4). For M0
//! it runs on tokio; recvmmsg batching and pinned workers are M3 work.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use wroom_edge::dtls::DtlsIdentity;
use wroom_edge::ice::{is_stun_datagram, Message};
use wroom_edge::sdp::{
    build_subscriber_offer, AnswerConfig, Candidate, Fingerprint, MediaKind, Offer, OfferedMedia,
};
use wroom_edge::transport::{PeerEvent, PeerTransport};
use wroom_signaling::media::MediaControl;
use wroom_signaling::proto::{self, server_message, ServerMessage};

/// Which peer connection a transport serves (D15: one PC per leg).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Leg {
    Pub,
    Sub,
}

/// A transport's full identity in the maps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransportKey {
    room: String,
    participant: String,
    leg: Leg,
}

/// One joined participant's media-plane state.
struct Member {
    /// Channel back to their signaling socket (offers/answers).
    reply: mpsc::Sender<ServerMessage>,
    /// Tracks this member has published (`Track.id`, kind).
    published: Vec<(String, MediaKind)>,
    /// Monotonic session version for their subscriber-leg re-offers.
    sub_offer_version: u64,
}

/// Runs the media plane until the control channel closes.
pub async fn run(
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    media_port: u16,
    advertise_addr: String,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", media_port)).await?;
    let mut rt = Runtime::new(socket, control_rx, advertise_addr);
    rt.loop_forever().await;
    Ok(())
}

struct Runtime {
    socket: UdpSocket,
    identity: DtlsIdentity,
    transports: HashMap<TransportKey, PeerTransport>,
    /// Pre-nomination routing: STUN USERNAME local part → transport.
    by_ufrag: HashMap<String, TransportKey>,
    /// Post-nomination routing: remote 5-tuple → transport.
    by_addr: HashMap<SocketAddr, TransportKey>,
    rooms: HashMap<String, HashMap<String, Member>>,
    advertise_addr: String,
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
}

impl Runtime {
    /// A runtime on an already-bound socket with a fresh DTLS identity
    /// and empty state. Split from [`run`] so tests can drive the real
    /// `loop_forever` on a socket they bound — and keep the runtime
    /// inspectable once it exits.
    fn new(
        socket: UdpSocket,
        control_rx: mpsc::UnboundedReceiver<MediaControl>,
        advertise_addr: String,
    ) -> Self {
        let identity = DtlsIdentity::generate().expect("dtls identity");
        tracing::info!(
            addr = ?socket.local_addr(),
            advertise = %advertise_addr,
            fingerprint = %identity.fingerprint_sha256(),
            "media plane listening"
        );
        Self {
            socket,
            identity,
            transports: HashMap::new(),
            by_ufrag: HashMap::new(),
            by_addr: HashMap::new(),
            rooms: HashMap::new(),
            advertise_addr,
            control_rx,
        }
    }

    async fn loop_forever(&mut self) {
        let mut buf = vec![0u8; 2048].into_boxed_slice();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
        loop {
            tokio::select! {
                recv = self.socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((n, from)) => self.on_datagram(&mut buf[..n], from).await,
                        Err(e) => {
                            tracing::error!(error = %e, "media socket recv failed");
                            return;
                        }
                    }
                }
                ctl = self.control_rx.recv() => match ctl {
                    Some(c) => self.on_control(c).await,
                    None => return,
                },
                _ = tick.tick() => self.on_tick(),
            }
        }
    }

    fn our_candidates(&self) -> Vec<Candidate> {
        vec![Candidate::host(
            "1",
            2_130_706_431,
            self.advertise_addr.clone(),
            self.socket.local_addr().map(|a| a.port()).unwrap_or(0),
        )]
    }

    fn answer_config(&self, t: &PeerTransport) -> AnswerConfig {
        AnswerConfig::new(
            1,
            t.local_ufrag().to_string(),
            t.local_pwd().to_string(),
            Fingerprint::sha256(self.identity.fingerprint_sha256().to_string()),
            self.our_candidates(),
        )
    }

    /// Route a datagram to its transport and act on what it yields.
    async fn on_datagram(&mut self, buf: &mut [u8], from: SocketAddr) {
        let key = if let Some(k) = self.by_addr.get(&from) {
            Some(k.clone())
        } else if is_stun_datagram(buf) {
            // Pre-nomination: the USERNAME's local half names the
            // transport ("localufrag:remoteufrag", RFC 8445).
            Message::parse(buf)
                .ok()
                .and_then(|m| m.get(wroom_edge::ice::attr::USERNAME))
                .and_then(|a| std::str::from_utf8(a.value).ok())
                .and_then(|u| u.split(':').next().map(str::to_owned))
                .and_then(|local| self.by_ufrag.get(&local).cloned())
        } else {
            None
        };
        let Some(key) = key else { return };
        let events = {
            let Some(t) = self.transports.get_mut(&key) else {
                return;
            };
            t.handle_datagram(buf, from, Instant::now())
        };
        self.apply_events(key, events, buf).await;
    }

    async fn apply_events(&mut self, key: TransportKey, events: Vec<PeerEvent>, buf: &[u8]) {
        for ev in events {
            match ev {
                PeerEvent::Send { to, data } => {
                    let _ = self.socket.send_to(&data, to).await;
                }
                PeerEvent::Nominated(addr) => {
                    self.by_addr.insert(addr, key.clone());
                }
                PeerEvent::Connected => {
                    tracing::info!(
                        room = %key.room,
                        participant = %key.participant,
                        leg = ?key.leg,
                        "peer transport connected"
                    );
                }
                PeerEvent::Media { len, rtcp } => {
                    if key.leg == Leg::Pub {
                        self.forward(&key, &buf[..len], rtcp).await;
                    }
                    // M0: subscriber-leg RTCP (PLI/RR) is dropped — the
                    // publisher never hears keyframe requests until the
                    // PLI relay lands with per-leg routing in M1.
                }
                PeerEvent::Failed(why) => {
                    tracing::warn!(
                        participant = %key.participant,
                        why,
                        "peer transport failed"
                    );
                    self.drop_transport(&key);
                }
                PeerEvent::Closed => self.drop_transport(&key),
            }
        }
    }

    fn drop_transport(&mut self, key: &TransportKey) {
        if let Some(t) = self.transports.remove(key) {
            self.by_ufrag.remove(t.local_ufrag());
            if let Some(a) = t.remote_addr() {
                self.by_addr.remove(&a);
            }
        }
    }

    async fn on_control(&mut self, ctl: MediaControl) {
        match ctl {
            MediaControl::Joined {
                room,
                participant,
                reply,
            } => {
                let member = Member {
                    reply,
                    published: Vec::new(),
                    sub_offer_version: 0,
                };
                let members = self.rooms.entry(room.clone()).or_default();
                // Offer them everyone else's already-published tracks.
                let others: Vec<(String, MediaKind)> = members
                    .iter()
                    .filter(|(p, _)| *p != &participant)
                    .flat_map(|(_, m)| m.published.iter().cloned())
                    .collect();
                members.insert(participant.clone(), member);
                if !others.is_empty() {
                    self.offer_subscriber(&room, &participant, &others).await;
                }
            }
            MediaControl::PublisherOffer {
                room,
                participant,
                sdp,
            } => {
                self.on_pub_offer(&room, &participant, &sdp).await;
            }
            MediaControl::SubscriberAnswer {
                room,
                participant,
                sdp,
            } => self.on_sub_answer(&room, &participant, &sdp),
            MediaControl::TracksPublished {
                room,
                participant,
                tracks,
            } => {
                let Some(members) = self.rooms.get_mut(&room) else {
                    return;
                };
                let kinds: Vec<(String, MediaKind)> = tracks
                    .iter()
                    .map(|t| {
                        (
                            t.id.clone(),
                            match t.kind() {
                                proto::TrackKind::Audio => MediaKind::Audio,
                                _ => MediaKind::Video,
                            },
                        )
                    })
                    .collect();
                if let Some(m) = members.get_mut(&participant) {
                    m.published.extend(kinds);
                }
                // Re-offer every other member's subscriber leg with the
                // union of everyone else's tracks (forward-all for M0).
                let updates: Vec<(String, Vec<(String, MediaKind)>)> = members
                    .iter()
                    .filter(|(p, _)| *p != &participant)
                    .map(|(p, _)| {
                        let tracks: Vec<(String, MediaKind)> = members
                            .iter()
                            .filter(|(q, _)| *q != p)
                            .flat_map(|(_, m)| m.published.iter().cloned())
                            .collect();
                        (p.clone(), tracks)
                    })
                    .collect();
                for (pid, tracks) in updates {
                    if !tracks.is_empty() {
                        self.offer_subscriber(&room, &pid, &tracks).await;
                    }
                }
            }
            MediaControl::Left { room, participant } => {
                for leg in [Leg::Pub, Leg::Sub] {
                    self.drop_transport(&TransportKey {
                        room: room.clone(),
                        participant: participant.clone(),
                        leg,
                    });
                }
                if let Some(members) = self.rooms.get_mut(&room) {
                    members.remove(&participant);
                    if members.is_empty() {
                        self.rooms.remove(&room);
                    }
                }
            }
        }
    }

    /// Publisher offer arrived: create the transport and answer it.
    async fn on_pub_offer(&mut self, room: &str, pid: &str, sdp: &str) {
        let offer = match Offer::parse(sdp) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(participant = pid, error = %e, "bad publisher offer");
                return;
            }
        };
        let key = TransportKey {
            room: room.to_string(),
            participant: pid.to_string(),
            leg: Leg::Pub,
        };
        self.drop_transport(&key); // re-offer: fresh transport
        let t = PeerTransport::new(
            &self.identity,
            Instant::now(),
            offer.ice_ufrag(),
            offer.sha256_fingerprint().map(|f| f.value.clone()),
        );
        let config = self.answer_config(&t);
        let answer = match offer.answer(&config) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(participant = pid, error = %e, "answer build failed");
                return;
            }
        };
        self.by_ufrag
            .insert(t.local_ufrag().to_string(), key.clone());
        self.transports.insert(key, t);
        self.send_sdp(
            pid,
            room,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
            answer.into_string(),
        );
    }

    /// Subscriber answer arrived: finish their sub-leg transport (it was
    /// created when we offered, remote creds now known).
    fn on_sub_answer(&mut self, room: &str, pid: &str, sdp: &str) {
        let answer = match Offer::parse(sdp) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(participant = pid, error = %e, "bad subscriber answer");
                return;
            }
        };
        let key = TransportKey {
            room: room.to_string(),
            participant: pid.to_string(),
            leg: Leg::Sub,
        };
        let Some(t) = self.transports.get_mut(&key) else {
            return;
        };
        if let Some(u) = answer.ice_ufrag() {
            t.set_remote_ufrag(u);
        }
        if let Some(f) = answer.sha256_fingerprint() {
            t.set_expected_fingerprint(f.value.clone());
        }
    }

    /// (Re)build a member's subscriber offer over their sub transport.
    async fn offer_subscriber(
        &mut self,
        room: &str,
        pid: &str,
        tracks: &[(String, MediaKind)],
    ) {
        let key = TransportKey {
            room: room.to_string(),
            participant: pid.to_string(),
            leg: Leg::Sub,
        };
        let fingerprint =
            Fingerprint::sha256(self.identity.fingerprint_sha256().to_string());
        let candidates = self.our_candidates();
        let version = {
            let Some(m) = self.rooms.get_mut(room).and_then(|m| m.get_mut(pid)) else {
                return;
            };
            m.sub_offer_version += 1;
            m.sub_offer_version
        };
        // Create the transport on first offer so ICE creds exist.
        let transport = match self.transports.get_mut(&key) {
            Some(t) => t,
            None => {
                let t = PeerTransport::new(&self.identity, Instant::now(), None, None);
                self.by_ufrag
                    .insert(t.local_ufrag().to_string(), key.clone());
                self.transports.insert(key.clone(), t);
                self.transports.get_mut(&key).unwrap()
            }
        };
        let mut config = AnswerConfig::new(
            1,
            transport.local_ufrag().to_string(),
            transport.local_pwd().to_string(),
            fingerprint,
            candidates,
        );
        config.session_version = version;
        let media: Vec<OfferedMedia> = tracks
            .iter()
            .enumerate()
            .map(|(i, (id, kind))| OfferedMedia {
                mid: i.to_string(),
                kind: kind.clone(),
                msid_track: id.clone(),
                payloads: match kind {
                    MediaKind::Audio => vec![111],
                    _ => vec![96],
                },
                payload_lines: match kind {
                    MediaKind::Audio => vec![(111, "opus/48000/2".to_string())],
                    _ => vec![(96, "VP8/90000".to_string())],
                },
            })
            .collect();
        let offer = match build_subscriber_offer(&config, &media) {
            Ok(o) => o.into_string(),
            Err(e) => {
                tracing::warn!(participant = pid, error = %e, "subscriber offer failed");
                return;
            }
        };
        self.send_sdp(
            pid,
            room,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
            offer,
        );
    }

    /// Push a SessionDescription to a participant's signaling socket.
    fn send_sdp(
        &self,
        pid: &str,
        room: &str,
        target: proto::SignalTarget,
        ty: proto::session_description::Type,
        sdp: String,
    ) {
        let Some(reply) = self
            .rooms
            .get(room)
            .and_then(|m| m.get(pid))
            .map(|m| m.reply.clone())
        else {
            return;
        };
        let msg = ServerMessage {
            msg: Some(server_message::Msg::SessionDescription(
                proto::SessionDescription {
                    target: target.into(),
                    r#type: ty.into(),
                    sdp,
                },
            )),
        };
        if reply.try_send(msg).is_err() {
            tracing::warn!(participant = pid, "reply queue full; SDP dropped");
        }
    }

    /// Forward decrypted media from a publisher transport to every other
    /// member's subscriber transport (forward-all; M1 adds layer select).
    async fn forward(&mut self, key: &TransportKey, plain: &[u8], rtcp: bool) {
        let Some(members) = self.rooms.get(&key.room) else {
            return;
        };
        let targets: Vec<TransportKey> = members
            .keys()
            .filter(|p| **p != key.participant)
            .map(|p| TransportKey {
                room: key.room.clone(),
                participant: p.clone(),
                leg: Leg::Sub,
            })
            .collect();
        let mut out = vec![0u8; 2048].into_boxed_slice();
        for tk in targets {
            let Some(t) = self.transports.get_mut(&tk) else {
                continue;
            };
            let res = if rtcp {
                t.protect_rtcp(plain, &mut out)
            } else {
                t.protect_rtp(plain, &mut out)
            };
            if let Some((to, n)) = res {
                let _ = self.socket.send_to(&out[..n], to).await;
            }
        }
    }

    /// Advance all transport timers (~20 ms granularity).
    fn on_tick(&mut self) {
        let now = Instant::now();
        let mut sends: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut dead: Vec<TransportKey> = Vec::new();
        for (key, t) in self.transports.iter_mut() {
            for ev in t.handle_timeout(now) {
                match ev {
                    PeerEvent::Send { to, data } => sends.push((to, data)),
                    PeerEvent::Nominated(addr) => {
                        self.by_addr.insert(addr, key.clone());
                    }
                    PeerEvent::Closed | PeerEvent::Failed(_) => {
                        dead.push(key.clone());
                    }
                    _ => {}
                }
            }
        }
        for key in dead {
            self.drop_transport(&key);
        }
        for (to, data) in sends {
            let _ = self.socket.try_send_to(&data, to);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────
//
// Headless fake-peer E2E: in-process "peers" that speak the real wire
// protocol to the running runtime over loopback UDP — STUN connectivity
// check + nomination, a client-role DTLS handshake, then SRTP media.
// Nothing here is on the forwarding hot path; allocations in helpers are
// deliberate (a real peer is a separate process, not a Sans-IO component).

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::time::timeout;
    use wroom_edge::dtls::{DtlsTransport, Output as DtlsOutput};
    use wroom_edge::ice::{BINDING_REQUEST, Class, MessageBuilder};
    use wroom_edge::rtp::RtpPacket;
    use wroom_edge::sdp::Direction;
    use wroom_edge::srtp::{Role as SrtpRole, SRTP_TAG_LEN, Srtp};

    /// A fake participant: one DTLS identity (browsers reuse the cert
    /// across peer connections) plus the bounded reply channel the
    /// runtime pushes server-initiated SDP into — the stand-in for its
    /// signaling socket.
    struct FakePeer {
        identity: DtlsIdentity,
        reply: mpsc::Receiver<ServerMessage>,
    }

    impl FakePeer {
        fn new() -> (Self, mpsc::Sender<ServerMessage>) {
            let (tx, rx) = mpsc::channel(16);
            (
                Self {
                    identity: DtlsIdentity::generate().expect("peer identity"),
                    reply: rx,
                },
                tx,
            )
        }
    }

    /// One fake peer-connection leg's wire state: its own UDP socket
    /// (legs are distinct 5-tuples, D15), the transport parameters the
    /// runtime advertised in SDP, and the DTLS client + SRTP stack the
    /// datagrams feed.
    struct FakeLeg {
        socket: UdpSocket,
        /// The runtime's host candidate, parsed out of its SDP.
        server: SocketAddr,
        /// Our ICE ufrag — the remote half of the STUN USERNAMEs we send.
        ufrag: String,
        /// The runtime's ufrag/pwd from its SDP: the USERNAME local half
        /// (which the runtime uses for pre-nomination routing) and the
        /// MESSAGE-INTEGRITY key respectively (RFC 8445 §7.3).
        server_ufrag: String,
        server_pwd: String,
        /// `a=fingerprint` from the runtime's SDP — asserted against the
        /// certificate it actually presents during the DTLS handshake.
        expected_fingerprint: String,
        dtls: DtlsTransport,
        srtp: Option<Srtp>,
    }

    impl FakeLeg {
        /// Bind a fresh socket and learn the server endpoint from its SDP
        /// (the answer for a pub leg, the offer for a sub leg).
        async fn new(identity: &DtlsIdentity, ufrag: &str, server_sdp: &Offer) -> Self {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("fake leg socket");
            let candidate = server_sdp
                .media
                .iter()
                .flat_map(|m| m.candidates.iter())
                .find(|c| c.transport.eq_ignore_ascii_case("udp"))
                .expect("server SDP carries a UDP candidate");
            Self {
                socket,
                server: SocketAddr::new(
                    candidate.address.parse().expect("candidate address parses"),
                    candidate.port,
                ),
                ufrag: ufrag.to_string(),
                server_ufrag: server_sdp.ice_ufrag().expect("server a=ice-ufrag").into(),
                server_pwd: server_sdp.ice_pwd().expect("server a=ice-pwd").into(),
                expected_fingerprint: server_sdp
                    .sha256_fingerprint()
                    .expect("server a=fingerprint")
                    .value
                    .clone(),
                dtls: DtlsTransport::new(identity, Instant::now()),
                srtp: None,
            }
        }

        fn local_addr(&self) -> SocketAddr {
            self.socket.local_addr().expect("leg addr")
        }

        /// ICE connectivity check + nomination as the controlling full
        /// agent (RFC 8445): a Binding request with USERNAME
        /// "<server>:<ours>", ICE-CONTROLLING, USE-CANDIDATE and
        /// MESSAGE-INTEGRITY keyed by the server's pwd. Asserts the
        /// signed success response and that our XOR-MAPPED-ADDRESS is
        /// this leg's own socket address.
        async fn nominate(&self) {
            let mut tid = [0xF0; 12];
            tid[..2].copy_from_slice(&self.local_addr().port().to_be_bytes());
            let username = format!("{}:{}", self.server_ufrag, self.ufrag);
            let mut req = [0u8; 256];
            let req_len = {
                let mut b = MessageBuilder::new(&mut req, BINDING_REQUEST, &tid).unwrap();
                b.username(&username)
                    .unwrap()
                    .priority(0x7EFF_0001) // host-candidate priority
                    .unwrap()
                    .ice_controlling(0x0123_4567_89AB_CDEF)
                    .unwrap()
                    .use_candidate()
                    .unwrap()
                    .message_integrity(self.server_pwd.as_bytes())
                    .unwrap()
                    .fingerprint()
                    .unwrap();
                b.finish().unwrap()
            };

            let mut resp = [0u8; 1024];
            // Loopback answers instantly; retry a few times so a lost
            // datagram can never flake the test.
            for _attempt in 0..10 {
                self.socket
                    .send_to(&req[..req_len], self.server)
                    .await
                    .unwrap();
                let verdict = timeout(Duration::from_secs(1), async {
                    loop {
                        let (n, _) = self.socket.recv_from(&mut resp).await.unwrap();
                        let Ok(msg) = Message::parse(&resp[..n]) else {
                            continue; // not STUN — never happens here
                        };
                        if msg.transaction_id() != tid {
                            continue; // a retransmit of an older check
                        }
                        assert!(
                            msg.fingerprint_valid(),
                            "binding response with bad FINGERPRINT"
                        );
                        if msg.class() == Class::Error {
                            panic!("binding request rejected: {:?}", msg.error_code());
                        }
                        assert_eq!(msg.class(), Class::Success);
                        assert!(
                            msg.verify_message_integrity(self.server_pwd.as_bytes()),
                            "binding response MESSAGE-INTEGRITY does not verify"
                        );
                        assert_eq!(msg.xor_mapped_address(), Some(self.local_addr()));
                        return;
                    }
                })
                .await;
                if verdict.is_ok() {
                    return;
                }
            }
            panic!("ICE nomination got no binding response");
        }

        /// DTLS handshake in the client role, pumped over the socket
        /// until Connected and the SRTP export have both landed.
        /// `set_active(true)` arms the ClientHello flight, which `dimpl`
        /// emits on the first `handle_timeout` — Sans-IO components
        /// never self-send.
        async fn connect(&mut self) {
            self.dtls.set_active(true);
            self.dtls
                .handle_timeout(Instant::now())
                .expect("client kickoff");

            timeout(Duration::from_secs(15), async {
                let mut buf = vec![0u8; 2048].into_boxed_slice();
                let mut retransmit_at: Option<Instant> = None;
                loop {
                    while let Some(out) = self.dtls.poll_output() {
                        match out {
                            DtlsOutput::Packet(p) => {
                                self.socket.send_to(&p, self.server).await.unwrap();
                            }
                            DtlsOutput::Timeout(t) => retransmit_at = Some(t),
                            // PeerCert/KeyingMaterial/Connected latch on
                            // the transport — read them after the loop.
                            _ => {}
                        }
                    }
                    if self.dtls.is_connected() && self.dtls.srtp_keying_material().is_some() {
                        break;
                    }
                    let wait = retransmit_at
                        .map(|t| t.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_secs(1))
                        .min(Duration::from_secs(1));
                    tokio::select! {
                        recv = self.socket.recv_from(&mut buf) => {
                            let (n, _) = recv.expect("leg socket recv");
                            let d = &buf[..n];
                            if is_stun_datagram(d) {
                                // Late ICE traffic; the agent owns those.
                            } else if (20..=63).contains(&d[0]) {
                                self.dtls
                                    .handle_packet(d, Instant::now())
                                    .expect("fatal dtls input");
                            }
                        }
                        _ = tokio::time::sleep(wait) => {
                            self.dtls
                                .handle_timeout(Instant::now())
                                .expect("fatal dtls timeout");
                        }
                    }
                }
            })
            .await
            .expect("dtls handshake stalled");

            // The certificate the runtime actually used must be the one
            // its SDP advertised — the RFC 5764 binding.
            let peer_fp = self
                .dtls
                .peer_fingerprint_sha256()
                .expect("server presented a cert");
            assert!(
                peer_fp.eq_ignore_ascii_case(&self.expected_fingerprint),
                "server cert {peer_fp} does not match SDP a=fingerprint {}",
                self.expected_fingerprint
            );
            let (profile, material) = self.dtls.srtp_keying_material().expect("dtls-srtp export");
            // We are the DTLS client: rx keys with the server-write half.
            self.srtp = Some(
                Srtp::from_keying_material_as(profile, material, SrtpRole::Client)
                    .expect("client-role srtp context"),
            );
        }

        /// SRTP-protect one plaintext RTP packet and send it.
        async fn send_media(&mut self, rtp: &[u8]) {
            let srtp = self.srtp.as_mut().expect("srtp installed");
            let mut buf = vec![0u8; rtp.len() + SRTP_TAG_LEN].into_boxed_slice();
            buf[..rtp.len()].copy_from_slice(rtp);
            let n = srtp.encrypt_rtp(&mut buf, rtp.len()).expect("protect rtp");
            self.socket.send_to(&buf[..n], self.server).await.unwrap();
        }

        /// Receive the next inbound SRTP-RTP datagram and return its
        /// plaintext, or `None` after `within`. STUN/DTLS stragglers (a
        /// retransmitted handshake flight can still be in flight) are
        /// skipped; authentication failures panic — the runtime must
        /// never emit a packet that doesn't verify.
        async fn try_recv_media(&mut self, within: Duration) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; 2048].into_boxed_slice();
            timeout(within, async {
                loop {
                    let (n, _) = self.socket.recv_from(&mut buf).await.expect("recv");
                    let d = &mut buf[..n];
                    if d.len() < 2 || !(128..=255).contains(&d[0]) || (192..=223).contains(&d[1]) {
                        continue;
                    }
                    let len = self
                        .srtp
                        .as_mut()
                        .expect("srtp installed")
                        .decrypt_rtp(d)
                        .expect("forwarded packet must authenticate");
                    return d[..len].to_vec();
                }
            })
            .await
            .ok()
        }
    }

    /// Wait for a SessionDescription of the given target + type on a
    /// peer's reply channel; anything else is skipped.
    async fn recv_sdp(
        rx: &mut mpsc::Receiver<ServerMessage>,
        target: proto::SignalTarget,
        ty: proto::session_description::Type,
    ) -> String {
        timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Some(ServerMessage {
                        msg: Some(server_message::Msg::SessionDescription(sd)),
                    }) if sd.target() == target && sd.r#type() == ty => return sd.sdp,
                    Some(_) => continue,
                    None => panic!("reply channel closed early"),
                }
            }
        })
        .await
        .expect("timed out waiting for session description")
    }

    /// Minimal-but-valid publisher offer: one sendonly VP8 m-line with
    /// the peer's ICE creds and cert fingerprint — everything
    /// `Offer::parse` and `SessionDescription::answer` consume.
    fn publisher_offer(identity: &DtlsIdentity, ufrag: &str, pwd: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 4242 1 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE 0\r\n\
             a=msid-semantic: WMS\r\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=rtcp:9 IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=ice-options:trickle\r\n\
             a=fingerprint:sha-256 {fp}\r\n\
             a=setup:actpass\r\n\
             a=mid:0\r\n\
             a=sendonly\r\n\
             a=rtcp-mux\r\n\
             a=msid:- cam\r\n\
             a=rtpmap:96 VP8/90000\r\n",
            fp = identity.fingerprint_sha256()
        )
    }

    /// Answer the runtime's subscriber offer: `recvonly` m-lines
    /// mirroring it, our ICE creds and cert fingerprint, `a=setup:active`
    /// (we are the DTLS client). The runtime only reads the ufrag and
    /// fingerprint today, but a browser-shaped answer keeps the fixture
    /// honest.
    fn subscriber_answer(identity: &DtlsIdentity, offer: &Offer, ufrag: &str, pwd: &str) -> String {
        let mut sdp = format!(
            "v=0\r\no=- 4343 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE {}\r\n",
            offer.bundle_mids().collect::<Vec<_>>().join(" ")
        );
        for m in &offer.media {
            sdp.push_str(&format!(
                "m={} 9 {} {}\r\n\
                 c=IN IP4 0.0.0.0\r\n\
                 a=rtcp:9 IN IP4 0.0.0.0\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:sha-256 {fp}\r\n\
                 a=setup:active\r\n\
                 a=mid:{mid}\r\n\
                 a=recvonly\r\n\
                 a=rtcp-mux\r\n",
                m.kind.as_str(),
                m.proto,
                m.formats.join(" "),
                fp = identity.fingerprint_sha256(),
                mid = m.mid.as_deref().unwrap_or("0"),
            ));
            for (pt, rm) in &m.rtpmaps {
                match &rm.params {
                    Some(p) => {
                        sdp.push_str(&format!("a=rtpmap:{pt} {}/{}/{p}\r\n", rm.codec, rm.clock))
                    }
                    None => sdp.push_str(&format!("a=rtpmap:{pt} {}/{}\r\n", rm.codec, rm.clock)),
                }
            }
        }
        sdp
    }

    /// One minimal valid RTP packet: V2, marker + PT96, seq/ts/ssrc,
    /// opaque payload bytes. Marker+PT96 puts byte 1 at 0xE0 — clear of
    /// the 192..=223 range the demux reserves for RTCP (RFC 5761).
    fn canned_rtp(seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(12 + payload.len());
        p.extend_from_slice(&[0x80, 0xE0]);
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&timestamp.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// The M0 media path, headless and end to end: peer B's publisher
    /// leg does a real STUN → DTLS → SRTP negotiation, publishes a video
    /// track, and peer A — joined earlier — gets the runtime's
    /// subscriber offer, answers it, negotiates its own leg, then
    /// receives B's forwarded RTP re-encrypted under A's keys.
    #[tokio::test]
    async fn fake_peers_media_path_end_to_end() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        // The real runtime on an ephemeral port — driven in-process so
        // its state stays inspectable once the loop exits.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let rt = Runtime::new(socket, ctl_rx, "127.0.0.1".to_string());
        let server_fingerprint = rt.identity.fingerprint_sha256().to_string();
        let runtime = tokio::spawn(async move {
            let mut rt = rt;
            rt.loop_forever().await;
            rt
        });

        // ── Both peers join (the signaling side) ────────────────────
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        ctl_tx
            .send(MediaControl::Joined {
                room: room.clone(),
                participant: "a".into(),
                reply: a_tx,
            })
            .unwrap();
        ctl_tx
            .send(MediaControl::Joined {
                room: room.clone(),
                participant: "b".into(),
                reply: b_tx,
            })
            .unwrap();

        // ── B's publisher leg: offer → answer → nominate → DTLS ─────
        let b_offer = publisher_offer(&b.identity, "bPubUfrag", "bPubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: b_offer,
            })
            .unwrap();
        let answer_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer = Offer::parse(&answer_sdp).expect("server answer parses");
        assert_eq!(
            answer.sha256_fingerprint().map(|f| f.value.as_str()),
            Some(server_fingerprint.as_str()),
            "the answer must carry the runtime's cert fingerprint"
        );
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        assert_eq!(
            b_pub.server, server_addr,
            "the advertised candidate is the socket we bound"
        );
        b_pub.nominate().await;
        b_pub.connect().await;

        // ── B publishes "cam"; the runtime re-offers A's sub leg ────
        ctl_tx
            .send(MediaControl::TracksPublished {
                room: room.clone(),
                participant: "b".into(),
                tracks: vec![proto::Track {
                    id: "cam".into(),
                    kind: proto::TrackKind::Video as i32,
                    source: proto::TrackSource::Camera as i32,
                    muted: false,
                    layers: Vec::new(),
                    mid: String::new(),
                }],
            })
            .unwrap();
        let offer_sdp = recv_sdp(
            &mut a.reply,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
        )
        .await;
        let sub_offer = Offer::parse(&offer_sdp).expect("subscriber offer parses");
        assert_eq!(
            sub_offer.sha256_fingerprint().map(|f| f.value.as_str()),
            Some(server_fingerprint.as_str())
        );
        assert_eq!(sub_offer.media.len(), 1, "one m-line per published track");
        assert_eq!(sub_offer.media[0].kind, MediaKind::Video);
        assert_eq!(sub_offer.media[0].direction, Direction::SendOnly);

        // A answers with its own ICE creds + cert fingerprint, then
        // brings its subscriber leg up over the wire.
        let a_answer = subscriber_answer(
            &a.identity,
            &sub_offer,
            "aSubUfrag",
            "aSubPwd0000123456789abcdef",
        );
        ctl_tx
            .send(MediaControl::SubscriberAnswer {
                room: room.clone(),
                participant: "a".into(),
                sdp: a_answer,
            })
            .unwrap();
        // Give on_sub_answer a beat to install the remote creds before
        // connectivity checks land (checks are legal earlier, this just
        // keeps the exercise order canonical).
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut a_sub = FakeLeg::new(&a.identity, "aSubUfrag", &sub_offer).await;
        a_sub.nominate().await;
        a_sub.connect().await;

        // ── B → runtime → A: canned RTP end to end ──────────────────
        // A packet sent while the server is still finishing its own
        // handshake side is legitimately dropped, so send a short burst
        // like a live encoder and keep whichever packet lands.
        const PAYLOAD: &[u8] = b"headless-e2e";
        const SSRC: u32 = 0xABCD_0001;
        let mut sent = Vec::new();
        let mut got = None;
        for seq in 1..=20u16 {
            let packet = canned_rtp(seq, 0x00C0_FFEE + u32::from(seq) * 3000, SSRC, PAYLOAD);
            b_pub.send_media(&packet).await;
            sent.push(packet);
            if let Some(plain) = a_sub.try_recv_media(Duration::from_millis(250)).await {
                got = Some(plain);
                break;
            }
        }
        let got = got.expect("no forwarded media arrived on A's sub leg");
        assert!(
            sent.iter().any(|p| p == &got),
            "forwarded plaintext is not one of the packets B sent"
        );
        let parsed = RtpPacket::parse(&got).expect("forwarded packet parses as RTP");
        assert_eq!(parsed.payload_type(), 96);
        assert_eq!(parsed.ssrc(), SSRC);
        assert!(parsed.marker());
        assert_eq!(parsed.payload(), PAYLOAD);

        // ── Control-plane view: both legs nominated (by_addr) and ───
        // ── keyed by server ufrag (by_ufrag), transports connected. ──
        drop(ctl_tx);
        let rt = timeout(Duration::from_secs(5), runtime)
            .await
            .expect("runtime loop exits when control closes")
            .expect("runtime task");
        let key_a_sub = TransportKey {
            room: room.clone(),
            participant: "a".into(),
            leg: Leg::Sub,
        };
        let key_b_pub = TransportKey {
            room: room.clone(),
            participant: "b".into(),
            leg: Leg::Pub,
        };
        assert_eq!(rt.by_addr.get(&a_sub.local_addr()), Some(&key_a_sub));
        assert_eq!(rt.by_addr.get(&b_pub.local_addr()), Some(&key_b_pub));
        assert_eq!(rt.by_ufrag.get(&a_sub.server_ufrag), Some(&key_a_sub));
        assert_eq!(rt.by_ufrag.get(&b_pub.server_ufrag), Some(&key_b_pub));
        assert!(rt.transports[&key_a_sub].is_connected());
        assert!(rt.transports[&key_b_pub].is_connected());
        let members = rt.rooms.get(&room).expect("room exists");
        assert_eq!(
            members["b"].published,
            vec![("cam".to_string(), MediaKind::Video)]
        );
    }
}
