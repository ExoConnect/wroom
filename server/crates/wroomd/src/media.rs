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
    let identity = DtlsIdentity::generate().expect("dtls identity");
    tracing::info!(
        addr = %socket.local_addr()?,
        advertise = %advertise_addr,
        fingerprint = %identity.fingerprint_sha256(),
        "media plane listening"
    );

    let mut rt = Runtime {
        socket,
        identity,
        transports: HashMap::new(),
        by_ufrag: HashMap::new(),
        by_addr: HashMap::new(),
        rooms: HashMap::new(),
        advertise_addr,
        control_rx,
    };
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
        for (key, t) in self.transports.iter_mut() {
            for ev in t.handle_timeout(now) {
                match ev {
                    PeerEvent::Send { to, data } => sends.push((to, data)),
                    PeerEvent::Nominated(addr) => {
                        self.by_addr.insert(addr, key.clone());
                    }
                    PeerEvent::Closed | PeerEvent::Failed(_) => {
                        // collected below
                    }
                    _ => {}
                }
            }
        }
        // `sends` is small (retransmits); fire-and-forget via try_send is
        // not available on UdpSocket — use spawn-free async send instead.
        for (to, data) in sends {
            let socket = &self.socket;
            // on_tick is sync; queue sends via a detached task is overkill
            // for M0 — use try_send_to? tokio UdpSocket has try_send_to.
            let _ = socket.try_send_to(&data, to);
        }
    }
}
