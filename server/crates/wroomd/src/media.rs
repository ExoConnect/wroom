//! The M0 media runtime: one UDP socket, per-connection transports,
//! forward-everything inside a room.
//!
//! Single task owns all forwarding state (`&mut`, no locks) — the
//! share-nothing shape the worker model formalizes (AGENTS §4). For M0
//! it runs on tokio; recvmmsg batching and pinned workers are M3 work.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant;

use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;
use nix::sys::eventfd::{EfdFlags, EventFd};
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

/// One offerable track: (owner pid, track id, kind). The owner names the
/// msid and the room-canonical mid — the same mid in every subscriber
/// offer for this track, so forwarded plaintext is byte-identical
/// across legs (rewrite happens once per packet, not per target).
type TrackRef = (String, String, MediaKind, String);

/// A track's identity on the wire: its kind + canonical mid bytes.
/// CanonMid is inline — no String work on the hot path.
#[derive(Clone, Copy)]
struct TrackTag {
    kind: u8,
    canon: CanonMid,
}

/// `m{pub_pid}.{m-line index}` — ≤16 bytes for pids under 10^6.
#[derive(Clone, Copy)]
struct CanonMid {
    buf: [u8; 16],
    len: u8,
}

impl CanonMid {
    fn new(pid: u32, idx: usize) -> Self {
        let mut c = CanonMid { buf: [0; 16], len: 0 };
        let s = format!("m{pid}.{idx}");
        let n = s.len().min(16);
        c.buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        c.len = n as u8;
        c
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}
/// One joined participant's media-plane state — shard-local copy.
struct MemberShard {
    /// Dense per-room id — the hot path keys by this, never by name.
    pid: u32,
    /// Channel back to their signaling socket (offers/answers).
    reply: mpsc::Sender<ServerMessage>,
    /// Monotonic session version for their subscriber-leg re-offers.
    sub_offer_version: u64,
    /// Their publisher offer's `a=mid` → the track's identity (kind +
    /// canonical mid). m-line order == published-track order — the
    /// client's TracksPublished follows its transceiver order.
    mid_track: HashMap<String, TrackTag>,
    /// SSRC → track identity, learned when a packet carries its mid —
    /// covers sources that stop emitting mid mid-stream. Bounded at 8.
    /// Also the PLI key set.
    ssrc_map: HashMap<u32, TrackTag>,
}

/// The slice of a room this shard owns: its own members' legs plus the
/// global pid table and resolved wants needed to compute local fan-out.
struct RoomShard {
    name: String,
    /// Every member's name → pid — fan-out tables index by pub pid,
    /// which needs the whole room's ids.
    pids: HashMap<String, u32>,
    /// This shard's own members (legs, mids, ssrcs live here).
    locals: HashMap<String, MemberShard>,
    /// Every member's resolved want-set: pid → (pub_pid, kind) pairs;
    /// `None` = never subscribed = wants all.
    wants: HashMap<u32, Option<HashSet<(u32, u8)>>>,
    /// Per-publisher shard mask: bit j = shard j has ≥1 target.
    /// Computed locally on every rebuild — no router round-trip.
    demand: HashMap<u32, (u64, u64)>,
    /// Demand-filtered local fan-out: only this shard's members appear.
    fanout_v: Vec<Vec<TransportKey>>,
    fanout_a: Vec<Vec<TransportKey>>,
    fanout_any: Vec<Vec<TransportKey>>,
    /// High-water pid for sizing the tables.
    max_pid: u32,
}

impl RoomShard {
    /// Rebuild local fan-out + demand masks from the global want table.
    /// O(members²) cold path — join/leave/subscription/publish only.
    fn rebuild_fanout(&mut self, n_shards: usize) {
        let n = self.max_pid as usize;
        self.fanout_v.clear();
        self.fanout_a.clear();
        self.fanout_any.clear();
        self.fanout_v.resize_with(n, Vec::new);
        self.fanout_a.resize_with(n, Vec::new);
        self.fanout_any.resize_with(n, Vec::new);
        self.demand.clear();
        // Single pass: mask bits for every shard holding a target, and
        // fan-out entries only for this shard's own members.
        for (tname, tpid) in &self.pids {
            let w = self.wants.get(tpid).and_then(|o| o.clone());
            let local = self.locals.contains_key(tname);
            let target_shard = (*tpid as usize) % n_shards;
            for ppid in self.pids.values() {
                if *ppid == *tpid {
                    continue;
                }
                let (v, a) = match &w {
                    None => (true, true),
                    Some(w) => (
                        w.contains(&(*ppid, kind_u8(&MediaKind::Video))),
                        w.contains(&(*ppid, kind_u8(&MediaKind::Audio))),
                    ),
                };
                if !(v || a) {
                    continue;
                }
                let m = self.demand.entry(*ppid).or_insert((0, 0));
                if v {
                    m.0 |= 1u64 << target_shard;
                }
                if a {
                    m.1 |= 1u64 << target_shard;
                }
                if local {
                    let tk = TransportKey {
                        room: self.name.clone(),
                        participant: tname.clone(),
                        leg: Leg::Sub,
                    };
                    if v {
                        self.fanout_v[*ppid as usize].push(tk.clone());
                    }
                    if a {
                        self.fanout_a[*ppid as usize].push(tk.clone());
                    }
                    self.fanout_any[*ppid as usize].push(tk);
                }
            }
        }
    }
}

/// Dense kind for map keys — audio/video are the only media tracks today.
fn kind_u8(k: &MediaKind) -> u8 {
    match k {
        MediaKind::Audio => 1,
        _ => 2,
    }
}

/// A decrypted packet crossing a shard boundary: the plaintext plus the
/// routing the source shard already computed. Inline 2KB payload — the
/// bounded ring moves slots by value, no allocation per packet.
struct FwdMsg {
    room_id: u32,
    /// Source member's pid — for `RTCP_BACK`, also the member excluded
    /// from pub-leg targets.
    src_pid: u32,
    kind: u8,
    len: u16,
    t0: Instant,
    buf: [u8; 2048],
}

mod fwd_kind {
    pub const AUDIO: u8 = 1;
    pub const VIDEO: u8 = 2;
    /// Subscriber RTCP back to publishers (NACK/PLI/RR).
    pub const RTCP_BACK: u8 = 3;
    /// "New subscriber leg connected" — every pub shard PLIs its locals.
    pub const PLI_ALL: u8 = 4;
    /// Publisher RTCP (sender reports) → the union of interested subs.
    pub const RTCP_FWD: u8 = 5;
}

/// A shard's control inbox: bounded queue + doorbell. The shard polls
/// the doorbell in the same epoll-style wait as its socket.
#[derive(Clone)]
struct ShardCtlQ {
    q: Arc<ArrayQueue<ShardCtl>>,
    efd: Arc<EventFd>,
}

impl ShardCtlQ {
    fn send(&self, m: ShardCtl) {
        if self.q.push(m).is_ok() {
            let _ = self.efd.write(1);
        } else {
            // Control messages must never be silently lost — a full queue
            // means a wedged shard, which is a bug, not backpressure.
            tracing::error!("shard control queue full — message dropped");
        }
    }
}

/// A room's resolved subscription table: pid → want-set (None = all).
type WantsTable = Vec<(u32, Option<HashSet<(u32, u8)>>)>;

/// Control deltas the router pushes to a shard — each shard keeps its own
/// copy of whatever it needs; nothing is shared mutable state.
enum ShardCtl {
    Shutdown,
    /// Room registered — broadcast to all shards.
    RoomUp { room_id: u32, room: String },
    /// A member joined. `reply` is Some only on their home shard — all
    /// shards learn name→pid for fan-out indexing.
    MemberUp {
        room_id: u32,
        name: String,
        pid: u32,
        reply: Option<mpsc::Sender<ServerMessage>>,
    },
    MemberGone { room_id: u32, name: String },
    /// A member's resolved want-set — broadcast; shards compute their own
    /// demand masks and local fan-out from the global picture.
    /// The room's whole resolved want-table — one message, not N.
    WantsAll {
        room_id: u32,
        table: WantsTable,
    },
    /// Publisher-leg SDP offer — home shard answers it.
    PubOffer {
        room_id: u32,
        name: String,
        sdp: String,
    },
    /// Subscriber-leg SDP answer — home shard applies it.
    SubAnswer {
        room_id: u32,
        name: String,
        sdp: String,
    },
    /// (Re)build this member's subscriber offer with this track list —
    /// home shard owns the transport, mids, and socket address.
    OfferSub {
        room_id: u32,
        name: String,
        tracks: Vec<TrackRef>,
    },
}

/// Runs the media plane until the control channel closes: a room-state
/// router plus `shards` worker tasks, each with its own UDP socket —
/// per-shard sockets give independent kernel TX queues, which is where
/// the real send parallelism lives.
pub async fn run(
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    media_port: u16,
    advertise_addr: String,
    shards: usize,
) -> std::io::Result<()> {
    spawn_plane(control_rx, media_port, advertise_addr, shards.clamp(1, 64)).await?;
    Ok(())
}

/// Build + spawn the whole plane; returns the shard thread handles
/// (tests inspect the finished shards' counters).
async fn spawn_plane(
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    media_port: u16,
    advertise_addr: String,
    n_shards: usize,
) -> std::io::Result<Vec<std::thread::JoinHandle<Shard>>> {
    // One bounded plaintext ring + doorbell per shard — all sources push.
    let rings: Vec<Arc<ArrayQueue<FwdMsg>>> = (0..n_shards)
        .map(|_| Arc::new(ArrayQueue::new(512)))
        .collect();
    let fwd_efds: Vec<Arc<EventFd>> = (0..n_shards)
        .map(|_| Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap()))
        .collect();

    let mut ctl_qs = Vec::with_capacity(n_shards);
    let mut handles = Vec::with_capacity(n_shards);
    for id in 0..n_shards {
        // port 0 → ephemeral (tests); production shards take port + id.
        let port = if media_port == 0 { 0 } else { media_port + id as u16 };
        let socket = media_socket(([0, 0, 0, 0], port).into())?;
        let ctl = ShardCtlQ {
            q: Arc::new(ArrayQueue::new(1024)),
            efd: Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap()),
        };
        ctl_qs.push(ctl.clone());
        let mut shard = Shard::new(
            id,
            n_shards,
            socket,
            ctl,
            rings[id].clone(),
            rings.clone(),
            fwd_efds.clone(),
            advertise_addr.clone(),
        );
        // Dedicated OS thread — the shard polls socket + rings directly;
        // no async scheduler latency on the media path.
        handles.push(
            std::thread::Builder::new()
                .name(format!("wroom-shard{id}"))
                .spawn(move || {
                    shard.run_loop();
                    shard
                })
                .expect("spawn shard thread"),
        );
    }
    let mut router = Router::new(control_rx, ctl_qs, n_shards);
    tokio::spawn(async move { router.run().await });
    Ok(handles)
}

/// The media socket with a deep kernel receive queue — the default
/// SO_RCVBUF (~200KB) drops under multi-publisher bursts well below our
/// forwarding capacity. 16MB absorbs a ~10k-packet burst of ~1.4KB datagrams.
/// The media socket with a deep kernel receive queue — the default
/// SO_RCVBUF (~200KB) drops under multi-publisher bursts well below our
/// forwarding capacity. 16MB absorbs a ~10k-packet burst of ~1.4KB datagrams.
/// The media socket with a deep kernel receive queue — the default
/// SO_RCVBUF (~200KB) drops under multi-publisher bursts well below our
/// forwarding capacity. 16MB absorbs a ~10k-packet burst of ~1.4KB datagrams.
fn media_socket(addr: std::net::SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        None,
    )?;
    sock.set_recv_buffer_size(16 * 1024 * 1024)?;
    // Send side too: a 512-target sendmmsg batch of ~1KB datagrams needs
    // ~512KB of kernel queue — default ~212KB truncates batches at ~64.
    sock.set_send_buffer_size(16 * 1024 * 1024)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

// ── Shard: one worker's legs, socket, and local fan-out ──────────────

struct Shard {
    id: usize,
    n_shards: usize,
    socket: UdpSocket,
    identity: DtlsIdentity,
    transports: HashMap<TransportKey, PeerTransport>,
    /// Pre-nomination routing: STUN USERNAME local part → transport.
    by_ufrag: HashMap<String, TransportKey>,
    /// Post-nomination routing: remote 5-tuple → transport.
    by_addr: HashMap<SocketAddr, TransportKey>,
    /// This shard's room slices, keyed by router-assigned id.
    rooms: HashMap<u32, RoomShard>,
    /// room name → id (filled by RoomUp).
    room_ids: HashMap<String, u32>,
    /// Inbound plaintext ring (all source shards push here).
    fwd_rx: Arc<ArrayQueue<FwdMsg>>,
    /// Every shard's inbound ring + doorbell — this shard pushes to
    /// others; own index unused.
    fwd_txs: Vec<Arc<ArrayQueue<FwdMsg>>>,
    fwd_efds: Vec<Arc<EventFd>>,
    /// Debug counters: decrypted inbound media / forwarded outbound media.
    media_in: u64,
    forwarded: u64,
    /// Forwarding residence histogram (recv→send), buckets in µs:
    /// <50, <100, <250, <500, <1000, <2000, <5000, ≥5000.
    res_buckets: [u64; 8],
    res_max_ns: u64,
    res_sum_ns: u64,
    /// Kernel send-queue drops (sendmmsg tail retries exhausted) and
    /// inter-shard ring drops (consumer shard overloaded).
    send_drops: u64,
    ring_drops: u64,
    /// Targets skipped because no transport was nominated yet.
    skip_no_transport: u64,
    /// Packets that entered fan-out — residence samples are per-packet,
    /// so the mean divides by this, not by `forwarded`.
    res_packets: u64,
    /// Per-stage attribution (ns) — where residence actually goes.
    prof_decrypt_ns: u64,
    prof_parse_ns: u64,
    prof_lookup_ns: u64,
    prof_crypto_ns: u64,
    prof_send_ns: u64,
    /// Reused per-datagram event buffer — no alloc on the media path.
    events: Vec<PeerEvent>,
    /// Reused protect + rewrite scratch — allocated once at init.
    scratch_out: Box<[u8; 2048]>,
    /// Batched-send arena: MAX_FANOUT ciphertext slots, one sendmmsg
    /// per inbound packet instead of one syscall per target.
    batch: Vec<u8>,
    /// sendmmsg destination addresses + per-msg lengths, reused per
    /// packet. (The mmsghdr block itself is `!Send` — `*mut c_void` —
    /// so it's allocated per call inside `fanout_send`, which awaits
    /// nothing while it lives.)
    mmsg_addrs: Vec<Option<nix::sys::socket::SockaddrStorage>>,
    mmsg_lens: Vec<usize>,
    advertise_addr: String,
    ctl: ShardCtlQ,
}

impl Shard {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: usize,
        n_shards: usize,
        socket: UdpSocket,
        ctl: ShardCtlQ,
        fwd_rx: Arc<ArrayQueue<FwdMsg>>,
        fwd_txs: Vec<Arc<ArrayQueue<FwdMsg>>>,
        fwd_efds: Vec<Arc<EventFd>>,
        advertise_addr: String,
    ) -> Self {
        let identity = DtlsIdentity::generate().expect("dtls identity");
        tracing::info!(
            shard = id,
            addr = ?socket.local_addr(),
            advertise = %advertise_addr,
            fingerprint = %identity.fingerprint_sha256(),
            "media shard listening"
        );
        Self {
            id,
            n_shards,
            socket,
            identity,
            transports: HashMap::new(),
            by_ufrag: HashMap::new(),
            by_addr: HashMap::new(),
            rooms: HashMap::new(),
            room_ids: HashMap::new(),
            fwd_rx,
            fwd_txs,
            fwd_efds,
            media_in: 0,
            forwarded: 0,
            res_buckets: [0; 8],
            res_max_ns: 0,
            res_sum_ns: 0,
            send_drops: 0,
            ring_drops: 0,
            skip_no_transport: 0,
            res_packets: 0,
            prof_decrypt_ns: 0,
            prof_parse_ns: 0,
            prof_lookup_ns: 0,
            prof_crypto_ns: 0,
            prof_send_ns: 0,
            events: Vec::with_capacity(16),
            scratch_out: Box::new([0u8; 2048]),
            batch: vec![0u8; 512 * 2048],
            mmsg_addrs: Vec::with_capacity(512),
            mmsg_lens: Vec::with_capacity(512),
            advertise_addr,
            ctl,
        }
    }

    /// The shard's whole life: poll socket + plaintext ring + control
    /// doorbell on one thread — no scheduler between arrival and forward.
    fn run_loop(&mut self) {
        let mut buf = vec![0u8; 2048].into_boxed_slice();
        // Poll-safe handles owned by this loop — borrowing `self` here
        // would block every `&mut self` call inside the loop.
        let Ok(poll_sock) = self.socket.try_clone() else {
            return;
        };
        let fwd_efd = self.fwd_efds[self.id].clone();
        let ctl_efd = self.ctl.efd.clone();
        let mut fds = [
            nix::poll::PollFd::new(poll_sock.as_fd(), nix::poll::PollFlags::POLLIN),
            nix::poll::PollFd::new(fwd_efd.as_fd(), nix::poll::PollFlags::POLLIN),
            nix::poll::PollFd::new(ctl_efd.as_fd(), nix::poll::PollFlags::POLLIN),
        ];
        let mut next_tick = Instant::now() + std::time::Duration::from_millis(20);
        let mut efd_buf = [0u8; 8];
        loop {
            // Fair scheduler: alternate one unit of work from each source
            // (ring, socket, control) so no queue starves another — every
            // item is a full fan-out, so ordering IS latency. Poll only
            // when all three are empty.
            // Ring items have already paid a hop — drain them first
            // (bounded); socket datagrams wait in the 16MB kernel queue.
            let mut busy = false;
            for _ in 0..32 {
                match self.fwd_rx.pop() {
                    Some(m) => {
                        self.on_fwd(m);
                        busy = true;
                    }
                    None => break,
                }
            }
            if let Ok((n, from)) = self.socket.recv_from(&mut buf) {
                self.on_datagram(&mut buf[..n], from);
                busy = true;
            }
            while let Some(c) = self.ctl.q.pop() {
                if !self.on_control(c) {
                    return;
                }
            }
            if busy {
                continue;
            }
            let now = Instant::now();
            let ms = next_tick
                .checked_duration_since(now)
                .map(|d| d.as_millis() as i32)
                .unwrap_or(0);
            let n = match nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(ms.max(0) as u16)) {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 {
                self.on_tick();
                next_tick = Instant::now() + std::time::Duration::from_millis(20);
                continue;
            }
            // Doorbells: clear the counters; queues drain next pass.
            for fd in &mut fds[1..] {
                if fd
                    .revents()
                    .is_some_and(|r| r.contains(nix::poll::PollFlags::POLLIN))
                {
                    let _ = nix::unistd::read(fd.as_fd(), &mut efd_buf);
                }
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
    fn on_datagram(&mut self, buf: &mut [u8], from: SocketAddr) {
        // Residence clock: received-datagram → emitted-datagram (D12).
        let t0 = Instant::now();
        let key = if let Some(k) = self.by_addr.get(&from) {
            Some(k.clone())
        } else if is_stun_datagram(buf) {
            // Pre-nomination: the USERNAME's local half names the
            // transport ("localufrag:remoteufrag", RFC 8445).
            match Message::parse(buf) {
                Err(e) => {
                    tracing::debug!(%from, error = %e, "stun parse failed");
                    None
                }
                Ok(m) => {
                    let u = m
                        .get(wroom_edge::ice::attr::USERNAME)
                        .and_then(|a| std::str::from_utf8(a.value).ok())
                        .map(str::to_owned);
                    match u {
                        None => {
                            tracing::debug!(%from, "stun without username");
                            None
                        }
                        Some(u) => {
                            let local = u.split(':').next().unwrap_or("");
                            match self.by_ufrag.get(local) {
                                Some(k) => Some(k.clone()),
                                None => {
                                    tracing::debug!(%from, username = %u, "no transport for ufrag");
                                    None
                                }
                            }
                        }
                    }
                }
            }
        } else {
            None
        };
        let Some(key) = key else {
            tracing::debug!(%from, len = buf.len(), stun = is_stun_datagram(buf), "unrouted datagram");
            return;
        };
        {
            let Some(t) = self.transports.get_mut(&key) else {
                return;
            };
            // Disjoint field borrows: `t` borrows transports, the event
            // buffer is a separate field — the media path never allocs.
            let td = Instant::now();
            t.handle_datagram(buf, from, Instant::now(), &mut self.events);
            self.prof_decrypt_ns += td.elapsed().as_nanos() as u64;
        }
        self.apply_events(key, buf, t0);
    }

    fn apply_events(&mut self, key: TransportKey, buf: &[u8], t0: Instant) {
        for i in 0..self.events.len() {
            // Swap each event out of the reused buffer without moving the
            // vec — Closed is the no-op placeholder.
            let ev = std::mem::replace(&mut self.events[i], PeerEvent::Closed);
            match ev {
                PeerEvent::Send { to, data } => {
                    let _ = self.socket.send_to(&data, to);
                }
                PeerEvent::Nominated(addr) => {
                    tracing::info!(%addr, participant = %key.participant, leg = ?key.leg, "ICE nominated");
                    self.by_addr.insert(addr, key.clone());
                }
                PeerEvent::Connected => {
                    tracing::info!(
                        room = %key.room,
                        participant = %key.participant,
                        leg = ?key.leg,
                        shard = self.id,
                        "peer transport connected"
                    );
                    // New subscriber leg: every pub shard PLIs its local
                    // publishers so the joiner decodes fast.
                    if key.leg == Leg::Sub
                        && let Some(room_id) = self.room_ids.get(&key.room).copied()
                    {
                        let new_pid = self
                            .rooms
                            .get(&room_id)
                            .and_then(|r| r.locals.get(&key.participant))
                            .map(|m| m.pid)
                            .unwrap_or(u32::MAX);
                        self.pli_local_pubs(room_id, new_pid);
                        self.broadcast(FwdMsg {
                            room_id,
                            src_pid: new_pid,
                            kind: fwd_kind::PLI_ALL,
                            len: 0,
                            t0,
                            buf: [0u8; 2048],
                        });
                    }
                }
                PeerEvent::Media { len, rtcp } => {
                    self.media_in += 1;
                    if self.media_in % 500 == 1 {
                        tracing::debug!(
                            shard = self.id,
                            total = self.media_in,
                            participant = %key.participant,
                            leg = ?key.leg,
                            "media decrypted"
                        );
                    }
                    let plain = &buf[..len];
                    if rtcp {
                        if key.leg == Leg::Pub {
                            // Publisher sender reports → demanded subs.
                            self.fanout_rtcp(&key, plain, t0);
                        } else if key.leg == Leg::Sub
                            && let Some(room_id) = self.room_ids.get(&key.room).copied()
                        {
                            // Subscriber feedback → this shard's local pub
                            // legs plus the same fan-out on every shard.
                            let src_pid = self
                                .rooms
                                .get(&room_id)
                                .and_then(|r| r.locals.get(&key.participant))
                                .map(|m| m.pid)
                                .unwrap_or(u32::MAX);
                            self.forward_to_pubs_local(room_id, src_pid, plain)
                                ;
                            let mut m = FwdMsg {
                                room_id,
                                src_pid,
                                kind: fwd_kind::RTCP_BACK,
                                len: len as u16,
                                t0,
                                buf: [0u8; 2048],
                            };
                            m.buf[..len].copy_from_slice(plain);
                            self.broadcast(m);
                        }
                    } else if key.leg == Leg::Pub {
                        self.fanout_start(&key, plain, t0);
                    }
                }
                PeerEvent::Failed(reason) => {
                    tracing::warn!(participant = %key.participant, leg = ?key.leg, %reason, "peer transport failed");
                    self.drop_transport(&key);
                }
                PeerEvent::Closed => {
                    self.drop_transport(&key);
                }
            }
        }
    }

    /// A sibling shard handed us plaintext — fan it out to OUR local
    /// targets only. Crypto + send happen here, on the owner thread.
    fn on_fwd(&mut self, m: FwdMsg) {
        let plain = &m.buf[..m.len as usize];
        match m.kind {
            k if k == fwd_kind::RTCP_BACK => {
                // Subscriber feedback → our local publisher legs.
                self.forward_to_pubs_local(m.room_id, m.src_pid, plain)
            }
            k if k == fwd_kind::PLI_ALL => {
                // New-subscriber nudge → PLI our local publishers.
                self.pli_local_pubs(m.room_id, m.src_pid)
            }
            k if k == fwd_kind::RTCP_FWD => {
                self.fanout_send(m.room_id, m.src_pid, None, plain, m.t0)
            }
            k => self.fanout_send(m.room_id, m.src_pid, Some(k), plain, m.t0),
        }
    }

    /// Clone-and-push onto shard j's ring, then ring its doorbell.
    /// A full ring drops the packet — bounded queues, counted.
    fn push_shard(&mut self, j: usize, m: &FwdMsg) {
        if self.fwd_txs[j].push(clone_msg(m)).is_ok() {
            let _ = self.fwd_efds[j].write(1);
        } else {
            self.ring_drops += 1;
        }
    }

    /// Push a message to every OTHER shard's ring (RTCP-back, PLI-all).
    fn broadcast(&mut self, m: FwdMsg) {
        for j in 0..self.n_shards {
            if j != self.id {
                self.push_shard(j, &m);
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

    /// PLI every local publisher's known SSRCs — the new-subscriber
    /// keyframe nudge, scoped to this shard's legs.
    fn pli_local_pubs(&mut self, room_id: u32, exclude_pid: u32) {
        let Some(room) = self.rooms.get(&room_id) else {
            return;
        };
        let mut pkt = [0u8; 64];
        let jobs: Vec<(TransportKey, Vec<u32>)> = room
            .locals
            .iter()
            .filter(|(_, m)| m.pid != exclude_pid && !m.ssrc_map.is_empty())
            .map(|(name, m)| {
                (
                    TransportKey {
                        room: room.name.clone(),
                        participant: name.clone(),
                        leg: Leg::Pub,
                    },
                    m.ssrc_map.keys().copied().collect(),
                )
            })
            .collect();
        for (tk, ssrcs) in jobs {
            let Some(t) = self.transports.get_mut(&tk) else {
                continue;
            };
            for ssrc in ssrcs {
                if let Ok(n) = wroom_edge::rtcp::Pli::build(&mut pkt, 0, ssrc)
                    && let Some((to, m)) = t.protect_rtcp(&pkt[..n], &mut self.scratch_out[..128])
                {
                    let _ = self.socket.send_to(&self.scratch_out[..m], to);
                }
            }
        }
    }

    /// Returns false when the control channel is gone → shard exits.
    fn on_control(&mut self, ctl: ShardCtl) -> bool {
        match ctl {
            ShardCtl::RoomUp { room_id, room } => {
                self.room_ids.insert(room.clone(), room_id);
                self.rooms.entry(room_id).or_insert_with(|| RoomShard {
                    name: room,
                    pids: HashMap::new(),
                    locals: HashMap::new(),
                    wants: HashMap::new(),
                    demand: HashMap::new(),
                    fanout_v: Vec::new(),
                    fanout_a: Vec::new(),
                    fanout_any: Vec::new(),
                    max_pid: 0,
                });
            }
            ShardCtl::MemberUp {
                room_id,
                name,
                pid,
                reply,
            } => {
                let Some(r) = self.rooms.get_mut(&room_id) else {
                    return true;
                };
                r.pids.insert(name.clone(), pid);
                r.wants.insert(pid, None);
                r.max_pid = r.max_pid.max(pid + 1);
                if let Some(reply) = reply {
                    r.locals.insert(
                        name.clone(),
                        MemberShard {
                            pid,
                            reply,
                            sub_offer_version: 0,
                            mid_track: HashMap::new(),
                            ssrc_map: HashMap::new(),
                        },
                    );
                }
                r.rebuild_fanout(self.n_shards);
            }
            ShardCtl::MemberGone { room_id, name } => {
                let room_name = self.rooms.get(&room_id).map(|r| r.name.clone());
                if let Some(rn) = room_name {
                    for leg in [Leg::Pub, Leg::Sub] {
                        self.drop_transport(&TransportKey {
                            room: rn.clone(),
                            participant: name.clone(),
                            leg,
                        });
                    }
                }
                if let Some(r) = self.rooms.get_mut(&room_id) {
                    if let Some(pid) = r.pids.remove(&name) {
                        r.locals.remove(&name);
                        r.wants.remove(&pid);
                    }
                    r.rebuild_fanout(self.n_shards);
                }
            }
            ShardCtl::WantsAll { room_id, table } => {
                if let Some(r) = self.rooms.get_mut(&room_id) {
                    for (pid, wants) in table {
                        r.wants.insert(pid, wants);
                    }
                    r.rebuild_fanout(self.n_shards);
                }
            }
            ShardCtl::PubOffer {
                room_id,
                name,
                sdp,
            } => {
                self.on_pub_offer(room_id, &name, &sdp);
            }
            ShardCtl::SubAnswer {
                room_id,
                name,
                sdp,
            } => self.on_sub_answer(room_id, &name, &sdp),
            ShardCtl::OfferSub {
                room_id,
                name,
                tracks,
            } => {
                self.offer_subscriber(room_id, &name, &tracks);
            }
            ShardCtl::Shutdown => return false,
        }
        true
    }

    /// Publisher offer arrived: create the transport and answer it.
    fn on_pub_offer(&mut self, room_id: u32, name: &str, sdp: &str) {
        let offer = match Offer::parse(sdp) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(participant = name, error = %e, "bad publisher offer");
                return;
            }
        };
        // Their offer's mid → canonical track identity. m-line order is
        // the track index (published order follows transceiver order).
        if let Some(r) = self.rooms.get_mut(&room_id)
            && let Some(m) = r.locals.get_mut(name)
        {
            let pid = m.pid;
            m.mid_track = offer
                .media
                .iter()
                .enumerate()
                .filter_map(|(i, md)| {
                    md.mid.clone().map(|mid| {
                        (
                            mid,
                            TrackTag {
                                kind: kind_u8(&md.kind),
                                canon: CanonMid::new(pid, i),
                            },
                        )
                    })
                })
                .collect();
        }
        let Some(room_name) = self.rooms.get(&room_id).map(|r| r.name.clone()) else {
            return;
        };
        let key = TransportKey {
            room: room_name,
            participant: name.to_string(),
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
                tracing::warn!(participant = name, error = %e, "answer build failed");
                return;
            }
        };
        self.by_ufrag
            .insert(t.local_ufrag().to_string(), key.clone());
        self.transports.insert(key, t);
        self.send_sdp(
            name,
            room_id,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
            answer.into_string(),
        );
    }

    /// Subscriber answer arrived: finish their sub-leg transport (it was
    /// created when we offered, remote creds now known).
    fn on_sub_answer(&mut self, room_id: u32, name: &str, sdp: &str) {
        let answer = match Offer::parse(sdp) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(participant = name, error = %e, "bad subscriber answer");
                return;
            }
        };
        let Some(room_name) = self.rooms.get(&room_id).map(|r| r.name.clone()) else {
            return;
        };
        let key = TransportKey {
            room: room_name,
            participant: name.to_string(),
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
    /// `tracks` is (owner name, track id, kind); the offer's sequential
    /// mids become that member's `sub_mids` keys for the rewrite.
    fn offer_subscriber(&mut self, room_id: u32, name: &str, tracks: &[TrackRef]) {
        let Some(room_name) = self.rooms.get(&room_id).map(|r| r.name.clone()) else {
            return;
        };
        let key = TransportKey {
            room: room_name,
            participant: name.to_string(),
            leg: Leg::Sub,
        };
        let fingerprint =
            Fingerprint::sha256(self.identity.fingerprint_sha256().to_string());
        let candidates = self.our_candidates();
        let version = {
            let Some(r) = self.rooms.get_mut(&room_id) else {
                return;
            };
            let Some(m) = r.locals.get_mut(name) else {
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
            .map(|(owner, id, kind, canon)| OfferedMedia {
                mid: canon.clone(),
                kind: kind.clone(),
                // msid namespaced by owner — browsers publish colliding
                // track ids ("mic"/"cam"); Chrome rejects duplicate msids.
                msid_track: format!("{owner}/{id}"),
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
                tracing::warn!(participant = name, error = %e, "subscriber offer failed");
                return;
            }
        };
        self.send_sdp(
            name,
            room_id,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
            offer,
        );
    }

    /// Push a SessionDescription to a participant's signaling socket.
    fn send_sdp(
        &self,
        name: &str,
        room_id: u32,
        target: proto::SignalTarget,
        ty: proto::session_description::Type,
        sdp: String,
    ) {
        let Some(reply) = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.locals.get(name))
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
            tracing::warn!(participant = name, "reply queue full; SDP dropped");
        }
    }

    /// The extmap all legs negotiate — Chrome's canonical ids; our offers
    /// emit the same, so in/out maps are identical today.
    fn leg_extmap() -> &'static wroom_edge::rtp::ExtMap {
        use wroom_edge::rtp::{ExtMap, KnownExt};
        static MAP: std::sync::OnceLock<ExtMap> = std::sync::OnceLock::new();
        MAP.get_or_init(|| {
            ExtMap::from_pairs(&[
                (1, KnownExt::AudioLevel),
                (2, KnownExt::AbsSendTime),
                (3, KnownExt::Twcc),
                (4, KnownExt::Mid),
                (10, KnownExt::Rid),
            ])
        })
    }

    /// Source shard side of media fan-out: classify once, send to local
    /// targets inline, hand the plaintext to every shard whose demand
    /// mask bit is set for this publisher+kind.
    fn fanout_start(&mut self, key: &TransportKey, plain: &[u8], t0: Instant) {
        let Some(&room_id) = self.room_ids.get(&key.room) else {
            return;
        };
        let tp = Instant::now();
        // Which track is this packet? mid ext → the publisher's
        // mid→canonical-tag map; fall back to the learned ssrc→tag map
        // (Chrome stops emitting mid mid-stream), then payload type for
        // single-track-per-kind publishers.
        let hdr = wroom_edge::rtp::RtpPacket::parse(plain).ok();
        let tag = hdr
            .as_ref()
            .and_then(|h| {
                h.mid(Self::leg_extmap())
                    .and_then(|m| std::str::from_utf8(m).ok())
                    .and_then(|m| {
                        self.rooms
                            .get(&room_id)
                            .and_then(|r| r.locals.get(&key.participant))
                            .and_then(|mm| mm.mid_track.get(m))
                            .copied()
                    })
                    .or_else(|| {
                        // mid absent → ssrc-learned identity
                        self.rooms
                            .get(&room_id)
                            .and_then(|r| r.locals.get(&key.participant))
                            .and_then(|mm| mm.ssrc_map.get(&h.ssrc()))
                            .copied()
                    })
                    .or_else(|| {
                        // Single matching-kind track → unambiguous.
                        let pt = h.payload_type();
                        let mm = self
                            .rooms
                            .get(&room_id)?
                            .locals
                            .get(&key.participant)?;
                        let want_kind = if pt == 111 { 1u8 } else { 2u8 };
                        let mut it =
                            mm.mid_track.values().filter(|t| t.kind == want_kind);
                        match (it.next(), it.next()) {
                            (Some(t), None) => Some(*t),
                            _ => None,
                        }
                    })
            });
        let Some(tag) = tag else {
            self.skip_no_transport += 1;
            return;
        };
        let kind = tag.kind;
        self.prof_parse_ns += tp.elapsed().as_nanos() as u64;
        let Some(src_pid) = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.locals.get(&key.participant))
            .map(|m| m.pid)
        else {
            return;
        };
        // Learn ssrc→tag for the mid-absent stretch + PLI key set.
        if let Some(h) = &hdr
            && let Some(r) = self.rooms.get_mut(&room_id)
            && let Some(m) = r.locals.get_mut(&key.participant)
            && m.ssrc_map.len() < 8
        {
            m.ssrc_map.insert(h.ssrc(), tag);
        }
        // Canonicalize the mid ONCE per packet — every leg then receives
        // byte-identical plaintext; per-target work is encrypt+send only.
        let mut cbuf = [0u8; 2048];
        let fixed: &[u8] = match &hdr {
            Some(h)
                if h.mid(Self::leg_extmap()) != Some(tag.canon.as_bytes()) =>
            {
                let rw = wroom_edge::rtp::Rewrite {
                    in_map: Self::leg_extmap(),
                    out_map: Self::leg_extmap(),
                    sequence_number: h.sequence_number(),
                    timestamp: h.timestamp(),
                    ssrc: h.ssrc(),
                    twcc_seq: None,
                    payload_type: None,
                    mid: Some(tag.canon.as_bytes()),
                };
                match h.rewrite_into(&mut cbuf, &rw) {
                    Ok(n) => &cbuf[..n],
                    Err(_) => plain,
                }
            }
            _ => plain,
        };
                // Local targets first.
        self.fanout_send(room_id, src_pid, Some(kind), fixed, t0);
        // Remote shards: the demand mask says which have any targets.
        let Some(mask) = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.demand.get(&src_pid))
            .copied()
        else {
            return;
        };
        let mut m = if kind == kind_u8(&MediaKind::Audio) {
            mask.1
        } else {
            mask.0
        };
        m &= !(1u64 << self.id);
        if m == 0 {
            return;
        }
        if fixed.len() > 2048 {
            return;
        }
        let mut msg = FwdMsg {
            room_id,
            src_pid,
            kind: if kind == kind_u8(&MediaKind::Audio) {
                fwd_kind::AUDIO
            } else {
                fwd_kind::VIDEO
            },
            len: fixed.len() as u16,
            t0,
            buf: [0u8; 2048],
        };
        msg.buf[..fixed.len()].copy_from_slice(fixed);
        for j in 0..self.n_shards {
            if m & (1u64 << j) != 0 {
                self.push_shard(j, &msg);
            }
        }
    }

    /// Publisher RTCP → local any-table plus every shard with any
    /// interested member (union of the kind masks).
    fn fanout_rtcp(&mut self, key: &TransportKey, plain: &[u8], t0: Instant) {
        let Some(&room_id) = self.room_ids.get(&key.room) else {
            return;
        };
        let Some(src_pid) = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.pids.get(&key.participant))
            .copied()
        else {
            return;
        };
        self.fanout_send(room_id, src_pid, None, plain, t0);
        let Some(mask) = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.demand.get(&src_pid))
            .copied()
        else {
            return;
        };
        let m = (mask.0 | mask.1) & !(1u64 << self.id);
        if m == 0 || plain.len() > 2048 {
            return;
        }
        let mut msg = FwdMsg {
            room_id,
            src_pid,
            kind: fwd_kind::RTCP_FWD,
            len: plain.len() as u16,
            t0,
            buf: [0u8; 2048],
        };
        msg.buf[..plain.len()].copy_from_slice(plain);
        for j in 0..self.n_shards {
            if m & (1u64 << j) != 0 {
                self.push_shard(j, &msg);
            }
        }
    }

    /// The per-target encrypt+batch+sendmmsg core — shared by the
    /// pub-side direct path and the inter-shard plaintext path.
    fn fanout_send(
        &mut self,
        room_id: u32,
        src_pid: u32,
        kind: Option<u8>,
        plain: &[u8],
        t0: Instant,
    ) {
        let rtcp = kind.is_none();
        let Some(room) = self.rooms.get(&room_id) else {
            return;
        };
        // Pick the demand-filtered table for this packet's kind; RTCP
        // rides the union of subscribers wanting anything from this pub.
        let table = if rtcp {
            &room.fanout_any
        } else {
            match kind {
                Some(k) if k == kind_u8(&MediaKind::Audio) => &room.fanout_a,
                _ => &room.fanout_v,
            }
        };
        let Some(targets) = table.get(src_pid as usize) else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        // Plaintext is already canonical — the source shard rewrote the
        // mid once. Per-target work is encrypt + queue-for-sendmmsg only.
        self.mmsg_addrs.clear();
        self.mmsg_lens.clear();
        let mut wi = 0usize; // dense write index into the arena
        for tk in targets.iter() {
            if wi >= 512 {
                break;
            }
            let tl = Instant::now();
            let Some(t) = self.transports.get_mut(tk) else {
                continue;
            };
            self.prof_lookup_ns += tl.elapsed().as_nanos() as u64;
            let tc = Instant::now();
            let slot = &mut self.batch[wi * 2048..(wi + 1) * 2048];
            let res = if rtcp {
                t.protect_rtcp(plain, slot)
            } else {
                t.protect_rtp(plain, slot)
            };
            self.prof_crypto_ns += tc.elapsed().as_nanos() as u64;
            let Some((to, n)) = res else {
                // Transport exists but isn't nominated/connected — or no
                // SRTP yet. Counted so "fewer sends than targets" is never
                // silent.
                self.skip_no_transport += 1;
                continue;
            };
                        let addr: nix::sys::socket::SockaddrStorage = match to {
                std::net::SocketAddr::V4(a) => a.into(),
                std::net::SocketAddr::V6(a) => a.into(),
            };
            self.mmsg_addrs.push(Some(addr));
            self.mmsg_lens.push(n);
            wi += 1;
        }

        // Pass 2: one sendmmsg for the whole batch — the fan-out's syscall
        // cost is O(1) per packet, not O(N).
        if wi > 0 {
            let iovs: Vec<[std::io::IoSlice; 1]> = (0..wi)
                .map(|i| {
                    [std::io::IoSlice::new(&self.batch[i * 2048..i * 2048 + self.mmsg_lens[i]])]
                })
                .collect();
            // MultiHeaders is !Send (*mut c_void) — allocated per call
            // here; fanout_send awaits nothing while it lives.
            let mut hdrs = nix::sys::socket::MultiHeaders::preallocate(wi, None);
            use std::os::fd::AsRawFd;
            let ts = Instant::now();
            // sendmmsg may stop early (kernel send queue transiently
            // full) — retry the tail a few times; whatever's left after
            // that counts as drops.
            let mut sent = 0usize;
            for _ in 0..4 {
                if sent >= wi {
                    break;
                }
                let res = nix::sys::socket::sendmmsg(
                    self.socket.as_raw_fd(),
                    &mut hdrs,
                    iovs[sent..].iter(),
                    &self.mmsg_addrs[sent..],
                    &[] as &[nix::sys::socket::ControlMessage],
                    nix::sys::socket::MsgFlags::empty(),
                );
                match res {
                    Ok(results) => sent += results.count(),
                    Err(_) => break,
                }
            }
            self.prof_send_ns += ts.elapsed().as_nanos() as u64;
            self.forwarded += sent as u64;
            self.send_drops += (wi - sent) as u64;
            let ns = t0.elapsed().as_nanos() as u64;
            self.res_packets += 1;
            self.res_sum_ns += ns;
            self.res_max_ns = self.res_max_ns.max(ns);
            let us = ns / 1_000;
            self.res_buckets[match us {
                0..=49 => 0,
                50..=99 => 1,
                100..=249 => 2,
                250..=499 => 3,
                500..=999 => 4,
                1000..=1999 => 5,
                2000..=4999 => 6,
                _ => 7,
            }] += 1;
            if self.res_packets.is_multiple_of(2000) {
                tracing::info!(
                    shard = self.id,
                    forwarded = self.forwarded,
                    packets = self.res_packets,
                    buckets_us = ?self.res_buckets,
                    mean_ns = self.res_sum_ns / self.res_packets.max(1),
                    max_ns = self.res_max_ns,
                    decrypt_us = self.prof_decrypt_ns / 1000,
                    parse_us = self.prof_parse_ns / 1000,
                    lookup_us = self.prof_lookup_ns / 1000,
                    crypto_us = self.prof_crypto_ns / 1000,
                    send_us = self.prof_send_ns / 1000,
                    "residence + stage profile"
                );
            }
        }
    }

    /// Relay decrypted RTCP from a subscriber leg to this shard's local
    /// publisher legs — the PLI/NACK path back to senders.
    fn forward_to_pubs_local(&mut self, room_id: u32, exclude_pid: u32, plain: &[u8]) {
        let Some(room) = self.rooms.get(&room_id) else {
            return;
        };
        let targets: Vec<TransportKey> = room
            .locals
            .iter()
            .filter(|(_, m)| m.pid != exclude_pid)
            .map(|(name, _)| TransportKey {
                room: room.name.clone(),
                participant: name.clone(),
                leg: Leg::Pub,
            })
            .collect();
        for tk in targets {
            let Some(t) = self.transports.get_mut(&tk) else {
                continue;
            };
            if let Some((to, n)) = t.protect_rtcp(plain, &mut self.scratch_out[..]) {
                let _ = self.socket.send_to(&self.scratch_out[..n], to);
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
            let _ = self.socket.send_to(&data, to);
        }
    }
}

/// FwdMsg isn't Clone (inline 2KB buf is a memcpy) — an explicit copy
/// keeps it visible in profiles.
fn clone_msg(m: &FwdMsg) -> FwdMsg {
    FwdMsg {
        room_id: m.room_id,
        src_pid: m.src_pid,
        kind: m.kind,
        len: m.len,
        t0: m.t0,
        buf: m.buf,
    }
}

// ── Router: room tables + control routing, never touches packets ─────

struct MemberCtl {
    pid: u32,
    shard: usize,
    published: Vec<(String, MediaKind)>,
    /// Raw subscription refs — resolved on demand against `published`.
    wants: Option<Vec<(String, String)>>,
}

struct RoomCtl {
    id: u32,
    members: HashMap<String, MemberCtl>,
    next_pid: u32,
}

struct Router {
    rooms: HashMap<String, RoomCtl>,
    next_room_id: u32,
    n_shards: usize,
    shards: Vec<ShardCtlQ>,
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    /// Members whose subscriber offer is stale — flushed in one batch
    /// when the control channel drains, so a publish storm emits one
    /// offer per member per lull, not one per publish per member.
    dirty_offers: HashSet<(u32, String)>,
}

impl Router {
    fn new(
        control_rx: mpsc::UnboundedReceiver<MediaControl>,
        shards: Vec<ShardCtlQ>,
        n_shards: usize,
    ) -> Self {
        Self {
            rooms: HashMap::new(),
            next_room_id: 0,
            n_shards,
            shards,
            control_rx,
            dirty_offers: HashSet::new(),
        }
    }

    async fn run(&mut self) {
        while let Some(c) = self.control_rx.recv().await {
            self.on_control(c);
            // Drain everything pending, then flush stale offers once —
            // a burst of N publishes coalesces to one offer per member.
            while let Ok(c) = self.control_rx.try_recv() {
                self.on_control(c);
            }
            self.flush_offers();
        }
        // Control plane is gone — take the shards down with it.
        for s in &self.shards {
            s.send(ShardCtl::Shutdown);
        }
    }

    /// Emit the coalesced subscriber offers — each dirty member gets one
    /// offer built from the latest wanted set.
    fn flush_offers(&mut self) {
        let dirty = std::mem::take(&mut self.dirty_offers);
        for (rid, name) in dirty {
            let Some(r) = self.rooms.values().find(|r| r.id == rid) else {
                continue;
            };
            let tracks = Self::wanted_tracks(r, &name);
            let Some(m) = r.members.get(&name) else {
                continue;
            };
            if tracks.is_empty() {
                continue;
            }
            self.shard_tx(m.shard).send(ShardCtl::OfferSub {
                room_id: rid,
                name,
                tracks,
            });
        }
    }

    /// Mark a member's subscriber offer stale — emitted on next lull.
    fn mark_dirty(&mut self, room_id: u32, name: &str) {
        self.dirty_offers.insert((room_id, name.to_string()));
    }

    fn shard_tx(&self, shard: usize) -> &ShardCtlQ {
        &self.shards[shard % self.n_shards]
    }

    fn broadcast(&self, msg_for: impl Fn(usize) -> ShardCtl) {
        for (i, s) in self.shards.iter().enumerate() {
            s.send(msg_for(i));
        }
    }

    /// Resolve a member's raw (owner, track id) refs to (pid, kind).
    fn resolve_wants(
        r: &RoomCtl,
        wants: &Option<Vec<(String, String)>>,
    ) -> Option<HashSet<(u32, u8)>> {
        let wants = wants.as_ref()?;
        let mut out = HashSet::with_capacity(wants.len());
        for (owner, tid) in wants {
            if let Some(m) = r.members.get(owner) {
                for (id, k) in &m.published {
                    if id == tid {
                        out.insert((m.pid, kind_u8(k)));
                    }
                }
            }
        }
        Some(out)
    }

    /// The tracks member `name` wants: their resolved subscription set,
    /// or all others' published tracks when they've never subscribed.
    fn wanted_tracks(r: &RoomCtl, name: &str) -> Vec<TrackRef> {
        let Some(t) = r.members.get(name) else {
            return Vec::new();
        };
        let w = Self::resolve_wants(r, &t.wants);
        r.members
            .iter()
            .filter(|(p, _)| *p != name)
            .flat_map(|(p, m)| {
                m.published
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, k))| match &w {
                        None => true,
                        Some(w) => w.contains(&(m.pid, kind_u8(k))),
                    })
                    .map(|(i, (id, k))| {
                        (
                            p.clone(),
                            id.clone(),
                            k.clone(),
                            format!("m{}.{}", m.pid, i),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every member's resolved want-set — pure, so callers can compute
    /// inside a mutable borrow and send after it ends.
    fn resolved_wants(r: &RoomCtl) -> WantsTable {
        r.members
            .values()
            .map(|m| (m.pid, Self::resolve_wants(r, &m.wants)))
            .collect()
    }

    /// Push the room's resolved want-table to all shards — one message
    /// per shard per event, so ctl traffic is O(events) not O(N²).
    fn push_wants(&self, r: &RoomCtl) {
        let table = Self::resolved_wants(r);
        self.broadcast(move |_| ShardCtl::WantsAll {
            room_id: r.id,
            table: table.clone(),
        });
    }

    fn on_control(&mut self, ctl: MediaControl) {
        match ctl {
            MediaControl::Joined {
                room,
                participant,
                reply,
            } => {
                if !self.rooms.contains_key(&room) {
                    let id = self.next_room_id;
                    self.next_room_id += 1;
                    self.rooms.insert(
                        room.clone(),
                        RoomCtl {
                            id,
                            members: HashMap::new(),
                            next_pid: 0,
                        },
                    );
                    self.broadcast(|_| ShardCtl::RoomUp {
                        room_id: id,
                        room: room.clone(),
                    });
                }
                let r = self.rooms.get_mut(&room).expect("just ensured");
                let rid = r.id;
                let pid = r.next_pid;
                r.next_pid += 1;
                let shard = (pid as usize) % self.n_shards;
                r.members.insert(
                    participant.clone(),
                    MemberCtl {
                        pid,
                        shard,
                        published: Vec::new(),
                        wants: None,
                    },
                );
                self.broadcast(|i| ShardCtl::MemberUp {
                    room_id: rid,
                    name: participant.clone(),
                    pid,
                    reply: if i == shard { Some(reply.clone()) } else { None },
                });
                self.push_wants(self.rooms.get(&room).expect("exists"));
                self.mark_dirty(rid, &participant);
            }
            MediaControl::PublisherOffer {
                room,
                participant,
                sdp,
            } => {
                if let Some(r) = self.rooms.get(&room)
                    && let Some(m) = r.members.get(&participant)
                {
                    self.shard_tx(m.shard).send(ShardCtl::PubOffer {
                        room_id: r.id,
                        name: participant,
                        sdp,
                    });
                }
            }
            MediaControl::SubscriberAnswer {
                room,
                participant,
                sdp,
            } => {
                if let Some(r) = self.rooms.get(&room)
                    && let Some(m) = r.members.get(&participant)
                {
                    self.shard_tx(m.shard).send(ShardCtl::SubAnswer {
                        room_id: r.id,
                        name: participant,
                        sdp,
                    });
                }
            }
            MediaControl::TracksPublished {
                room,
                participant,
                tracks,
            } => {
                let Some(r) = self.rooms.get_mut(&room) else {
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
                if let Some(m) = r.members.get_mut(&participant) {
                    for k in kinds {
                        if !m.published.iter().any(|(id, _)| *id == k.0) {
                            m.published.push(k);
                        }
                    }
                }
                let pub_tids: HashSet<&str> =
                    tracks.iter().map(|t| t.id.as_str()).collect();
                // Re-offer only members whose wants cover this publisher
                // — marked dirty; the flush coalesces the storm.
                let dirty: Vec<String> = r
                    .members
                    .iter()
                    .filter(|(p, m)| {
                        **p != participant
                            && match &m.wants {
                                None => true,
                                Some(w) => w
                                    .iter()
                                    .any(|(o, t)| {
                                        *o == participant && pub_tids.contains(t.as_str())
                                    }),
                            }
                    })
                    .map(|(p, _)| p.clone())
                    .collect();
                // Publishes may satisfy pending wants — refresh shards.
                let rid = r.id;
                let table = Self::resolved_wants(r);
                self.broadcast(|_| ShardCtl::WantsAll {
                    room_id: rid,
                    table: table.clone(),
                });
                for name in dirty {
                    self.mark_dirty(rid, &name);
                }
            }
            MediaControl::SubscriptionsChanged {
                room,
                participant,
                tracks,
            } => {
                let Some(r) = self.rooms.get_mut(&room) else {
                    return;
                };
                if let Some(m) = r.members.get_mut(&participant) {
                    m.wants = Some(tracks);
                }
                let rid = r.id;
                let table = Self::resolved_wants(r);
                self.broadcast(|_| ShardCtl::WantsAll {
                    room_id: rid,
                    table: table.clone(),
                });
                self.mark_dirty(rid, &participant);
            }
            MediaControl::Left { room, participant } => {
                let Some(r) = self.rooms.get_mut(&room) else {
                    return;
                };
                if r.members.remove(&participant).is_some() {
                    let rid = r.id;
                    self.dirty_offers.retain(|d| *d != (rid, participant.clone()));
                    let empty = r.members.is_empty();
                    let wants_msgs = if empty { Vec::new() } else { Self::resolved_wants(r) };
                    self.broadcast(|_| ShardCtl::MemberGone {
                        room_id: rid,
                        name: participant.clone(),
                    });
                    if empty {
                        self.rooms.remove(&room);
                    } else {
                        self.broadcast(|_| ShardCtl::WantsAll {
                    room_id: rid,
                    table: wants_msgs.clone(),
                });
                    }
                }
            }
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
    // Fake legs are tokio tasks — the std-socket alias above is for the
    // shard threads only.
    use tokio::net::UdpSocket;
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
            // Generous bound: a re-offer storm with N publishers sends
            // ~N messages per member before we drain them.
            let (tx, rx) = mpsc::channel(1024);
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

        // The real plane, one shard — inspectable once the loop exits.
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, "127.0.0.1".to_string(), 1)
            .await
            .unwrap();

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
        let server_fingerprint = answer
            .sha256_fingerprint()
            .map(|f| f.value.clone())
            .expect("the answer carries the server's cert fingerprint");
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        assert_ne!(
            b_pub.server.port(), 0,
            "the advertised candidate is the shard's bound socket"
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
        tokio::time::sleep(Duration::from_millis(30));
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
        // Forwarding rewrites the packet's mid to the subscriber's value
        // (and inserts it when the source stopped emitting), so the wire
        // form legitimately differs — assert the semantic fields instead.
        let parsed = RtpPacket::parse(&got).expect("forwarded packet parses as RTP");
        assert_eq!(parsed.payload_type(), 96);
        assert_eq!(parsed.ssrc(), SSRC);
        assert!(parsed.marker());
        assert_eq!(parsed.payload(), PAYLOAD);
        // The canned packet has no mid; forwarding inserts the
        // canonical mid every subscriber was offered for b's track 0.
        assert_eq!(
            parsed.mid(&wroom_edge::rtp::ExtMap::from_pairs(&[(
                4,
                wroom_edge::rtp::KnownExt::Mid
            )])),
            Some(b"m1.0".as_slice()),
            "forwarded packet carries the canonical mid"
        );

        // ── Control-plane view: both legs nominated (by_addr) and ───
        // ── keyed by server ufrag (by_ufrag), transports connected. ──
        drop(ctl_tx);
        let h = handles.remove(0);
        let rt = timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
            .await
            .expect("shard exits when control closes")
            .expect("join task")
            .expect("shard thread");
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
        assert_eq!(
            server_fingerprint,
            rt.identity.fingerprint_sha256().to_string(),
            "answer fingerprint is the shard's cert"
        );
        // b published → its mid_track maps the offer's mid to canon;
        // a published nothing → empty.
        let room0 = &rt.rooms[&0];
        assert!(room0.locals["a"].mid_track.is_empty());
        assert!(!room0.locals["b"].mid_track.is_empty());
    }

    /// What one flood run measured.
    #[derive(Debug)]
    struct FloodStats {
        n: usize,
        media_in: u64,
        forwarded: u64,
        drained: usize,
        buckets: [u64; 8],
        mean_ns: u64,
        max_ns: u64,
        send_s: f64,
        cpu_ticks: u64,
        rss0_kb: u64,
        rss1_kb: u64,
        setup_s: f64,
        send_drops: u64,
        ring_drops: u64,
        skip_no_transport: u64,
        // Per-stage totals (ns) over the whole run.
        prof_decrypt_ns: u64,
        prof_parse_ns: u64,
        prof_lookup_ns: u64,
        prof_crypto_ns: u64,
        prof_send_ns: u64,
    }

    /// The whole load scenario, parameterized: N peers, real DTLS+SRTP
    /// handshakes on both legs, encoder-paced flood, then read the
    /// runtime's counters back. Returns stats; asserts nothing — callers
    /// decide what the thresholds are.
    /// `demand`: how many publishers each subscriber asks for. `usize::MAX`
    /// = never subscribe = forward-all. `shards`: worker count — members
    /// spread pid % shards across that many sockets and cores.
    async fn run_flood(n: usize, pkts: usize, demand: usize, shards: usize) -> FloodStats {
        const PAYLOAD: usize = 1000; // bytes
        let setup0 = Instant::now();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let handles = spawn_plane(ctl_rx, 0, "127.0.0.1".to_string(), shards)
            .await
            .unwrap();
        let room = "room".to_string();

        let rss0 = proc_rss_kb();
        let cpu0 = proc_cpu_ticks();

        // ── Join all → offer+connect pubs → publish → answer+connect subs
        let mut peers = Vec::with_capacity(n);
        for i in 0..n {
            let pid = format!("p{i}");
            let (peer, tx) = FakePeer::new();
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: pid.clone(),
                    reply: tx,
                })
                .unwrap();
            peers.push((pid, peer));
        }
        let mut pubs = Vec::with_capacity(n);
        for (i, (pid, peer)) in peers.iter_mut().enumerate() {
            let uf = format!("pub{i}");
            let offer = publisher_offer(&peer.identity, &uf, "pubpwd0000123456789abcdef");
            ctl_tx
                .send(MediaControl::PublisherOffer {
                    room: room.clone(),
                    participant: pid.clone(),
                    sdp: offer,
                })
                .unwrap();
            let sdp = recv_sdp(
                &mut peer.reply,
                proto::SignalTarget::Publisher,
                proto::session_description::Type::Answer,
            )
            .await;
            let answer = Offer::parse(&sdp).unwrap();
            let mut leg = FakeLeg::new(&peer.identity, &uf, &answer).await;
            leg.nominate().await;
            leg.connect().await;
            pubs.push(leg);
        }
        // Demand-aware subscription: each member watches a rotating
        // window of `demand` publishers — viewport-sized interest, even
        // load distribution across sources. Posted BEFORE the publishes
        // so the re-offer scoping engages from the first publish.
        if demand < n {
            for (i, (pid, _)) in peers.iter().enumerate() {
                let tracks: Vec<(String, String)> = (0..demand)
                    .map(|d| (format!("p{}", (i + d) % n), "cam".to_string()))
                    .collect();
                ctl_tx
                    .send(MediaControl::SubscriptionsChanged {
                        room: room.clone(),
                        participant: pid.clone(),
                        tracks,
                    })
                    .unwrap();
            }
        }
        for (pid, _) in &peers {
            ctl_tx
                .send(MediaControl::TracksPublished {
                    room: room.clone(),
                    participant: pid.clone(),
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
        }
        let mut subs = Vec::with_capacity(n);
        for (i, (pid, peer)) in peers.iter_mut().enumerate() {
            // Each publish re-offers everyone — drain to the LAST offer,
            // the one with all N-1 m-lines.
            let mut sdp = recv_sdp(
                &mut peer.reply,
                proto::SignalTarget::Subscriber,
                proto::session_description::Type::Offer,
            )
            .await;
            // The publish storm produces N-1 re-offers per member; the
            // reply queue may hold a mid-storm snapshot. Keep draining
            // until the offer carries all N-1 m-lines (with a cap).
            // Demand-scoped offer: the member's window of `demand`
            // publishers, minus self — every window contains self at d=0.
            let expected = if demand == usize::MAX {
                n - 1
            } else {
                demand - 1
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut offer = Offer::parse(&sdp).unwrap();
            while offer.media.len() != expected && Instant::now() < deadline {
                match peer.reply.try_recv() {
                    Ok(ServerMessage {
                        msg:
                            Some(server_message::Msg::SessionDescription(sd)),
                    }) if sd.target() == proto::SignalTarget::Subscriber
                        && sd.r#type() == proto::session_description::Type::Offer =>
                    {
                        sdp = sd.sdp;
                        offer = Offer::parse(&sdp).unwrap();
                    }
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
            assert_eq!(offer.media.len(), expected, "sub offer size wrong");
            let uf = format!("sub{i}");
            let ans = subscriber_answer(
                &peer.identity,
                &offer,
                &uf,
                "subpwd0000123456789abcdef",
            );
            ctl_tx
                .send(MediaControl::SubscriberAnswer {
                    room: room.clone(),
                    participant: pid.clone(),
                    sdp: ans,
                })
                .unwrap();
            tokio::time::sleep(Duration::from_millis(5));
            let mut leg = FakeLeg::new(&peer.identity, &uf, &offer).await;
            leg.nominate().await;
            leg.connect().await;
            subs.push(leg);
        }
        let setup_s = setup0.elapsed().as_secs_f64();
        // Let server-side DTLS finish: a fake leg's connect() returns when
        // its client reports done — the server's last flight lands a few
        // ms later, and until it does protect_rtp returns None.
        tokio::time::sleep(Duration::from_millis(300));
        // Drain subscriber sockets concurrently so rx buffers never stall.
        // Spawned *after* the settle — earlier their 50ms idle timeout
        // fires before the first packet arrives.
        let mut drainers = Vec::with_capacity(n);
        for mut s in subs {
            drainers.push(tokio::spawn(async move {
                let mut n = 0usize;
                while s
                    .try_recv_media(Duration::from_millis(50))
                    .await
                    .is_some()
                {
                    n += 1;
                }
                n
            }));
        }

        // ── Flood, paced like real encoders: one round of all pubs ────
        // every ~8ms ≈ 125 rounds/s.
        let t0 = Instant::now();
        for seq in 0..pkts {
            let round = Instant::now();
            for (i, p) in pubs.iter_mut().enumerate() {
                let pkt = canned_rtp(
                    seq as u16,
                    (seq * 3000) as u32,
                    0xBEEF_0000 + i as u32,
                    &vec![0x5Au8; PAYLOAD],
                );
                p.send_media(&pkt).await;
            }
            let spent = round.elapsed();
            if spent < Duration::from_millis(8) {
                tokio::time::sleep(Duration::from_millis(8) - spent);
            }
        }
        let send_s = t0.elapsed().as_secs_f64();
        // Let the runtime drain its socket queue.
        tokio::time::sleep(Duration::from_secs(3));
        let cpu1 = proc_cpu_ticks();
        let rss1 = proc_rss_kb();

        drop(ctl_tx);
        // Aggregate every shard's counters — the plane's totals.
        let mut media_in = 0u64;
        let mut forwarded = 0u64;
        let mut buckets = [0u64; 8];
        let mut res_sum = 0u64;
        let mut res_pkts = 0u64;
        let mut max_ns = 0u64;
        let mut send_drops = 0u64;
        let mut ring_drops = 0u64;
        let mut skip_no_transport = 0u64;
        let mut prof = [0u64; 5];
        let mut legs = 0usize;
        for h in handles {
            let s = timeout(
                Duration::from_secs(10),
                tokio::task::spawn_blocking(move || h.join()),
            )
            .await
            .expect("shard exits when control closes")
            .expect("join task")
            .expect("shard thread");
            media_in += s.media_in;
            forwarded += s.forwarded;
            for (i, b) in buckets.iter_mut().enumerate() {
                *b += s.res_buckets[i];
            }
            res_sum += s.res_sum_ns;
            res_pkts += s.res_packets;
            max_ns = max_ns.max(s.res_max_ns);
            send_drops += s.send_drops;
            ring_drops += s.ring_drops;
            skip_no_transport += s.skip_no_transport;
            prof[0] += s.prof_decrypt_ns;
            prof[1] += s.prof_parse_ns;
            prof[2] += s.prof_lookup_ns;
            prof[3] += s.prof_crypto_ns;
            prof[4] += s.prof_send_ns;
            legs += s.transports.len();
        }
        eprintln!("leg census: {legs} transports across {shards} shards");
        let mut drained = 0usize;
        for d in drainers {
            drained += d.await.unwrap_or(0);
        }

        FloodStats {
            n,
            media_in,
            forwarded,
            drained,
            buckets,
            mean_ns: res_sum / res_pkts.max(1),
            max_ns,
            send_s,
            cpu_ticks: cpu1 - cpu0,
            rss0_kb: rss0,
            rss1_kb: rss1,
            setup_s,
            send_drops,
            ring_drops,
            skip_no_transport,
            prof_decrypt_ns: prof[0],
            prof_parse_ns: prof[1],
            prof_lookup_ns: prof[2],
            prof_crypto_ns: prof[3],
            prof_send_ns: prof[4],
        }
    }

    /// The assertion-bearing entry point: one flood at CI scale.
    /// Debug crypto is ~10× slower than release — scale the swarm so the
    /// paced flood stays sustainable in both profiles.
    #[tokio::test]
    async fn forwarding_flood_load() {
        const N: usize = if cfg!(debug_assertions) { 6 } else { 24 };
        const PKTS: usize = 400;
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let s = run_flood(N, PKTS, usize::MAX, 4).await;
        eprintln!("\n=== flood load ===");
        eprintln!("{s:?}");
        eprintln!("drained={} rss={}kB→{}kB", s.drained, s.rss0_kb, s.rss1_kb);
        let expected = (N * PKTS * (N - 1)) as u64;
        assert!(s.forwarded > expected / 2, "forwarded most packets");
        // Tail bound: debug runs ~10× slower; the release ladder holds
        // the strict bound. Delivery and drops are the real gates here.
        if cfg!(debug_assertions) {
            assert!(s.buckets[7] < expected / 10, "few forwards ≥5ms");
        } else {
            assert_eq!(s.buckets[7], 0, "no forward ≥5ms");
        }
        assert_eq!(s.send_drops, 0, "no kernel send drops");
        assert_eq!(s.ring_drops, 0, "no ring drops");
    }

    /// The scale ladder — the benchmark. Run:
    ///   cargo test -p wroomd --release forwarding_scale_ladder -- --ignored --nocapture
    /// Prints a table: peers → forwards/s, residence mean/max, CPU%, RSS.
    #[tokio::test]
    #[ignore]
    async fn forwarding_scale_ladder() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // (peers, demand) — demand=usize::MAX is forward-all; demand=12 is
        // a viewport-sized interest set, the M1 lever.
        let rungs: &[(usize, usize)] = if cfg!(debug_assertions) {
            &[(4, usize::MAX), (8, usize::MAX), (8, 4)]
        } else {
            &[
                (4, usize::MAX),
                (12, usize::MAX),
                (24, usize::MAX),
                (48, usize::MAX),
                (96, usize::MAX),
                (96, 12),
                (192, 12),
            ]
        };
        eprintln!(
            "\n{:>5} {:>7} {:>12} {:>12} {:>10} {:>10} {:>8} {:>10} {:>12}",
            "peers", "demand", "in-pkts", "forwards", "res-meanµs", "res-maxµs", "cpu%", "rssMB", "setup s"
        );
        for &(n, demand) in rungs {
            let s = run_flood(n, 200, demand, if demand == usize::MAX { 1 } else { 4 }).await;
            let cpu_pct = s.cpu_ticks as f64 * 10.0
                / ((s.send_s + 3.0) * 1000.0)
                * 100.0;
            eprintln!(
                "{:>5} {:>7} {:>12} {:>12} {:>10.1} {:>10.1} {:>8.1} {:>10.1} {:>12.1}",
                s.n,
                if demand == usize::MAX { "all".to_string() } else { demand.to_string() },
                s.media_in,
                s.forwarded,
                s.mean_ns as f64 / 1000.0,
                s.max_ns as f64 / 1000.0,
                cpu_pct,
                s.rss1_kb as f64 / 1024.0,
                s.setup_s,
            );
            eprintln!(
                "       send_drops={} ring_drops={} skip_no_transport={} drained={}",
                s.send_drops, s.ring_drops, s.skip_no_transport, s.drained
            );
            // Stage attribution: µs of each stage per inbound packet.
            let pkts = s.media_in.max(1) as f64;
            eprintln!(
                "       stages/pktµs: decrypt={:.1} parse={:.1} lookup={:.1} crypto={:.1} send={:.1}",
                s.prof_decrypt_ns as f64 / pkts / 1000.0,
                s.prof_parse_ns as f64 / pkts / 1000.0,
                s.prof_lookup_ns as f64 / pkts / 1000.0,
                s.prof_crypto_ns as f64 / pkts / 1000.0,
                s.prof_send_ns as f64 / pkts / 1000.0,
            );
        }
    }

    /// Current RSS in kB from /proc/self/status.
    fn proc_rss_kb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS"))
                    .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
            })
            .unwrap_or(0)
    }

    /// /proc/self/stat utime+stime in jiffies (~10ms each on this kernel).
    fn proc_cpu_ticks() -> u64 {
        std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|s| {
                let v: Vec<&str> = s.split_whitespace().collect();
                Some(v[13].parse::<u64>().ok()? + v[14].parse::<u64>().ok()?)
            })
            .unwrap_or(0)
    }
}
