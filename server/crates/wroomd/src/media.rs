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
use wroom_edge::rtcp::{self, ReportBlock, RtcpKind, TwccStatus};
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
    /// m-line sequence of the last subscriber offer sent to this member:
    /// (canon mid, kind) per position. Re-offers may never drop or
    /// reorder m-lines — a removed track's slot is re-emitted at port 0
    /// and new tracks only ever append.
    sub_mlines: Vec<(String, MediaKind)>,
    /// Their publisher offer's `a=mid` → the track's identity (kind +
    /// canonical mid). m-line order == published-track order — the
    /// client's TracksPublished follows its transceiver order.
    mid_track: HashMap<String, TrackTag>,
    /// SSRC → track identity, learned when a packet carries its mid —
    /// covers sources that stop emitting mid mid-stream. Bounded at 8.
    /// Also the PLI key set.
    ssrc_map: HashMap<u32, TrackTag>,
    /// Active-speaker state for this member's audio: smoothed linear
    /// energy (EWMA α=0.3 of 10^(−dBov/20)) and the last packet whose
    /// audio-level extension flagged voice.
    spk_ewma: f32,
    spk_last_voice: Instant,
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
    /// Source member's pid — the publisher for media, the subscriber
    /// who sent the feedback for `RTCP_BACK`.
    src_pid: u32,
    /// `RTCP_BACK` only: the media ssrc the feedback block targets. The
    /// source shard can't name the owner — ssrc→member knowledge lives
    /// on the owner's home shard — so each receiving shard resolves it
    /// against its own locals. Zero for every other kind.
    ssrc: u32,
    kind: u8,
    len: u16,
    t0: Instant,
    buf: [u8; 2048],
}

mod fwd_kind {
    pub const AUDIO: u8 = 1;
    pub const VIDEO: u8 = 2;
    /// One filtered subscriber feedback block (PLI/FIR/NACK) → whichever
    /// shard owns the publisher of `ssrc` delivers it locally.
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
    /// Room-wide merged active speakers — every shard forwards it to
    /// its own local members' reply channels.
    ActiveSpeakers {
        room_id: u32,
        /// Top ≤3, loudest first: (participant name, level 0..1).
        speakers: Vec<(String, f32)>,
    },
}

/// A shard's local active-speaker partial for one room — the router
/// merges these across shards (share-nothing: no shard sees the whole
/// room's audio levels).
struct ShardReport {
    room_id: u32,
    /// The reporting shard — the router keys partials per shard.
    shard: usize,
    /// Top ≤3 local publishers, loudest first: (name, smoothed energy).
    top: Vec<(String, f32)>,
}

/// Runs the media plane until the control channel closes: a room-state
/// router plus `shards` worker tasks, each with its own UDP socket —
/// per-shard sockets give independent kernel TX queues, which is where
/// the real send parallelism lives.
pub async fn run(
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    media_port: u16,
    advertise_addrs: Vec<String>,
    shards: usize,
) -> std::io::Result<()> {
    spawn_plane(control_rx, media_port, advertise_addrs, shards.clamp(1, 64)).await?;
    Ok(())
}

/// Build + spawn the whole plane; returns the shard thread handles
/// (tests inspect the finished shards' counters).
async fn spawn_plane(
    control_rx: mpsc::UnboundedReceiver<MediaControl>,
    media_port: u16,
    advertise_addrs: Vec<String>,
    n_shards: usize,
) -> std::io::Result<Vec<std::thread::JoinHandle<Shard>>> {
    // One bounded plaintext ring + doorbell per shard — all sources push.
    let rings: Vec<Arc<ArrayQueue<FwdMsg>>> = (0..n_shards)
        .map(|_| Arc::new(ArrayQueue::new(512)))
        .collect();
    let fwd_efds: Vec<Arc<EventFd>> = (0..n_shards)
        .map(|_| Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap()))
        .collect();

    // One bounded shard→router report ring — active-speaker partials.
    // Cadence is fixed (~300 ms/shard), so no doorbell: the router
    // drains it on its own interval.
    let reports: Arc<ArrayQueue<ShardReport>> = Arc::new(ArrayQueue::new(1024));

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
            reports.clone(),
            advertise_addrs.clone(),
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
    let mut router = Router::new(control_rx, ctl_qs, reports, n_shards);
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

/// A transport plus the receiver-side feedback state a publisher leg
/// needs. `rx` is `Some` only on `Leg::Pub` — subscribers never send us
/// media, so they carry none.
struct LegState {
    t: PeerTransport,
    rx: Option<Box<RecvFeedback>>,
}

/// RR counters for one media ssrc on a publisher leg, per RFC 3550
/// §6.4.1 / A.8. Fixed size; updated in place per packet.
#[derive(Clone, Copy)]
struct RrSlot {
    ssrc: u32,
    /// Highest sequence number seen (low 16 bits) and its cycle count.
    max_seq: u16,
    cycles: u32,
    base_seq: u16,
    received: u32,
    expected_prior: u32,
    received_prior: u32,
    /// Interarrival jitter in timestamp units, <<4 fixed point.
    jitter16: i64,
    /// Last transit time (arrival in clock units − RTP timestamp).
    transit: i64,
    /// Middle 32 bits of the last SR's NTP timestamp + when it arrived.
    lsr: u32,
    lsr_at: Option<Instant>,
    /// Last time this slot saw a packet — eviction key.
    seen: Instant,
    init: bool,
}

impl RrSlot {
    fn new(ssrc: u32, seq: u16, now: Instant) -> Self {
        Self {
            ssrc,
            max_seq: seq,
            cycles: 0,
            base_seq: seq,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
            jitter16: 0,
            transit: 0,
            lsr: 0,
            lsr_at: None,
            seen: now,
            init: false,
        }
    }

    /// RFC 3550 A.8 sequence tracking + interarrival jitter.
    fn record(&mut self, seq: u16, rtp_ts: u32, arrival_ticks: i64, now: Instant) {
        self.seen = now;
        if !self.init {
            self.base_seq = seq;
            self.max_seq = seq;
            self.received = 0;
            self.transit = arrival_ticks - i64::from(rtp_ts);
            self.init = true;
        } else {
            let udelta = seq.wrapping_sub(self.max_seq);
            if udelta < 3000 {
                // In-order (or small reorder past the wrap): advance.
                if seq < self.max_seq {
                    self.cycles += 1 << 16;
                }
                self.max_seq = seq;
            } else if udelta as u32 <= (1 << 16) - 100 {
                // Misordered/duplicate — counts as received but does
                // not move the high-water mark.
            } else {
                // Large jump: the source restarted — re-anchor.
                self.base_seq = seq;
                self.max_seq = seq;
                self.received = 0;
                self.cycles = 0;
                self.transit = arrival_ticks - i64::from(rtp_ts);
            }
            let transit = arrival_ticks - i64::from(rtp_ts);
            let d = (transit - self.transit).abs();
            self.transit = transit;
            self.jitter16 += d - ((self.jitter16 + 8) >> 4);
        }
        self.received += 1;
    }

    /// The report block for this interval; updates the priors.
    fn report(&mut self, now: Instant) -> ReportBlock {
        let ext_max = self.cycles + u32::from(self.max_seq);
        let expected = ext_max.wrapping_sub(u32::from(self.base_seq)) + 1;
        let lost = expected as i64 - i64::from(self.received);
        let exp_iv = expected - self.expected_prior;
        let rec_iv = self.received - self.received_prior;
        self.expected_prior = expected;
        self.received_prior = self.received;
        let lost_iv = i64::from(exp_iv) - i64::from(rec_iv);
        let fraction = if exp_iv == 0 || lost_iv <= 0 {
            0
        } else {
            ((lost_iv << 8) / i64::from(exp_iv)) as u8
        };
        let dlsr = self
            .lsr_at
            .map(|t| (now.saturating_duration_since(t).as_secs_f64() * 65536.0) as u32)
            .unwrap_or(0);
        ReportBlock {
            ssrc: self.ssrc,
            fraction_lost: fraction,
            cumulative_lost: lost.clamp(-0x7F_FFFF, 0x7F_FFFF) as i32,
            highest_seq: ext_max,
            jitter: (self.jitter16 >> 4).clamp(0, i64::from(u32::MAX)) as u32,
            lsr: self.lsr,
            dlsr,
        }
    }
}

/// Receiver-side feedback state for one publisher leg: a bounded TWCC
/// status window plus per-ssrc RR counters. Fully preallocated — nothing
/// on the media path allocates.
struct RecvFeedback {
    /// Time zero for TWCC reference times and RR arrival ticks.
    epoch: Instant,
    /// TWCC batch: statuses for base_seq..base_seq+len, holding
    /// *absolute* arrival ticks (250 µs units from `epoch`) — converted
    /// to incremental wire deltas at flush time.
    tw_init: bool,
    tw_base_seq: u16,
    tw_statuses: [TwccStatus; 512],
    tw_len: u16,
    tw_fb_count: u8,
    tw_last_flush: Instant,
    /// Media ssrc of the most recent packet — the feedback's target.
    tw_media_ssrc: u32,
    /// Per-ssrc RR counters, ≤4 slots.
    rr: [RrSlot; 4],
    rr_len: usize,
    rr_last: Instant,
}

impl RecvFeedback {
    fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            tw_init: false,
            tw_base_seq: 0,
            tw_statuses: [TwccStatus::NotReceived; 512],
            tw_len: 0,
            tw_fb_count: 0,
            tw_last_flush: now,
            tw_media_ssrc: 0,
            rr: [RrSlot::new(0, 0, now); 4],
            rr_len: 0,
            rr_last: now,
        }
    }

    /// Record one decrypted pub-leg RTP packet. Returns true when the
    /// TWCC window must be flushed before this packet can be recorded
    /// (full to the bound, or the seq jumped past the window).
    fn on_rtp(&mut self, plain: &[u8], now: Instant) -> bool {
        let Ok(h) = wroom_edge::rtp::RtpPacket::parse(plain) else {
            return false;
        };
        let ssrc = h.ssrc();
        // RR bookkeeping: find or claim a slot for this ssrc.
        let rate = if h.payload_type() == 111 { 48000 } else { 90000 };
        let arrival = now.saturating_duration_since(self.epoch).as_nanos() as i64
            * i64::from(rate)
            / 1_000_000_000;
        let idx = self.rr[..self.rr_len]
            .iter()
            .position(|s| s.ssrc == ssrc)
            .unwrap_or_else(|| {
                if self.rr_len < self.rr.len() {
                    let i = self.rr_len;
                    self.rr_len += 1;
                    i
                } else {
                    // Bounded: evict the stalest source.
                    self.rr
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, s)| s.seen)
                        .map(|(i, _)| i)
                        .unwrap_or(0)
                }
            });
        if !self.rr[idx].init || self.rr[idx].ssrc != ssrc {
            self.rr[idx] = RrSlot::new(ssrc, h.sequence_number(), now);
        }
        self.rr[idx].record(h.sequence_number(), h.timestamp(), arrival, now);

        let Some(seq) = h.twcc_seq(Shard::leg_extmap()) else {
            return false;
        };
        self.tw_media_ssrc = ssrc;
        if !self.tw_init {
            self.tw_init = true;
            self.tw_base_seq = seq;
            self.tw_last_flush = now;
            self.tw_statuses[0] = TwccStatus::Received(self.epoch_ticks(now));
            self.tw_len = 1;
            return false;
        }
        let d = seq.wrapping_sub(self.tw_base_seq) as i16;
        if d < 0 {
            // Older than the window's first packet — unrepresentable.
            return false;
        }
        let d = d as usize;
        if d >= self.tw_statuses.len() {
            // Jumped past the window — caller flushes and re-records.
            return true;
        }
        if d >= self.tw_len as usize {
            // Reset through `d` inclusive: slots beyond tw_len hold stale
            // values from earlier windows (the array isn't cleared on flush).
            for s in &mut self.tw_statuses[self.tw_len as usize..=d] {
                *s = TwccStatus::NotReceived;
            }
            self.tw_len = d as u16 + 1;
        }
        // First arrival wins for a reordered duplicate.
        if self.tw_statuses[d] == TwccStatus::NotReceived {
            self.tw_statuses[d] = TwccStatus::Received(self.epoch_ticks(now));
        }
        // Bound the batch so feedback stays small and timely.
        self.tw_len >= 400
    }

    /// `now` as absolute 250 µs ticks from the leg's epoch.
    fn epoch_ticks(&self, now: Instant) -> i32 {
        (now.saturating_duration_since(self.epoch).as_micros() / 250) as i32
    }

    /// Learn LSR/DLSR inputs from an incoming decrypted RTCP datagram
    /// (the publisher's sender reports).
    fn on_rtcp(&mut self, plain: &[u8], now: Instant) {
        for p in rtcp::packets(plain) {
            let Ok(p) = p else { break };
            if let RtcpKind::SenderReport(sr) = p.kind()
                && let Some(s) = self.rr[..self.rr_len]
                    .iter_mut()
                    .find(|s| s.ssrc == sr.sender_ssrc())
            {
                s.lsr = sr.ntp_middle();
                s.lsr_at = Some(now);
            }
        }
    }

    /// True when the pending TWCC batch is due for a timed flush.
    fn twcc_due(&self, now: Instant) -> bool {
        self.tw_len > 0
            && now.saturating_duration_since(self.tw_last_flush)
                >= std::time::Duration::from_millis(50)
    }

    /// True when a periodic RR is due.
    fn rr_due(&self, now: Instant) -> bool {
        self.rr_len > 0
            && now.saturating_duration_since(self.rr_last)
                >= std::time::Duration::from_secs(1)
    }
}

struct Shard {
    id: usize,
    n_shards: usize,
    socket: UdpSocket,
    identity: DtlsIdentity,
    transports: HashMap<TransportKey, LegState>,
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
    /// Local active-speaker partials → the router (merged globally).
    reports: Arc<ArrayQueue<ShardReport>>,
    /// Last time speaker partials were computed (~300 ms cadence).
    spk_last: Instant,
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
    advertise_addrs: Vec<String>,
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
        reports: Arc<ArrayQueue<ShardReport>>,
        advertise_addrs: Vec<String>,
    ) -> Self {
        let identity = DtlsIdentity::generate().expect("dtls identity");
        tracing::info!(
            shard = id,
            addr = ?socket.local_addr(),
            advertise = ?advertise_addrs,
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
            reports,
            spk_last: Instant::now(),
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
            advertise_addrs,
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
        // One host candidate per advertised address — a client picks
        // whichever is reachable (LAN, tailnet, ...). Foundations are
        // per-address so pairing doesn't conflate them.
        let port = self.socket.local_addr().map(|a| a.port()).unwrap_or(0);
        self.advertise_addrs
            .iter()
            .enumerate()
            .map(|(i, addr)| Candidate::host(format!("{}", i + 1), 2_130_706_431, addr.clone(), port))
            .collect()
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
            let Some(leg) = self.transports.get_mut(&key) else {
                return;
            };
            // Disjoint field borrows: `leg` borrows transports, the event
            // buffer is a separate field — the media path never allocs.
            let td = Instant::now();
            leg.t.handle_datagram(buf, from, Instant::now(), &mut self.events);
            self.prof_decrypt_ns += td.elapsed().as_nanos() as u64;
            // Publisher-leg receive bookkeeping while the leg borrow is
            // live — recording needs no second map lookup, and a full
            // TWCC window flushes inline.
            if leg.rx.is_some() {
                for i in 0..self.events.len() {
                    let (len, rtcp) = match &self.events[i] {
                        PeerEvent::Media { len, rtcp } => (*len, *rtcp),
                        _ => continue,
                    };
                    let plain = &buf[..len];
                    if rtcp {
                        if let Some(rx) = leg.rx.as_deref_mut() {
                            rx.on_rtcp(plain, t0);
                        }
                    } else {
                        let flush = leg
                            .rx
                            .as_deref_mut()
                            .is_some_and(|rx| rx.on_rtp(plain, t0));
                        if flush {
                            Self::flush_twcc(&self.socket, &mut self.scratch_out, leg);
                            if let Some(rx) = leg.rx.as_deref_mut() {
                                rx.on_rtp(plain, t0);
                            }
                        }
                    }
                }
            }
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
                            ssrc: 0,
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
                            // Subscriber feedback: only PLI/FIR/NACK go
                            // back, routed to the media-ssrc's owner —
                            // the subscriber's RR/TWCC/REMB describe the
                            // server→sub leg and are meaningless to pubs.
                            let src_pid = self
                                .rooms
                                .get(&room_id)
                                .and_then(|r| r.locals.get(&key.participant))
                                .map(|m| m.pid)
                                .unwrap_or(u32::MAX);
                            self.forward_sub_rtcp(room_id, src_pid, plain, t0);
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
                // Filtered subscriber feedback — resolve the target media
                // ssrc against OUR locals; only the owner's home shard
                // holds its ssrc_map entry, every other shard no-ops.
                self.deliver_pub_rtcp_by_ssrc(m.room_id, m.ssrc, plain)
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
        if let Some(leg) = self.transports.remove(key) {
            self.by_ufrag.remove(leg.t.local_ufrag());
            if let Some(a) = leg.t.remote_addr() {
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
            let Some(leg) = self.transports.get_mut(&tk) else {
                continue;
            };
            for ssrc in ssrcs {
                if let Ok(n) = wroom_edge::rtcp::Pli::build(&mut pkt, 0, ssrc)
                    && let Some((to, m)) =
                        leg.t.protect_rtcp(&pkt[..n], &mut self.scratch_out[..128])
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
                            sub_mlines: Vec::new(),
                            mid_track: HashMap::new(),
                            ssrc_map: HashMap::new(),
                            spk_ewma: 0.0,
                            spk_last_voice: Instant::now(),
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
            ShardCtl::ActiveSpeakers { room_id, speakers } => {
                let Some(r) = self.rooms.get(&room_id) else {
                    return true;
                };
                let msg = ServerMessage {
                    msg: Some(server_message::Msg::ActiveSpeakers(
                        proto::ActiveSpeakers {
                            speakers: speakers
                                .iter()
                                .map(|(id, level)| proto::Speaker {
                                    participant_id: id.clone(),
                                    level: level.clamp(0.0, 1.0),
                                })
                                .collect(),
                        },
                    )),
                };
                for m in r.locals.values() {
                    let _ = m.reply.try_send(msg.clone());
                }
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
        // Rejected (port 0) and inactive m-lines publish nothing but
        // keep their index — canonical mids of live tracks never shift.
        if let Some(r) = self.rooms.get_mut(&room_id)
            && let Some(m) = r.locals.get_mut(name)
        {
            let pid = m.pid;
            m.mid_track = offer
                .media
                .iter()
                .enumerate()
                .filter_map(|(i, md)| {
                    if md.is_rejected() || md.direction == wroom_edge::sdp::Direction::Inactive {
                        return None;
                    }
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
            // Ssrc→tag entries pointing at a now-unpublished m-line are
            // stale: their canonical mid no longer exists in offers.
            let live: HashSet<CanonMid> =
                m.mid_track.values().map(|t| t.canon).collect();
            m.ssrc_map.retain(|_, t| live.contains(&t.canon));
        }
        let Some(room_name) = self.rooms.get(&room_id).map(|r| r.name.clone()) else {
            return;
        };
        let key = TransportKey {
            room: room_name,
            participant: name.to_string(),
            leg: Leg::Pub,
        };
        // A re-offer on an existing leg reuses the transport: DTLS/SRTP
        // state and the local ICE creds (hence by_ufrag routing) survive.
        // A changed remote ufrag is an ICE restart — set_remote_ufrag
        // flushes pair/nomination state; the next check re-nominates and
        // by_addr re-learns the 5-tuple. Fresh local creds would force
        // the client into a full new-pair dance for nothing — reused.
        if !self.transports.contains_key(&key) {
            let t = PeerTransport::new(
                &self.identity,
                Instant::now(),
                offer.ice_ufrag(),
                offer.sha256_fingerprint().map(|f| f.value.clone()),
            );
            self.by_ufrag
                .insert(t.local_ufrag().to_string(), key.clone());
            self.transports.insert(
                key.clone(),
                LegState {
                    t,
                    rx: Some(Box::new(RecvFeedback::new(Instant::now()))),
                },
            );
        } else if let Some(leg) = self.transports.get_mut(&key) {
            if let Some(u) = offer.ice_ufrag() {
                leg.t.set_remote_ufrag(u);
            }
            if let Some(f) = offer.sha256_fingerprint() {
                leg.t.set_expected_fingerprint(f.value.clone());
            }
        }
        let Some(leg) = self.transports.get(&key) else {
            return;
        };
        let config = self.answer_config(&leg.t);
        let answer = match offer.answer(&config) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(participant = name, error = %e, "answer build failed");
                return;
            }
        };
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
        let Some(leg) = self.transports.get_mut(&key) else {
            return;
        };
        if let Some(u) = answer.ice_ufrag() {
            leg.t.set_remote_ufrag(u);
        }
        if let Some(f) = answer.sha256_fingerprint() {
            leg.t.set_expected_fingerprint(f.value.clone());
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
            Some(leg) => &mut leg.t,
            None => {
                let t = PeerTransport::new(&self.identity, Instant::now(), None, None);
                self.by_ufrag
                    .insert(t.local_ufrag().to_string(), key.clone());
                self.transports.insert(key.clone(), LegState { t, rx: None });
                &mut self.transports.get_mut(&key).unwrap().t
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

        // JSEP m-line stability: the offered m-line sequence may never
        // shrink or reorder — Chrome rejects such offers outright. Old
        // slots are reused when their track is still wanted and retired
        // (port 0) when it is not; new tracks only ever append.
        let mut wanted: HashMap<&str, &TrackRef> = HashMap::new();
        for t in tracks {
            wanted.insert(t.3.as_str(), t);
        }
        let mut seen: HashSet<&str> = HashSet::with_capacity(tracks.len());
        let mut media: Vec<OfferedMedia> = Vec::new();
        let mut new_mlines: Vec<(String, MediaKind)> = Vec::new();
        {
            let Some(r) = self.rooms.get(&room_id) else {
                return;
            };
            let Some(m) = r.locals.get(name) else {
                return;
            };
            for (canon, kind) in &m.sub_mlines {
                new_mlines.push((canon.clone(), kind.clone()));
                match wanted.get(canon.as_str()) {
                    Some(t) => {
                        let (owner, id, trk_kind, _) = *t;
                        seen.insert(canon.as_str());
                        media.push(OfferedMedia {
                            mid: canon.clone(),
                            kind: trk_kind.clone(),
                            // msid namespaced by owner — browsers publish
                            // colliding track ids ("mic"/"cam"); Chrome
                            // rejects duplicate msids.
                            msid_track: format!("{owner}/{id}"),
                            payloads: match kind {
                                MediaKind::Audio => vec![111],
                                _ => vec![96],
                            },
                            payload_lines: match kind {
                                MediaKind::Audio => {
                                    vec![(111, "opus/48000/2".to_string())]
                                }
                                _ => vec![(96, "VP8/90000".to_string())],
                            },
                            retired: false,
                        });
                    }
                    None => {
                        media.push(OfferedMedia {
                            mid: canon.clone(),
                            kind: kind.clone(),
                            msid_track: String::new(),
                            payloads: match kind {
                                MediaKind::Audio => vec![111],
                                _ => vec![96],
                            },
                            payload_lines: Vec::new(),
                            retired: true,
                        });
                    }
                }
            }
        }
        for (owner, id, kind, canon) in tracks {
            if !seen.insert(canon.as_str()) {
                continue;
            }
            new_mlines.push((canon.clone(), kind.clone()));
            media.push(OfferedMedia {
                mid: canon.clone(),
                kind: kind.clone(),
                msid_track: format!("{owner}/{id}"),
                payloads: match kind {
                    MediaKind::Audio => vec![111],
                    _ => vec![96],
                },
                payload_lines: match kind {
                    MediaKind::Audio => vec![(111, "opus/48000/2".to_string())],
                    _ => vec![(96, "VP8/90000".to_string())],
                },
                retired: false,
            });
        }
        let offer = match build_subscriber_offer(&config, &media) {
            Ok(o) => o.into_string(),
            Err(e) => {
                tracing::warn!(participant = name, error = %e, "subscriber offer failed");
                return;
            }
        };
        // Commit the slot sequence only once the offer exists — a failed
        // build must not record m-lines that never went on the wire.
        if let Some(r) = self.rooms.get_mut(&room_id)
            && let Some(m) = r.locals.get_mut(name)
        {
            m.sub_mlines = new_mlines;
        }
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
        // Learn ssrc→tag for the mid-absent stretch + PLI key set, and
        // fold audio packets' level extension into the member's
        // active-speaker state — same borrow, no second lookup.
        if let Some(h) = &hdr
            && let Some(r) = self.rooms.get_mut(&room_id)
            && let Some(m) = r.locals.get_mut(&key.participant)
        {
            if m.ssrc_map.len() < 8 {
                m.ssrc_map.insert(h.ssrc(), tag);
            }
            if kind == kind_u8(&MediaKind::Audio)
                && let Some(al) = h.audio_level(Self::leg_extmap())
            {
                // level is −dBov (0 = full scale): linear energy.
                let e = 10f32.powf(-f32::from(al.level) / 20.0);
                m.spk_ewma += 0.3 * (e - m.spk_ewma);
                if al.vad {
                    m.spk_last_voice = t0;
                }
            }
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
            ssrc: 0,
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
            ssrc: 0,
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
            let Some(leg) = self.transports.get_mut(tk) else {
                continue;
            };
            self.prof_lookup_ns += tl.elapsed().as_nanos() as u64;
            let tc = Instant::now();
            let slot = &mut self.batch[wi * 2048..(wi + 1) * 2048];
            let res = if rtcp {
                leg.t.protect_rtcp(plain, slot)
            } else {
                leg.t.protect_rtp(plain, slot)
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

    /// Filtered subscriber→publisher RTCP. Only PLI, FIR, and generic
    /// NACK cross back — reports (RR/SR/TWCC/REMB/SDES/BYE) describe the
    /// server→subscriber leg and would corrupt the publisher's send-side
    /// state. Each kept block is routed to the publisher owning its
    /// media ssrc: local delivery here plus a broadcast so the owner's
    /// home shard delivers too (only that shard's `locals` matches the
    /// pid — every other shard no-ops).
    fn forward_sub_rtcp(&mut self, room_id: u32, src_pid: u32, plain: &[u8], t0: Instant) {
        for pkt in rtcp::packets(plain) {
            let Ok(pkt) = pkt else { break };
            let target_ssrc = match pkt.kind() {
                RtcpKind::Pli(p) => p.media_ssrc(),
                RtcpKind::Nack(n) => n.media_ssrc(),
                RtcpKind::Fir(f) => {
                    let m = f.media_ssrc();
                    if m != 0 {
                        m
                    } else {
                        // RFC 5104 puts the target in the FCI entries.
                        f.entries().next().map(|e| e.ssrc).unwrap_or(0)
                    }
                }
                _ => continue,
            };
            if target_ssrc == 0 {
                continue;
            }
            let raw = pkt.raw();
            // Fast path: the owner may be one of OUR locals — deliver
            // without the ring hop.
            let local_owner = self.rooms.get(&room_id).and_then(|r| {
                r.locals
                    .iter()
                    .find(|(_, m)| m.ssrc_map.contains_key(&target_ssrc))
                    .map(|(_, m)| m.pid)
            });
            if let Some(owner_pid) = local_owner
                && owner_pid != src_pid
            {
                self.deliver_pub_rtcp(room_id, owner_pid, raw);
            }
            // Whether or not we found a local owner, the block crosses to
            // every other shard — only the owner's home shard holds its
            // ssrc_map entry, and it resolves + delivers there.
            if raw.len() > 2048 {
                continue;
            }
            let mut m = FwdMsg {
                room_id,
                src_pid,
                ssrc: target_ssrc,
                kind: fwd_kind::RTCP_BACK,
                len: raw.len() as u16,
                t0,
                buf: [0u8; 2048],
            };
            m.buf[..raw.len()].copy_from_slice(raw);
            self.broadcast(m);
        }
    }

    /// Send one RTCP block to the local member `owner_pid`'s publisher
    /// leg — a no-op when that member lives on a different shard.
    fn deliver_pub_rtcp(&mut self, room_id: u32, owner_pid: u32, plain: &[u8]) {
        let Some(tk) = self.rooms.get(&room_id).and_then(|r| {
            r.locals
                .iter()
                .find(|(_, m)| m.pid == owner_pid)
                .map(|(name, _)| TransportKey {
                    room: r.name.clone(),
                    participant: name.clone(),
                    leg: Leg::Pub,
                })
        }) else {
            return;
        };
        self.send_pub_rtcp(&tk, plain);
    }

    /// Same as `deliver_pub_rtcp` but resolves the destination by the
    /// feedback's target media ssrc — used for blocks relayed from
    /// sibling shards, where only the owner's home shard can name it.
    fn deliver_pub_rtcp_by_ssrc(&mut self, room_id: u32, ssrc: u32, plain: &[u8]) {
        let Some(tk) = self.rooms.get(&room_id).and_then(|r| {
            r.locals
                .iter()
                .find(|(_, m)| m.ssrc_map.contains_key(&ssrc))
                .map(|(name, _)| TransportKey {
                    room: r.name.clone(),
                    participant: name.clone(),
                    leg: Leg::Pub,
                })
        }) else {
            return;
        };
        self.send_pub_rtcp(&tk, plain);
    }

    fn send_pub_rtcp(&mut self, tk: &TransportKey, plain: &[u8]) {
        let Some(leg) = self.transports.get_mut(tk) else {
            return;
        };
        if let Some((to, n)) = leg.t.protect_rtcp(plain, &mut self.scratch_out[..]) {
            let _ = self.socket.send_to(&self.scratch_out[..n], to);
        }
    }

    /// Emit the pending TWCC batch for one pub leg: build → protect →
    /// send. Free-standing over disjoint fields so it can run while a
    /// `transports` borrow is live.
    fn flush_twcc(socket: &UdpSocket, scratch: &mut [u8; 2048], leg: &mut LegState) {
        let Some(rx) = leg.rx.as_deref_mut() else {
            return;
        };
        if rx.tw_len == 0 {
            return;
        }
        // Convert absolute epoch ticks to incremental wire deltas and
        // derive the reference time — see `twcc_to_deltas`.
        let len = rx.tw_len as usize;
        let mut conv = [TwccStatus::NotReceived; 512];
        conv[..len].copy_from_slice(&rx.tw_statuses[..len]);
        let ref_time = twcc_to_deltas(&mut conv[..len]);
        let mut pkt = [0u8; 2048];
        let Ok(n) = rtcp::Twcc::build(
            &mut pkt,
            1,
            rx.tw_media_ssrc,
            rx.tw_base_seq,
            ref_time,
            rx.tw_fb_count,
            &conv[..len],
        ) else {
            rx.tw_len = 0;
            rx.tw_init = false;
            return;
        };
        if let Some((to, m)) = leg.t.protect_rtcp(&pkt[..n], &mut scratch[..]) {
            let _ = socket.send_to(&scratch[..m], to);
        }
        rx.tw_fb_count = rx.tw_fb_count.wrapping_add(1);
        rx.tw_len = 0;
        rx.tw_init = false;
        rx.tw_last_flush = Instant::now();
    }

    /// Emit a compound RR + SDES CNAME to one publisher leg when due
    /// (~1 s). sender_ssrc 1 is the media plane's RTCP identity.
    fn send_rr(socket: &UdpSocket, scratch: &mut [u8; 2048], leg: &mut LegState, now: Instant) {
        let Some(rx) = leg.rx.as_deref_mut() else {
            return;
        };
        if !rx.rr_due(now) {
            return;
        }
        rx.rr_last = now;
        let mut reports = [ReportBlock {
            ssrc: 0,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_seq: 0,
            jitter: 0,
            lsr: 0,
            dlsr: 0,
        }; 4];
        for (i, s) in rx.rr[..rx.rr_len].iter_mut().enumerate() {
            reports[i] = s.report(now);
        }
        let mut pkt = [0u8; 512];
        let Ok(mut n) = rtcp::ReceiverReport::build(&mut pkt, 1, &reports[..rx.rr_len])
        else {
            return;
        };
        if let Ok(m) = rtcp::Sdes::build_cname(&mut pkt[n..], 1, b"wroomd") {
            n += m;
        }
        if let Some((to, m)) = leg.t.protect_rtcp(&pkt[..n], &mut scratch[..]) {
            let _ = socket.send_to(&scratch[..m], to);
        }
    }

    /// Advance all transport timers (~20 ms granularity) and emit any
    /// receiver feedback that came due on publisher legs.
    fn on_tick(&mut self) {
        let now = Instant::now();
        let mut sends: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut dead: Vec<TransportKey> = Vec::new();
        for (key, leg) in self.transports.iter_mut() {
            for ev in leg.t.handle_timeout(now) {
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
            if leg.rx.is_some() {
                if leg.rx.as_ref().is_some_and(|rx| rx.twcc_due(now)) {
                    Self::flush_twcc(&self.socket, &mut self.scratch_out, leg);
                }
                Self::send_rr(&self.socket, &mut self.scratch_out, leg, now);
            }
        }
        for key in dead {
            self.drop_transport(&key);
        }
        for (to, data) in sends {
            let _ = self.socket.send_to(&data, to);
        }
        if now.saturating_duration_since(self.spk_last)
            >= std::time::Duration::from_millis(300)
        {
            self.spk_last = now;
            self.report_speakers(now);
        }
    }

    /// Compute this shard's per-room top-3 active speakers and push a
    /// partial to the router. Reported even when empty — an empty
    /// partial is what clears a publisher that went quiet or left.
    fn report_speakers(&mut self, now: Instant) {
        for (&room_id, r) in &self.rooms {
            let mut top: Vec<(String, f32)> = r
                .locals
                .iter()
                .filter(|(_, m)| {
                    m.spk_ewma > 0.02
                        && now.saturating_duration_since(m.spk_last_voice)
                            < std::time::Duration::from_millis(600)
                })
                .map(|(name, m)| (name.clone(), m.spk_ewma))
                .collect();
            top.sort_by(|a, b| {
                b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
            });
            top.truncate(3);
            if self
                .reports
                .push(ShardReport {
                    room_id,
                    shard: self.id,
                    top,
                })
                .is_err()
            {
                tracing::error!("speaker report ring full — partial dropped");
            }
        }
    }
}

/// Convert a TWCC status window's absolute arrival ticks (250 µs units
/// from the leg epoch) to the wire's *incremental* deltas in place, and
/// return the reference time in 64 ms units (24-bit). delta[i] =
/// arrival[i] − arrival[previous received]; the first received delta is
/// relative to `ref_time × 256` ticks. Reordered packets yield negative
/// deltas — legal large signed deltas; anything outside i16 clamps.
fn twcc_to_deltas(statuses: &mut [TwccStatus]) -> u32 {
    let base_abs = statuses
        .iter()
        .find_map(|s| match s {
            TwccStatus::Received(a) => Some(*a),
            _ => None,
        })
        .unwrap_or(0);
    let ref_time = (base_abs / 256) as u32 & 0xFF_FFFF;
    let mut prev = i64::from(ref_time) * 256;
    for s in statuses.iter_mut() {
        if let TwccStatus::Received(abs) = *s {
            let d = i64::from(abs) - prev;
            prev = i64::from(abs);
            *s = TwccStatus::Received(
                d.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i32,
            );
        }
    }
    ref_time
}

/// FwdMsg isn't Clone (inline 2KB buf is a memcpy) — an explicit copy
/// keeps it visible in profiles.
fn clone_msg(m: &FwdMsg) -> FwdMsg {
    FwdMsg {
        room_id: m.room_id,
        src_pid: m.src_pid,
        ssrc: m.ssrc,
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
    /// Shard active-speaker partials — drained on a ~300 ms interval.
    reports: Arc<ArrayQueue<ShardReport>>,
    /// Latest partial per (room, shard); a shard that reports empty
    /// clears its own stale entries by overwriting them.
    speaker_parts: HashMap<u32, HashMap<usize, Vec<(String, f32)>>>,
    /// What each room was last told + when — dedupe + ≤1 s heartbeat.
    speaker_sent: HashMap<u32, (Vec<String>, Instant)>,
}

impl Router {
    fn new(
        control_rx: mpsc::UnboundedReceiver<MediaControl>,
        shards: Vec<ShardCtlQ>,
        reports: Arc<ArrayQueue<ShardReport>>,
        n_shards: usize,
    ) -> Self {
        Self {
            rooms: HashMap::new(),
            next_room_id: 0,
            n_shards,
            shards,
            control_rx,
            dirty_offers: HashSet::new(),
            reports,
            speaker_parts: HashMap::new(),
            speaker_sent: HashMap::new(),
        }
    }

    async fn run(&mut self) {
        let mut spk_tick = tokio::time::interval(std::time::Duration::from_millis(300));
        loop {
            tokio::select! {
                c = self.control_rx.recv() => {
                    let Some(c) = c else { break };
                    self.on_control(c);
                    // Drain everything pending, then flush stale offers
                    // once — a burst of N publishes coalesces to one
                    // offer per member.
                    while let Ok(c) = self.control_rx.try_recv() {
                        self.on_control(c);
                    }
                    self.flush_offers();
                }
                _ = spk_tick.tick() => self.merge_speakers(),
            }
        }
        // Control plane is gone — take the shards down with it.
        for s in &self.shards {
            s.send(ShardCtl::Shutdown);
        }
    }

    /// Merge the shards' top-3 speaker partials into each room's global
    /// top-3, and broadcast `ActiveSpeakers` when the ordered id set
    /// changed or a second passed — ≤3.3 msgs/s/room.
    fn merge_speakers(&mut self) {
        while let Some(rep) = self.reports.pop() {
            self.speaker_parts
                .entry(rep.room_id)
                .or_default()
                .insert(rep.shard, rep.top);
        }
        let now = Instant::now();
        let live: HashSet<u32> = self.rooms.values().map(|r| r.id).collect();
        self.speaker_parts.retain(|rid, _| live.contains(rid));
        self.speaker_sent.retain(|rid, _| live.contains(rid));
        for r in self.rooms.values() {
            let mut merged: Vec<(String, f32)> = self
                .speaker_parts
                .get(&r.id)
                .into_iter()
                .flat_map(|m| m.values())
                .flatten()
                // A member can leave between the shard's snapshot and
                // now — never name a departed speaker.
                .filter(|(name, _)| r.members.contains_key(name))
                .cloned()
                .collect();
            merged.sort_by(|a, b| {
                b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
            });
            merged.truncate(3);
            let ids: Vec<String> = merged.iter().map(|s| s.0.clone()).collect();
            let emit = match self.speaker_sent.get(&r.id) {
                Some((last, at)) => {
                    *last != ids
                        || now.saturating_duration_since(*at)
                            >= std::time::Duration::from_secs(1)
                }
                None => !ids.is_empty(),
            };
            if !emit {
                continue;
            }
            self.speaker_sent.insert(r.id, (ids, now));
            self.broadcast(|_| ShardCtl::ActiveSpeakers {
                room_id: r.id,
                speakers: merged.clone(),
            });
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

        /// SRTCP-protect one plaintext compound RTCP datagram and send it.
        async fn send_rtcp(&mut self, rtcp: &[u8]) {
            let srtp = self.srtp.as_mut().expect("srtp installed");
            let mut buf = vec![0u8; rtcp.len() + SRTP_TAG_LEN + 8].into_boxed_slice();
            buf[..rtcp.len()].copy_from_slice(rtcp);
            let n = srtp
                .encrypt_rtcp(&mut buf, rtcp.len())
                .expect("protect rtcp");
            self.socket.send_to(&buf[..n], self.server).await.unwrap();
        }

        /// Receive the next inbound SRTCP datagram and return its
        /// plaintext, or `None` after `within`. Byte 1 in 192..=223 is
        /// the RTCP demux range (RFC 5761); anything else is skipped.
        async fn try_recv_rtcp(&mut self, within: Duration) -> Option<Vec<u8>> {
            let mut buf = vec![0u8; 2048].into_boxed_slice();
            timeout(within, async {
                loop {
                    let (n, _) = self.socket.recv_from(&mut buf).await.expect("recv");
                    let d = &mut buf[..n];
                    if d.len() < 2 || !(128..=255).contains(&d[0]) || !(192..=223).contains(&d[1]) {
                        continue;
                    }
                    let len = self
                        .srtp
                        .as_mut()
                        .expect("srtp installed")
                        .decrypt_rtcp(d)
                        .expect("rtcp packet must authenticate");
                    return d[..len].to_vec();
                }
            })
            .await
            .ok()
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

    /// Multi-m-line publisher offer: one sendonly section per track —
    /// (mid, kind, msid track id). Audio rides pt 111/opus, video 96/VP8.
    fn publisher_offer_tracks(
        identity: &DtlsIdentity,
        ufrag: &str,
        pwd: &str,
        tracks: &[(&str, MediaKind, &str)],
    ) -> String {
        let mids: Vec<&str> = tracks.iter().map(|t| t.0).collect();
        let mut sdp = format!(
            "v=0\r\no=- 4242 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE {}\r\na=msid-semantic: WMS\r\n",
            mids.join(" ")
        );
        for (mid, kind, tid) in tracks {
            let (mline, rtpmap) = match kind {
                MediaKind::Audio => (
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111",
                    "a=rtpmap:111 opus/48000/2",
                ),
                _ => ("m=video 9 UDP/TLS/RTP/SAVPF 96", "a=rtpmap:96 VP8/90000"),
            };
            sdp.push_str(&format!(
                "{mline}\r\n\
                 c=IN IP4 0.0.0.0\r\n\
                 a=rtcp:9 IN IP4 0.0.0.0\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=ice-options:trickle\r\n\
                 a=fingerprint:sha-256 {fp}\r\n\
                 a=setup:actpass\r\n\
                 a=mid:{mid}\r\n\
                 a=sendonly\r\n\
                 a=rtcp-mux\r\n\
                 a=msid:- {tid}\r\n\
                 {rtpmap}\r\n",
                fp = identity.fingerprint_sha256()
            ));
        }
        sdp
    }

    /// `canned_rtp` plus a one-byte-header extension block built from
    /// (id, value) pairs — audio-level (1), twcc (3), mid (4), etc.
    fn canned_rtp_ext(
        seq: u16,
        pt: u8,
        timestamp: u32,
        ssrc: u32,
        payload: &[u8],
        exts: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for (id, v) in exts {
            assert!(!v.is_empty() && v.len() <= 16);
            body.push((id << 4) | (v.len() as u8 - 1));
            body.extend_from_slice(v);
        }
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut p = Vec::with_capacity(16 + body.len() + payload.len());
        p.extend_from_slice(&[0x90, 0x80 | pt]); // V2 + extension bit
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&timestamp.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0xBE, 0xDE]);
        p.extend_from_slice(&((body.len() / 4) as u16).to_be_bytes());
        p.extend_from_slice(&body);
        p.extend_from_slice(payload);
        p
    }

    /// `canned_rtp` plus a one-byte-header extension block carrying a
    /// TWCC sequence (ext id 3) and a dummy abs-send-time (ext id 2) —
    /// the shape a Chrome publisher's packets take on the wire.
    fn canned_rtp_twcc(seq: u16, twcc: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(24 + payload.len());
        p.extend_from_slice(&[0x90, 0xE0]); // V2 + extension bit
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&timestamp.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x02]); // profile + 2 words
        p.push(0x31); // id 3, len-1 = 1 → 2-byte TWCC seq
        p.extend_from_slice(&twcc.to_be_bytes());
        p.push(0x22); // id 2, len-1 = 2 → 3-byte abs-send-time
        p.extend_from_slice(&[0x12, 0x34, 0x56]);
        p.push(0); // pad to the 32-bit boundary
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
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 1)
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
        assert!(rt.transports[&key_a_sub].t.is_connected());
        assert!(rt.transports[&key_b_pub].t.is_connected());
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

    /// Receiver-side feedback on the publisher leg: the shard must emit
    /// TWCC feedback covering the published stream's transport-wide seqs
    /// and a periodic RR with loss/jitter stats — Chrome's send-side BWE
    /// stalls at start bitrate without them. Subscriber feedback must be
    /// filtered: a compound RR+PLI delivers only the PLI, and only to
    /// the media-ssrc's owner.
    #[tokio::test]
    async fn pub_leg_receiver_feedback() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 1)
            .await
            .unwrap();
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        for (name, tx) in [("a", a_tx), ("b", b_tx)] {
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: name.into(),
                    reply: tx,
                })
                .unwrap();
        }
        // b's publisher leg up, "cam" published.
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
        let answer = Offer::parse(&answer_sdp).unwrap();
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        b_pub.nominate().await;
        b_pub.connect().await;
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
        // a's subscriber leg up.
        let offer_sdp = recv_sdp(
            &mut a.reply,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
        )
        .await;
        let sub_offer = Offer::parse(&offer_sdp).unwrap();
        let a_answer = subscriber_answer(&a.identity, &sub_offer, "aSubUfrag", "aSubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::SubscriberAnswer {
                room: room.clone(),
                participant: "a".into(),
                sdp: a_answer,
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut a_sub = FakeLeg::new(&a.identity, "aSubUfrag", &sub_offer).await;
        a_sub.nominate().await;
        a_sub.connect().await;
        tokio::time::sleep(Duration::from_millis(150)).await;

        // ── b publishes 50 packets with twcc seqs 0..50 ────────────
        const SSRC: u32 = 0xC0FF_EE01;
        for i in 0..50u16 {
            b_pub
                .send_media(&canned_rtp_twcc(
                    1000 + i,
                    i,
                    0x1000_0000 + u32::from(i) * 3000,
                    SSRC,
                    b"feedback-e2e",
                ))
                .await;
        }

        // ── a's sub leg sends a compound RR + PLI for b's ssrc ─────
        let mut compound = Vec::new();
        let mut scratch = [0u8; 256];
        let n = rtcp::ReceiverReport::build(
            &mut scratch,
            0xAAAA_0001,
            &[ReportBlock {
                ssrc: SSRC,
                fraction_lost: 9,
                cumulative_lost: 3,
                highest_seq: 42,
                jitter: 1,
                lsr: 0,
                dlsr: 0,
            }],
        )
        .unwrap();
        compound.extend_from_slice(&scratch[..n]);
        let n = rtcp::Pli::build(&mut scratch, 0xAAAA_0001, SSRC).unwrap();
        compound.extend_from_slice(&scratch[..n]);
        a_sub.send_rtcp(&compound).await;

        // ── Collect everything the shard sends b's pub leg ─────────
        let mut twcc_seen = [false; 50];
        let mut arrivals: Vec<i64> = Vec::new(); // reconstructed, 250µs ticks
        let mut saw_twcc = false;
        let mut rr_ok = false;
        let mut pli_only = false;
        let deadline = Instant::now() + Duration::from_millis(2500);
        while Instant::now() < deadline && !(saw_twcc && rr_ok && pli_only) {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(d) = b_pub.try_recv_rtcp(left.min(Duration::from_millis(200))).await
            else {
                continue;
            };
            let mut pli_in_datagram = false;
            let mut block_count = 0usize;
            for p in rtcp::packets(&d) {
                let Ok(p) = p else { break };
                block_count += 1;
                match p.kind() {
                    RtcpKind::Twcc(t) => {
                        assert_eq!(t.media_ssrc(), SSRC);
                        // Rebuild absolute arrival times: ref_time ×
                        // 64ms + cumulative (incremental) deltas — the
                        // decode Chrome's BWE performs.
                        let mut at = i64::from(t.reference_time()) * 256;
                        for (seq, st) in t.packets() {
                            if let TwccStatus::Received(d) = st {
                                at += i64::from(d);
                                if seq < 50 {
                                    twcc_seen[seq as usize] = true;
                                    arrivals.push(at);
                                }
                            }
                        }
                    }
                    RtcpKind::ReceiverReport(rr) => {
                        for r in rr.reports() {
                            if r.ssrc == SSRC {
                                assert!(r.highest_seq >= 1049, "RR highest_seq {}", r.highest_seq);
                                assert_eq!(r.fraction_lost, 0);
                                rr_ok = true;
                            }
                        }
                    }
                    RtcpKind::Pli(pli) => {
                        assert_eq!(pli.media_ssrc(), SSRC);
                        pli_in_datagram = true;
                    }
                    _ => {}
                }
            }
            // The relayed PLI must arrive alone — the subscriber's RR
            // must never be forwarded to a publisher.
            if pli_in_datagram {
                assert_eq!(block_count, 1, "PLI relayed alongside other blocks");
                pli_only = true;
            }
            saw_twcc = twcc_seen.iter().all(|s| *s);
        }
        assert!(saw_twcc, "TWCC feedback did not cover seqs 0..50");
        // Reconstructed arrivals must be monotone and span ≤300ms —
        // back-to-back loopback sends — which only holds if the wire
        // deltas are incremental, not absolute offsets.
        assert!(
            arrivals.windows(2).all(|w| w[0] <= w[1]),
            "reconstructed TWCC arrivals are not monotonic"
        );
        let span_ticks = arrivals.last().unwrap_or(&0) - arrivals.first().unwrap_or(&0);
        assert!(
            span_ticks <= 1200,
            "arrival span {}×250µs exceeds 300ms — deltas look absolute",
            span_ticks
        );
        assert!(rr_ok, "no RR for the published ssrc within the window");
        assert!(pli_only, "subscriber PLI was not relayed to the publisher");

        drop(ctl_tx);
        let h = handles.remove(0);
        timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
            .await
            .expect("shard exits")
            .expect("join")
            .expect("shard thread");
    }

    /// The PLI relay must survive the subscriber and publisher living on
    /// DIFFERENT shards: only the owner's home shard holds its ssrc_map,
    /// so the block has to cross the ring and be resolved there. Two
    /// shards puts a (pid 0) and b (pid 1) on different workers.
    #[tokio::test]
    async fn sub_feedback_crosses_shards() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 2)
            .await
            .unwrap();
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        for (name, tx) in [("a", a_tx), ("b", b_tx)] {
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: name.into(),
                    reply: tx,
                })
                .unwrap();
        }
        // b's publisher leg on shard 1.
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
        let answer = Offer::parse(&answer_sdp).unwrap();
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        b_pub.nominate().await;
        b_pub.connect().await;
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
        // a's subscriber leg on shard 0.
        let offer_sdp = recv_sdp(
            &mut a.reply,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
        )
        .await;
        let sub_offer = Offer::parse(&offer_sdp).unwrap();
        let a_answer = subscriber_answer(&a.identity, &sub_offer, "aSubUfrag", "aSubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::SubscriberAnswer {
                room: room.clone(),
                participant: "a".into(),
                sdp: a_answer,
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut a_sub = FakeLeg::new(&a.identity, "aSubUfrag", &sub_offer).await;
        a_sub.nominate().await;
        a_sub.connect().await;
        tokio::time::sleep(Duration::from_millis(150)).await;

        // b floods a few packets so its ssrc lands in shard 1's ssrc_map.
        const SSRC: u32 = 0xCAFE_0001;
        for i in 0..20u16 {
            b_pub
                .send_media(&canned_rtp(
                    2000 + i,
                    0x2000_0000 + u32::from(i) * 3000,
                    SSRC,
                    b"cross-shard-pli",
                ))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // a's sub leg (shard 0) PLIs b's ssrc — owner lives on shard 1.
        let mut scratch = [0u8; 64];
        let n = rtcp::Pli::build(&mut scratch, 0xBBBB_0001, SSRC).unwrap();
        a_sub.send_rtcp(&scratch[..n]).await;

        // The PLI must reach b's pub leg — via the shard ring.
        let mut got_pli = false;
        let deadline = Instant::now() + Duration::from_millis(2500);
        while Instant::now() < deadline && !got_pli {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(d) = b_pub.try_recv_rtcp(left.min(Duration::from_millis(200))).await
            else {
                continue;
            };
            for p in rtcp::packets(&d) {
                let Ok(p) = p else { break };
                if let RtcpKind::Pli(pli) = p.kind() {
                    assert_eq!(pli.media_ssrc(), SSRC);
                    got_pli = true;
                }
            }
        }
        assert!(got_pli, "cross-shard PLI never reached the publisher");

        drop(ctl_tx);
        for h in handles.drain(..) {
            timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
                .await
                .expect("shard exits")
                .expect("join")
                .expect("shard thread");
        }
    }

    /// Active-speaker pipeline: a publisher's audio-level extension
    /// feeds a per-member EWMA; the shard's top-3 partial reaches the
    /// router, which broadcasts the merged set to every member's reply
    /// channel. Loud publisher appears first; silence removes it.
    #[tokio::test]
    async fn active_speakers_from_audio_level() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 1)
            .await
            .unwrap();
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        for (name, tx) in [("a", a_tx), ("b", b_tx)] {
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: name.into(),
                    reply: tx,
                })
                .unwrap();
        }
        // b's publisher leg: a single audio m-line.
        let offer = publisher_offer_tracks(
            &b.identity,
            "bPubUfrag",
            "bPubPwd0000123456789abcdef",
            &[("0", MediaKind::Audio, "mic")],
        );
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: offer,
            })
            .unwrap();
        let answer_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer = Offer::parse(&answer_sdp).unwrap();
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        b_pub.nominate().await;
        b_pub.connect().await;

        // 30 audio packets at −20 dBov with the V bit set — loud voice.
        const SSRC: u32 = 0xAAAA_5501;
        for i in 0..30u16 {
            b_pub
                .send_media(&canned_rtp_ext(
                    100 + i,
                    111,
                    0x2000_0000 + u32::from(i) * 160,
                    SSRC,
                    b"audio-e2e",
                    &[(1, &[0x80 | 20])],
                ))
                .await;
        }

        // The merged update reaches every member — a publishes nothing
        // and still sees b named first.
        let deadline = Instant::now() + Duration::from_secs(2);
        let loud = timeout(deadline.saturating_duration_since(Instant::now()), async {
            loop {
                match a.reply.recv().await {
                    Some(ServerMessage {
                        msg: Some(server_message::Msg::ActiveSpeakers(s)),
                    }) if !s.speakers.is_empty() => return s,
                    Some(_) => continue,
                    None => panic!("reply channel closed early"),
                }
            }
        })
        .await
        .expect("no ActiveSpeakers within 2s of speech");
        assert_eq!(loud.speakers[0].participant_id, "b");
        assert!(
            loud.speakers[0].level > 0.02,
            "level {} should clear the active threshold",
            loud.speakers[0].level
        );

        // Voice stops → within ~1 s the room is told the set is empty.
        let deadline = Instant::now() + Duration::from_secs(3);
        timeout(deadline.saturating_duration_since(Instant::now()), async {
            loop {
                match a.reply.recv().await {
                    Some(ServerMessage {
                        msg: Some(server_message::Msg::ActiveSpeakers(s)),
                    }) if s.speakers.is_empty() => return,
                    Some(_) => continue,
                    None => panic!("reply channel closed early"),
                }
            }
        })
        .await
        .expect("no empty ActiveSpeakers after silence");

        drop(ctl_tx);
        let h = handles.remove(0);
        timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
            .await
            .expect("shard exits")
            .expect("join")
            .expect("shard thread");
    }

    /// Renegotiation: b re-offers on the SAME publisher leg, appending a
    /// third m-line (screen share). The subscriber's next offer carries
    /// canonical mid `m{pid}.2`, and media on the new track forwards
    /// under that mid — the transport was reused, not rebuilt.
    #[tokio::test]
    async fn publisher_reoffer_adds_third_mline() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 1)
            .await
            .unwrap();
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        for (name, tx) in [("a", a_tx), ("b", b_tx)] {
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: name.into(),
                    reply: tx,
                })
                .unwrap();
        }

        // b's publisher leg: audio mic + video cam (mids 0, 1).
        let offer = publisher_offer_tracks(
            &b.identity,
            "bPubUfrag",
            "bPubPwd0000123456789abcdef",
            &[
                ("0", MediaKind::Audio, "mic"),
                ("1", MediaKind::Video, "cam"),
            ],
        );
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: offer,
            })
            .unwrap();
        let answer_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer = Offer::parse(&answer_sdp).unwrap();
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        b_pub.nominate().await;
        b_pub.connect().await;

        let track = |id: &str, kind: proto::TrackKind, source: proto::TrackSource| proto::Track {
            id: id.into(),
            kind: kind as i32,
            source: source as i32,
            muted: false,
            layers: Vec::new(),
            mid: String::new(),
        };
        ctl_tx
            .send(MediaControl::TracksPublished {
                room: room.clone(),
                participant: "b".into(),
                tracks: vec![
                    track("mic", proto::TrackKind::Audio, proto::TrackSource::Microphone),
                    track("cam", proto::TrackKind::Video, proto::TrackSource::Camera),
                ],
            })
            .unwrap();
        // a's first sub offer covers b's two tracks (b is pid 1).
        let offer_sdp = recv_sdp(
            &mut a.reply,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
        )
        .await;
        let sub_offer = Offer::parse(&offer_sdp).unwrap();
        let mids: Vec<&str> = sub_offer
            .media
            .iter()
            .map(|m| m.mid.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(mids, ["m1.0", "m1.1"]);
        let a_answer = subscriber_answer(&a.identity, &sub_offer, "aSubUfrag", "aSubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::SubscriberAnswer {
                room: room.clone(),
                participant: "a".into(),
                sdp: a_answer,
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut a_sub = FakeLeg::new(&a.identity, "aSubUfrag", &sub_offer).await;
        a_sub.nominate().await;
        a_sub.connect().await;

        // ── Screen share: a new offer on the same pub leg, mids 0/1 ──
        // ── unchanged, new m-line "2". The transport must be reused. ─
        let reoffer = publisher_offer_tracks(
            &b.identity,
            "bPubUfrag",
            "bPubPwd0000123456789abcdef",
            &[
                ("0", MediaKind::Audio, "mic"),
                ("1", MediaKind::Video, "cam"),
                ("2", MediaKind::Video, "screen"),
            ],
        );
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: reoffer,
            })
            .unwrap();
        let answer2_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer2 = Offer::parse(&answer2_sdp).unwrap();
        assert_eq!(answer2.media.len(), 3);
        assert_eq!(
            answer2.ice_ufrag(),
            answer.ice_ufrag(),
            "transport reuse: local ICE creds are unchanged"
        );

        // Publish the screen track; a is re-offered with m1.2.
        ctl_tx
            .send(MediaControl::TracksPublished {
                room: room.clone(),
                participant: "b".into(),
                tracks: vec![track(
                    "screen",
                    proto::TrackKind::Video,
                    proto::TrackSource::Screenshare,
                )],
            })
            .unwrap();
        let offer_sdp = recv_sdp(
            &mut a.reply,
            proto::SignalTarget::Subscriber,
            proto::session_description::Type::Offer,
        )
        .await;
        let reoffer_sub = Offer::parse(&offer_sdp).unwrap();
        let mids: Vec<&str> = reoffer_sub
            .media
            .iter()
            .map(|m| m.mid.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(mids, ["m1.0", "m1.1", "m1.2"]);

        // Media on the new track (offer mid "2") forwards under the
        // canonical mid on the existing, un-renegotiated sub leg.
        const SSRC: u32 = 0x5C5E_EE02;
        let mut got = None;
        for seq in 1..=20u16 {
            b_pub
                .send_media(&canned_rtp_ext(
                    500 + seq,
                    96,
                    0x3000_0000 + u32::from(seq) * 3000,
                    SSRC,
                    b"screen-e2e",
                    &[(4, b"2")],
                ))
                .await;
            if let Some(plain) = a_sub.try_recv_media(Duration::from_millis(250)).await {
                got = Some(plain);
                break;
            }
        }
        let got = got.expect("screen media never reached a's sub leg");
        let parsed = RtpPacket::parse(&got).expect("forwarded packet parses");
        assert_eq!(
            parsed.mid(&wroom_edge::rtp::ExtMap::from_pairs(&[(
                4,
                wroom_edge::rtp::KnownExt::Mid
            )])),
            Some(b"m1.2".as_slice()),
            "third track forwards under canonical mid m1.2"
        );

        drop(ctl_tx);
        let h = handles.remove(0);
        let rt = timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
            .await
            .expect("shard exits")
            .expect("join")
            .expect("shard thread");
        let room0 = &rt.rooms[&0];
        // Canonical mid map covers all three offer mids, indices 0-2.
        let mt = &room0.locals["b"].mid_track;
        assert_eq!(mt.len(), 3);
        assert_eq!(mt["2"].canon.as_bytes(), b"m1.2");
    }

    /// ICE restart: a publisher re-offer whose remote ufrag changed must
    /// not tear down the leg — the same local creds answer, the new
    /// ufrag's checks re-nominate (possibly a new 5-tuple), and media
    /// keeps flowing under the untouched DTLS/SRTP context.
    #[tokio::test]
    async fn publisher_ice_restart_keeps_media_flowing() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let mut handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], 1)
            .await
            .unwrap();
        let room = "room".to_string();
        let (mut a, a_tx) = FakePeer::new();
        let (mut b, b_tx) = FakePeer::new();
        for (name, tx) in [("a", a_tx), ("b", b_tx)] {
            ctl_tx
                .send(MediaControl::Joined {
                    room: room.clone(),
                    participant: name.into(),
                    reply: tx,
                })
                .unwrap();
        }
        let offer = publisher_offer(&b.identity, "bPubUfrag", "bPubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: offer,
            })
            .unwrap();
        let answer_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer = Offer::parse(&answer_sdp).unwrap();
        let mut b_pub = FakeLeg::new(&b.identity, "bPubUfrag", &answer).await;
        b_pub.nominate().await;
        b_pub.connect().await;
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
        let sub_offer = Offer::parse(&offer_sdp).unwrap();
        let a_answer = subscriber_answer(&a.identity, &sub_offer, "aSubUfrag", "aSubPwd0000123456789abcdef");
        ctl_tx
            .send(MediaControl::SubscriberAnswer {
                room: room.clone(),
                participant: "a".into(),
                sdp: a_answer,
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut a_sub = FakeLeg::new(&a.identity, "aSubUfrag", &sub_offer).await;
        a_sub.nominate().await;
        a_sub.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Baseline: media flows.
        const SSRC: u32 = 0xBE57_0001;
        let mut forwarded = false;
        for seq in 1..=20u16 {
            b_pub
                .send_media(&canned_rtp(seq, 0x4000_0000 + u32::from(seq) * 3000, SSRC, b"pre"))
                .await;
            if a_sub
                .try_recv_media(Duration::from_millis(150))
                .await
                .is_some()
            {
                forwarded = true;
                break;
            }
        }
        assert!(forwarded, "baseline forward failed");

        // ── ICE restart: same offer shape, new remote creds ─────────
        let restart = publisher_offer(&b.identity, "bPubUfrag2", "bPubPwd9999888877776666");
        ctl_tx
            .send(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: "b".into(),
                sdp: restart,
            })
            .unwrap();
        let answer2_sdp = recv_sdp(
            &mut b.reply,
            proto::SignalTarget::Publisher,
            proto::session_description::Type::Answer,
        )
        .await;
        let answer2 = Offer::parse(&answer2_sdp).unwrap();
        assert_eq!(
            answer2.ice_ufrag(),
            answer.ice_ufrag(),
            "restart keeps local creds — transport and DTLS survive"
        );

        // The client re-checks from a fresh 5-tuple (e.g. a new
        // interface). Its SRTP context is unchanged — DTLS persisted.
        let mut b_pub2 = FakeLeg::new(&b.identity, "bPubUfrag2", &answer2).await;
        b_pub2.srtp = b_pub.srtp.take();
        b_pub2.nominate().await;

        let mut forwarded = false;
        for seq in 30..=60u16 {
            b_pub2
                .send_media(&canned_rtp(seq, 0x5000_0000 + u32::from(seq) * 3000, SSRC, b"post"))
                .await;
            if a_sub
                .try_recv_media(Duration::from_millis(150))
                .await
                .is_some()
            {
                forwarded = true;
                break;
            }
        }
        assert!(forwarded, "media did not flow after ICE restart");

        drop(ctl_tx);
        let h = handles.remove(0);
        let rt = timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || h.join()))
            .await
            .expect("shard exits")
            .expect("join")
            .expect("shard thread");
        let key_b_pub = TransportKey {
            room: room.clone(),
            participant: "b".into(),
            leg: Leg::Pub,
        };
        // Local creds never rotated: the one by_ufrag entry still routes
        // to the (same) transport; the new 5-tuple was nominated.
        assert_eq!(rt.by_ufrag.get(&b_pub2.server_ufrag), Some(&key_b_pub));
        assert_eq!(rt.by_addr.get(&b_pub2.local_addr()), Some(&key_b_pub));
        assert!(rt.transports[&key_b_pub].t.is_connected());
    }

    /// Absolute→incremental conversion: ref = floor(first/256); each
    /// received delta chains off the previous received arrival.
    #[test]
    fn twcc_to_deltas_converts_absolute_ticks() {
        let mut w = [
            TwccStatus::Received(1000),
            TwccStatus::Received(1004),
            TwccStatus::Received(1010),
        ];
        let r = twcc_to_deltas(&mut w);
        assert_eq!(r, 3); // 1000/256 = 3 → ref 768
        assert_eq!(
            w,
            [
                TwccStatus::Received(232),
                TwccStatus::Received(4),
                TwccStatus::Received(6)
            ]
        );

        // Gaps don't move the chain; a reorder produces a negative delta.
        let mut w = [
            TwccStatus::Received(1000),
            TwccStatus::NotReceived,
            TwccStatus::Received(996),
        ];
        let r = twcc_to_deltas(&mut w);
        assert_eq!(r, 3);
        assert_eq!(
            w,
            [
                TwccStatus::Received(232),
                TwccStatus::NotReceived,
                TwccStatus::Received(-4)
            ]
        );
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
        let handles = spawn_plane(ctl_rx, 0, vec!["127.0.0.1".to_string()], shards)
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
