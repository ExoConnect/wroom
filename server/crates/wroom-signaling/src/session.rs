//! The Sans-IO signaling session.
//!
//! A `Session` consumes decoded `ClientMessage`s against the room
//! `Registry` and yields `ServerMessage`s plus delivery intents
//! (`Output`). It performs no IO and owns no channel — the axum adapter
//! in `ws.rs` encodes, routes, and delivers — so the entire join/room
//! flow is unit-testable in-process.

use std::sync::Arc;

use wroom_core::room::{
    Participant, PublishOutcome, Registry, RegistryError, Room, TrackKind, TrackMeta, TrackSource,
};
use wroom_core::{Layer, Subscription, TrackRef};

use crate::auth::TokenVerifier;
use crate::proto::{self, client_message, server_message, ClientMessage, ServerMessage};

/// ICE candidates worth parking per signal target until the media edge
/// (M0b) consumes them. A browser trickles a handful per connection;
/// this is headroom, not a budget clients should fill.
const MAX_PARKED_CANDIDATES: usize = 256;

/// What the WS adapter must do with a message the session emitted.
#[derive(Debug)]
pub enum Output {
    /// Encode and send on this session's own socket.
    ToSelf(ServerMessage),
    /// Encode and send to every *other* joined session in the same room.
    ToPeers(ServerMessage),
    /// Close the socket once prior outputs are flushed.
    Close,
}

/// Bit flags marking which parked transport fields were updated since
/// the adapter last drained them.
#[derive(Debug, Default, Clone, Copy)]
pub struct TransportDirty {
    /// A new publisher-leg `SessionDescription` was parked.
    pub publisher_sdp: bool,
    /// A new subscriber-leg `SessionDescription` was parked.
    pub subscriber_sdp: bool,
}

/// Transport-negotiation material parked until the media edge (M0b) is
/// wired: session descriptions and trickled candidates per signal target.
/// Stored, logged, and otherwise untouched — signaling carries intent and
/// room state only until then.
#[derive(Debug, Default)]
pub struct TransportPark {
    /// Latest session description seen for each target. The publisher
    /// offer may arrive inside `JoinRequest`; later descriptions
    /// supersede earlier ones.
    pub publisher_sdp: Option<proto::SessionDescription>,
    pub subscriber_sdp: Option<proto::SessionDescription>,
    /// Trickled candidates per target; an empty batch marks the end.
    pub publisher_candidates: Vec<String>,
    pub subscriber_candidates: Vec<String>,
    pub publisher_candidates_done: bool,
    pub subscriber_candidates_done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingJoin,
    Joined,
    /// Terminal. Ids are retained (not cleared) so the adapter can route
    /// the final `left` delta and deregister the outbound channel.
    Closed,
}

/// One client connection's protocol state machine.
pub struct Session {
    verifier: Arc<dyn TokenVerifier>,
    state: State,
    participant_id: Option<String>,
    room_id: Option<String>,
    transport: TransportPark,
    transport_dirty: TransportDirty,
}

impl Session {
    pub fn new(verifier: Arc<dyn TokenVerifier>) -> Self {
        Self {
            verifier,
            state: State::AwaitingJoin,
            participant_id: None,
            room_id: None,
            transport: TransportPark::default(),
            transport_dirty: TransportDirty::default(),
        }
    }

    /// Server-assigned participant id, once joined. Still `Some` after
    /// close so teardown can route the `left` delta.
    pub fn participant_id(&self) -> Option<&str> {
        self.participant_id.as_deref()
    }

    /// Room this session belongs to. Still `Some` after close.
    pub fn room_id(&self) -> Option<&str> {
        self.room_id.as_deref()
    }

    /// True while the session may process room messages.
    pub fn is_joined(&self) -> bool {
        self.state == State::Joined
    }

    /// True once the session is terminal (leave or rejection).
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Parked transport negotiation state, for the media edge (M0b).
    pub fn transport(&self) -> &TransportPark {
        &self.transport
    }

    /// Which parked transport fields changed since the last drain; the
    /// adapter calls this once per handled message to notify the media
    /// plane of newly arrived SDP.
    pub fn take_transport_dirty(&mut self) -> TransportDirty {
        std::mem::take(&mut self.transport_dirty)
    }

    /// Drive the state machine with one decoded client message.
    /// The first message on a fresh session must be `join`.
    pub fn handle(&mut self, msg: ClientMessage, registry: &mut Registry) -> Vec<Output> {
        match self.state {
            State::AwaitingJoin => match msg.msg {
                Some(client_message::Msg::Join(req)) => self.on_join(req, registry),
                Some(_) => self.reject("first message must be join"),
                None => self.reject("empty client message"),
            },
            State::Joined => self.on_room_message(msg, registry),
            State::Closed => Vec::new(),
        }
    }

    /// The socket went away without a `LeaveRequest`: remove the
    /// participant and yield the `left` broadcast. Idempotent.
    pub fn close(&mut self, registry: &mut Registry) -> Vec<Output> {
        match self.remove_from_room(registry) {
            Some(delta) => vec![Output::ToPeers(delta)],
            None => Vec::new(),
        }
    }

    // ── Join ──────────────────────────────────────────────────────────

    /// Send `Disconnect` and close: the session is terminal from here.
    fn reject(&mut self, detail: impl Into<String>) -> Vec<Output> {
        self.state = State::Closed;
        vec![
            Output::ToSelf(disconnect_message(proto::Reason::Unspecified, detail)),
            Output::Close,
        ]
    }

    fn on_join(&mut self, req: proto::JoinRequest, registry: &mut Registry) -> Vec<Output> {
        let Some(claims) = self.verifier.verify(&req.token) else {
            return self.reject("invalid token");
        };
        if let Some(client) = &req.client {
            tracing::info!(
                client = %client.name,
                version = %client.version,
                room = %claims.room_id,
                "client joining"
            );
        }
        // A pre-warmed publisher offer rides along inside JoinRequest so
        // negotiation can finish in one round trip — park it for M0b.
        if let Some(offer) = req.publisher_offer {
            tracing::debug!(target = ?offer.target(), "parked publisher offer from join");
            self.transport.publisher_sdp = Some(offer);
            self.transport_dirty.publisher_sdp = true;
        }
        match registry.join(&claims.room_id, &claims.display_name) {
            Ok(participant_id) => {
                self.participant_id = Some(participant_id.clone());
                self.room_id = Some(claims.room_id.clone());
                self.state = State::Joined;

                let room = registry.room(&claims.room_id).expect("room just joined");
                let join_response = ServerMessage {
                    msg: Some(server_message::Msg::Join(proto::JoinResponse {
                        participant_id: participant_id.clone(),
                        room: Some(proto_room(room)),
                        // No STUN/TURN config in M0a; the subscriber
                        // connection's server offer lands with the media
                        // edge in M0b.
                        ice_servers: Vec::new(),
                        subscriber_offer: None,
                    })),
                };
                let me = room
                    .participant(&participant_id)
                    .expect("participant just inserted");
                let joined = ServerMessage {
                    msg: Some(server_message::Msg::RoomDelta(proto::RoomDelta {
                        joined: vec![proto_participant(me)],
                        ..Default::default()
                    })),
                };
                tracing::info!(
                    room = %claims.room_id,
                    participant = %participant_id,
                    name = %claims.display_name,
                    "joined"
                );
                vec![Output::ToSelf(join_response), Output::ToPeers(joined)]
            }
            Err(e) => {
                tracing::warn!(error = %e, room = %claims.room_id, "join rejected");
                self.reject(format!("join rejected: {e}"))
            }
        }
    }

    // ── Joined ────────────────────────────────────────────────────────

    fn on_room_message(&mut self, msg: ClientMessage, registry: &mut Registry) -> Vec<Output> {
        match msg.msg {
            Some(client_message::Msg::Join(_)) => self.reject("already joined"),
            Some(client_message::Msg::SessionDescription(sd)) => {
                self.park_sdp(sd);
                Vec::new()
            }
            Some(client_message::Msg::IceCandidates(ic)) => {
                self.park_candidates(ic);
                Vec::new()
            }
            Some(client_message::Msg::UpdateSubscriptions(us)) => {
                vec![self.on_update_subscriptions(us, registry)]
            }
            Some(client_message::Msg::UpdateLocalTracks(ult)) => {
                self.on_update_local_tracks(ult, registry)
            }
            Some(client_message::Msg::Pong(_)) => Vec::new(),
            Some(client_message::Msg::Leave(_)) => self.on_leave(registry),
            None => Vec::new(),
        }
    }

    /// `UpdateLocalTracks`: publish new tracks, apply updates (mute
    /// flips fan out), remove unpublished ones — then broadcast a single
    /// combined `RoomDelta` to the room's other sessions.
    fn on_update_local_tracks(
        &mut self,
        ult: proto::UpdateLocalTracks,
        registry: &mut Registry,
    ) -> Vec<Output> {
        let (room_id, pid) = (self.room_id.clone().expect("joined"), self.participant_id.clone().expect("joined"));
        let mut delta = proto::RoomDelta::default();

        for track in ult.publish {
            let meta = core_track_meta(&track);
            match registry.publish(&room_id, &pid, &track.id, meta) {
                Ok(PublishOutcome {
                    is_new: true, ..
                }) => {
                    delta.published.push(proto::TrackPublished {
                        participant_id: pid.clone(),
                        track: Some(track),
                    });
                }
                Ok(PublishOutcome {
                    mute_change: Some(muted),
                    ..
                }) => {
                    delta.mute_changes.push(proto::TrackMuted {
                        track: Some(proto::TrackRef {
                            participant_id: pid.clone(),
                            track_id: track.id,
                        }),
                        muted,
                    });
                }
                Ok(_) => {
                    // Re-publish where only layers/mid changed: registry
                    // updated, nothing worth a delta.
                }
                Err(e) => {
                    tracing::warn!(error = %e, track = %track.id, "publish rejected")
                }
            }
        }

        for track_id in ult.unpublish {
            match registry.unpublish(&room_id, &pid, &track_id) {
                Ok(true) => delta.unpublished.push(proto::TrackRef {
                    participant_id: pid.clone(),
                    track_id,
                }),
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, track = %track_id, "unpublish rejected")
                }
            }
        }

        if room_delta_is_empty(&delta) {
            Vec::new()
        } else {
            vec![Output::ToPeers(ServerMessage {
                msg: Some(server_message::Msg::RoomDelta(delta)),
            })]
        }
    }

    /// `UpdateSubscriptions`: apply the batch to the registry, then echo
    /// the revision actually applied. Grants stay empty until the media
    /// edge exists to forward layers (M0b).
    fn on_update_subscriptions(
        &mut self,
        us: proto::UpdateSubscriptions,
        registry: &mut Registry,
    ) -> Output {
        let (room_id, pid) = (self.room_id.clone().expect("joined"), self.participant_id.clone().expect("joined"));
        let upsert: Vec<Subscription> = us.upsert.iter().filter_map(core_subscription).collect();
        let remove: Vec<TrackRef> = us.remove.iter().map(core_track_ref).collect();

        let applied_revision = match registry.update_subscriptions(
            &room_id,
            &pid,
            upsert,
            remove,
            us.revision,
        ) {
            Ok(rev) => rev,
            Err(RegistryError::StaleRevision { applied }) => {
                tracing::debug!(revision = us.revision, applied, "stale subscription update");
                applied
            }
            Err(e) => {
                tracing::warn!(error = %e, "subscription update rejected");
                last_applied_revision(registry, &room_id, &pid)
            }
        };
        Output::ToSelf(ServerMessage {
            msg: Some(server_message::Msg::SubscriptionUpdate(
                proto::SubscriptionUpdate {
                    grants: Vec::new(),
                    applied_revision,
                },
            )),
        })
    }

    /// `LeaveRequest`: ack with a `Disconnect`, drop the participant, and
    /// broadcast the `left` delta.
    fn on_leave(&mut self, registry: &mut Registry) -> Vec<Output> {
        let mut out = vec![Output::ToSelf(disconnect_message(
            proto::Reason::ClientLeft,
            "bye",
        ))];
        if let Some(delta) = self.remove_from_room(registry) {
            out.push(Output::ToPeers(delta));
        }
        out.push(Output::Close);
        out
    }

    /// Remove this session's participant from the room; yields the `left`
    /// broadcast when something was actually removed. Marks the session
    /// closed either way.
    fn remove_from_room(&mut self, registry: &mut Registry) -> Option<ServerMessage> {
        self.state = State::Closed;
        let (room_id, pid) = (self.room_id()?, self.participant_id()?);
        registry.leave(room_id, pid).then(|| {
            tracing::info!(room = %room_id, participant = %pid, "left");
            ServerMessage {
                msg: Some(server_message::Msg::RoomDelta(proto::RoomDelta {
                    left: vec![pid.to_string()],
                    ..Default::default()
                })),
            }
        })
    }

    // ── Transport parking (for M0b) ───────────────────────────────────

    fn park_sdp(&mut self, sd: proto::SessionDescription) {
        tracing::debug!(
            target = ?sd.target(),
            r#type = ?sd.r#type(),
            sdp_len = sd.sdp.len(),
            "session description parked"
        );
        match sd.target() {
            proto::SignalTarget::Publisher => {
                self.transport.publisher_sdp = Some(sd);
                self.transport_dirty.publisher_sdp = true;
            }
            proto::SignalTarget::Subscriber => {
                self.transport.subscriber_sdp = Some(sd);
                self.transport_dirty.subscriber_sdp = true;
            }
            _ => tracing::warn!("session description with unspecified target dropped"),
        }
    }

    fn park_candidates(&mut self, ic: proto::IceCandidates) {
        let (buf, done, label) = match ic.target() {
            proto::SignalTarget::Publisher => (
                &mut self.transport.publisher_candidates,
                &mut self.transport.publisher_candidates_done,
                "publisher",
            ),
            proto::SignalTarget::Subscriber => (
                &mut self.transport.subscriber_candidates,
                &mut self.transport.subscriber_candidates_done,
                "subscriber",
            ),
            _ => {
                tracing::warn!("ice candidates with unspecified target dropped");
                return;
            }
        };
        if ic.candidates.is_empty() {
            *done = true; // empty list = end-of-candidates
        } else {
            let room = MAX_PARKED_CANDIDATES.saturating_sub(buf.len());
            let take = ic.candidates.len().min(room);
            if take < ic.candidates.len() {
                tracing::warn!(target = label, "candidate park full; dropping excess");
            }
            buf.extend(ic.candidates.into_iter().take(take));
        }
        tracing::debug!(target = label, parked = buf.len(), "ice candidates parked");
    }
}

fn last_applied_revision(registry: &Registry, room_id: &str, pid: &str) -> u64 {
    registry
        .room(room_id)
        .and_then(|r| r.participant(pid))
        .and_then(|p| p.applied_subscription_revision())
        .unwrap_or(0)
}

/// Build a `Disconnect` server message. `pub(crate)` so the WS adapter
/// can fail decoding sessions identically.
pub(crate) fn disconnect_message(
    reason: proto::Reason,
    detail: impl Into<String>,
) -> ServerMessage {
    ServerMessage {
        msg: Some(server_message::Msg::Disconnect(proto::Disconnect {
            reason: reason as i32,
            detail: detail.into(),
        })),
    }
}

fn room_delta_is_empty(d: &proto::RoomDelta) -> bool {
    d.joined.is_empty()
        && d.left.is_empty()
        && d.published.is_empty()
        && d.unpublished.is_empty()
        && d.mute_changes.is_empty()
}

// ── proto ↔ core conversions ───────────────────────────────────────────
// The registry is transport-agnostic and knows nothing of protobuf;
// adaptation lives here at the signaling edge.

fn core_layer(l: proto::Layer) -> Layer {
    Layer {
        spatial: l.spatial,
        temporal: l.temporal,
    }
}

fn proto_layer(l: Layer) -> proto::Layer {
    proto::Layer {
        spatial: l.spatial,
        temporal: l.temporal,
    }
}

fn core_track_ref(t: &proto::TrackRef) -> TrackRef {
    TrackRef {
        participant_id: t.participant_id.clone(),
        track_id: t.track_id.clone(),
    }
}

fn core_track_meta(t: &proto::Track) -> TrackMeta {
    TrackMeta {
        kind: match t.kind() {
            proto::TrackKind::Audio => TrackKind::Audio,
            proto::TrackKind::Video => TrackKind::Video,
            _ => TrackKind::Unspecified,
        },
        source: match t.source() {
            proto::TrackSource::Camera => TrackSource::Camera,
            proto::TrackSource::Microphone => TrackSource::Microphone,
            proto::TrackSource::Screenshare => TrackSource::Screenshare,
            proto::TrackSource::ScreenshareAudio => TrackSource::ScreenshareAudio,
            _ => TrackSource::Unspecified,
        },
        muted: t.muted,
        layers: t.layers.iter().copied().map(core_layer).collect(),
        mid: t.mid.clone(),
    }
}

/// A missing `max_layer` means "send the best you have".
const UNBOUNDED_LAYER: Layer = Layer {
    spatial: u32::MAX,
    temporal: u32::MAX,
};

fn core_subscription(s: &proto::Subscription) -> Option<Subscription> {
    let track = s.track.as_ref().map(core_track_ref)?;
    Some(Subscription {
        track,
        max_layer: s.max_layer.map(core_layer).unwrap_or(UNBOUNDED_LAYER),
        priority: s.priority,
    })
}

fn proto_track(track_id: &str, meta: &TrackMeta) -> proto::Track {
    proto::Track {
        id: track_id.to_string(),
        kind: match meta.kind {
            TrackKind::Audio => proto::TrackKind::Audio,
            TrackKind::Video => proto::TrackKind::Video,
            TrackKind::Unspecified => proto::TrackKind::Unspecified,
        } as i32,
        source: match meta.source {
            TrackSource::Camera => proto::TrackSource::Camera,
            TrackSource::Microphone => proto::TrackSource::Microphone,
            TrackSource::Screenshare => proto::TrackSource::Screenshare,
            TrackSource::ScreenshareAudio => proto::TrackSource::ScreenshareAudio,
            TrackSource::Unspecified => proto::TrackSource::Unspecified,
        } as i32,
        muted: meta.muted,
        layers: meta.layers.iter().copied().map(proto_layer).collect(),
        mid: meta.mid.clone(),
    }
}

fn proto_participant(p: &Participant) -> proto::Participant {
    proto::Participant {
        id: p.id().to_string(),
        name: p.name().to_string(),
        tracks: p.tracks().map(|(id, m)| proto_track(id, m)).collect(),
    }
}

fn proto_room(room: &Room) -> proto::Room {
    proto::Room {
        id: room.id().to_string(),
        participants: room.participants().map(proto_participant).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DevTokenVerifier;

    fn session() -> Session {
        Session::new(Arc::new(DevTokenVerifier))
    }

    fn client_msg(msg: client_message::Msg) -> ClientMessage {
        ClientMessage { msg: Some(msg) }
    }

    fn join_msg(token: &str) -> ClientMessage {
        client_msg(client_message::Msg::Join(proto::JoinRequest {
            token: token.to_string(),
            client: Some(proto::ClientInfo {
                name: "test".to_string(),
                version: "0".to_string(),
            }),
            publisher_offer: None,
        }))
    }

    fn track(id: &str, muted: bool) -> proto::Track {
        proto::Track {
            id: id.to_string(),
            kind: proto::TrackKind::Video as i32,
            source: proto::TrackSource::Camera as i32,
            muted,
            layers: vec![proto::Layer {
                spatial: 0,
                temporal: 0,
            }],
            mid: String::new(),
        }
    }

    /// Extract `ToSelf` payloads.
    fn to_self(outputs: &[Output]) -> Vec<&ServerMessage> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::ToSelf(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    /// Extract `ToPeers` payloads.
    fn to_peers(outputs: &[Output]) -> Vec<&ServerMessage> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::ToPeers(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    fn has_close(outputs: &[Output]) -> bool {
        outputs.iter().any(|o| matches!(o, Output::Close))
    }

    fn as_join_response(m: &ServerMessage) -> &proto::JoinResponse {
        match &m.msg {
            Some(server_message::Msg::Join(j)) => j,
            other => panic!("expected JoinResponse, got {other:?}"),
        }
    }

    fn as_room_delta(m: &ServerMessage) -> &proto::RoomDelta {
        match &m.msg {
            Some(server_message::Msg::RoomDelta(d)) => d,
            other => panic!("expected RoomDelta, got {other:?}"),
        }
    }

    #[test]
    fn join_end_to_end() {
        let mut reg = Registry::new();
        let mut s = session();

        let out = s.handle(join_msg("room1:alice"), &mut reg);
        assert_eq!(out.len(), 2);
        assert!(s.is_joined());
        assert_eq!(s.participant_id(), Some("p0"));
        assert_eq!(s.room_id(), Some("room1"));

        // First output: JoinResponse with snapshot including self.
        let jr = as_join_response(to_self(&out)[0]);
        assert_eq!(jr.participant_id, "p0");
        let room = jr.room.as_ref().unwrap();
        assert_eq!(room.id, "room1");
        assert_eq!(room.participants.len(), 1);
        assert_eq!(room.participants[0].name, "alice");
        assert!(jr.ice_servers.is_empty());
        assert!(jr.subscriber_offer.is_none());

        // Second output: `joined` delta for existing peers (none yet —
        // the adapter will fan it out to whoever else is in the room).
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.joined.len(), 1);
        assert_eq!(d.joined[0].id, "p0");
    }

    #[test]
    fn second_join_sees_first_participant() {
        let mut reg = Registry::new();
        let mut a = session();
        let mut b = session();
        a.handle(join_msg("r:alice"), &mut reg);
        let out = b.handle(join_msg("r:bob"), &mut reg);

        let jr = as_join_response(to_self(&out)[0]);
        let room = jr.room.as_ref().unwrap();
        assert_eq!(room.participants.len(), 2);
        // Bob's joined-delta announces only Bob.
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.joined.len(), 1);
        assert_eq!(d.joined[0].name, "bob");
    }

    #[test]
    fn rejects_non_join_first_message() {
        let mut reg = Registry::new();
        for first in [
            client_msg(client_message::Msg::Pong(proto::Pong { timestamp_ms: 1 })),
            client_msg(client_message::Msg::Leave(proto::LeaveRequest {})),
            client_msg(client_message::Msg::UpdateLocalTracks(
                proto::UpdateLocalTracks::default(),
            )),
            ClientMessage { msg: None },
        ] {
            let mut s = session();
            let out = s.handle(first, &mut reg);
            let self_msgs = to_self(&out);
            assert_eq!(self_msgs.len(), 1);
            assert!(matches!(
                self_msgs[0].msg,
                Some(server_message::Msg::Disconnect(_))
            ));
            assert!(has_close(&out));
            assert!(s.is_closed());
            // Terminal: nothing further is processed.
            assert!(s.handle(join_msg("r:a"), &mut reg).is_empty());
        }
    }

    #[test]
    fn rejects_bad_tokens() {
        let mut reg = Registry::new();
        for token in ["", "nocolon", ":name", "room:", "ro om:name"] {
            let mut s = session();
            let out = s.handle(join_msg(token), &mut reg);
            assert!(matches!(
                to_self(&out)[0].msg,
                Some(server_message::Msg::Disconnect(_))
            ));
            assert!(has_close(&out));
            assert!(!s.is_joined());
        }
        assert_eq!(reg.room_count(), 0);
    }

    #[test]
    fn rejects_double_join() {
        let mut reg = Registry::new();
        let mut s = session();
        s.handle(join_msg("r:alice"), &mut reg);
        let out = s.handle(join_msg("r:mallory"), &mut reg);
        assert!(matches!(
            to_self(&out)[0].msg,
            Some(server_message::Msg::Disconnect(_))
        ));
        assert!(has_close(&out));
        assert!(s.is_closed());
    }

    #[test]
    fn publish_mute_unpublish_deltas() {
        let mut reg = Registry::new();
        let mut s = session();
        s.handle(join_msg("r:alice"), &mut reg);

        // Publish a camera track → published delta.
        let out = s.handle(
            client_msg(client_message::Msg::UpdateLocalTracks(
                proto::UpdateLocalTracks {
                    publish: vec![track("cam", false)],
                    unpublish: vec![],
                },
            )),
            &mut reg,
        );
        let peers = to_peers(&out);
        assert_eq!(peers.len(), 1);
        let d = as_room_delta(peers[0]);
        assert_eq!(d.published.len(), 1);
        assert_eq!(d.published[0].participant_id, "p0");
        assert_eq!(d.published[0].track.as_ref().unwrap().id, "cam");
        assert!(d.unpublished.is_empty() && d.mute_changes.is_empty());

        // Mute it via re-publish → mute_changes delta.
        let out = s.handle(
            client_msg(client_message::Msg::UpdateLocalTracks(
                proto::UpdateLocalTracks {
                    publish: vec![track("cam", true)],
                    unpublish: vec![],
                },
            )),
            &mut reg,
        );
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.mute_changes.len(), 1);
        assert_eq!(d.mute_changes[0].track.as_ref().unwrap().track_id, "cam");
        assert!(d.mute_changes[0].muted);

        // Same state again → no-op, no delta.
        let out = s.handle(
            client_msg(client_message::Msg::UpdateLocalTracks(
                proto::UpdateLocalTracks {
                    publish: vec![track("cam", true)],
                    unpublish: vec![],
                },
            )),
            &mut reg,
        );
        assert!(out.is_empty());

        // Unpublish → unpublished delta.
        let out = s.handle(
            client_msg(client_message::Msg::UpdateLocalTracks(
                proto::UpdateLocalTracks {
                    publish: vec![],
                    unpublish: vec!["cam".to_string()],
                },
            )),
            &mut reg,
        );
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.unpublished.len(), 1);
        assert_eq!(d.unpublished[0].track_id, "cam");
        // Registry agrees: participant has no tracks left.
        let room = reg.room("r").unwrap();
        assert_eq!(room.participant("p0").unwrap().tracks().count(), 0);
    }

    #[test]
    fn subscription_revision_echoed() {
        let mut reg = Registry::new();
        let mut s = session();
        s.handle(join_msg("r:alice"), &mut reg);

        let upsert = proto::Subscription {
            track: Some(proto::TrackRef {
                participant_id: "pX".to_string(),
                track_id: "cam".to_string(),
            }),
            max_layer: Some(proto::Layer {
                spatial: 1,
                temporal: 0,
            }),
            priority: 3,
        };
        let out = s.handle(
            client_msg(client_message::Msg::UpdateSubscriptions(
                proto::UpdateSubscriptions {
                    upsert: vec![upsert.clone()],
                    remove: vec![],
                    revision: 7,
                },
            )),
            &mut reg,
        );
        let self_msgs = to_self(&out);
        assert_eq!(self_msgs.len(), 1);
        let Some(server_message::Msg::SubscriptionUpdate(su)) = &self_msgs[0].msg else {
            panic!("expected SubscriptionUpdate")
        };
        assert_eq!(su.applied_revision, 7);
        assert!(su.grants.is_empty()); // no media plane yet

        // The subscription landed in the registry.
        let p = reg.room("r").unwrap().participant("p0").unwrap();
        assert_eq!(p.subscriptions().count(), 1);
        assert_eq!(p.applied_subscription_revision(), Some(7));

        // A stale revision is echoed with the applied one.
        let out = s.handle(
            client_msg(client_message::Msg::UpdateSubscriptions(
                proto::UpdateSubscriptions {
                    upsert: vec![upsert],
                    remove: vec![],
                    revision: 5,
                },
            )),
            &mut reg,
        );
        let Some(server_message::Msg::SubscriptionUpdate(su)) = &to_self(&out)[0].msg else {
            panic!("expected SubscriptionUpdate")
        };
        assert_eq!(su.applied_revision, 7);
    }

    #[test]
    fn leave_broadcasts_left() {
        let mut reg = Registry::new();
        let mut a = session();
        let mut b = session();
        a.handle(join_msg("r:alice"), &mut reg);
        b.handle(join_msg("r:bob"), &mut reg);

        let out = b.handle(
            client_msg(client_message::Msg::Leave(proto::LeaveRequest {})),
            &mut reg,
        );
        // Ack to self, left-delta to peers, close.
        assert!(matches!(
            to_self(&out)[0].msg,
            Some(server_message::Msg::Disconnect(_))
        ));
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.left, vec!["p1".to_string()]);
        assert!(has_close(&out));
        assert!(b.is_closed());
        // Registry reflects the departure.
        assert_eq!(reg.room("r").unwrap().len(), 1);
    }

    #[test]
    fn transport_close_broadcasts_left() {
        let mut reg = Registry::new();
        let mut a = session();
        let mut b = session();
        a.handle(join_msg("r:alice"), &mut reg);
        b.handle(join_msg("r:bob"), &mut reg);

        // Socket dies without LeaveRequest.
        let out = b.close(&mut reg);
        let d = as_room_delta(to_peers(&out)[0]);
        assert_eq!(d.left, vec!["p1".to_string()]);
        // Idempotent: a second close yields nothing.
        assert!(b.close(&mut reg).is_empty());
    }

    #[test]
    fn empty_room_is_destroyed() {
        let mut reg = Registry::new();
        let mut s = session();
        s.handle(join_msg("ephemeral:alice"), &mut reg);
        s.close(&mut reg);
        assert!(reg.room("ephemeral").is_none());
    }

    #[test]
    fn transport_messages_are_parked_not_answered() {
        let mut reg = Registry::new();
        let mut s = session();

        // Offer can ride inside the join.
        let mut join = join_msg("r:alice");
        if let Some(client_message::Msg::Join(j)) = &mut join.msg {
            j.publisher_offer = Some(proto::SessionDescription {
                target: proto::SignalTarget::Publisher as i32,
                r#type: proto::session_description::Type::Offer as i32,
                sdp: "v=0 ...".to_string(),
            });
        }
        s.handle(join, &mut reg);
        assert!(s.transport().publisher_sdp.is_some());

        // Answer for the subscriber PC + trickle: parked, no outputs.
        let out = s.handle(
            client_msg(client_message::Msg::SessionDescription(
                proto::SessionDescription {
                    target: proto::SignalTarget::Subscriber as i32,
                    r#type: proto::session_description::Type::Answer as i32,
                    sdp: "v=0 answer".to_string(),
                },
            )),
            &mut reg,
        );
        assert!(out.is_empty());
        let out = s.handle(
            client_msg(client_message::Msg::IceCandidates(proto::IceCandidates {
                target: proto::SignalTarget::Subscriber as i32,
                candidates: vec!["candidate:1 ...".to_string()],
            })),
            &mut reg,
        );
        assert!(out.is_empty());
        assert_eq!(s.transport().subscriber_candidates.len(), 1);
        assert!(s.transport().subscriber_sdp.is_some());
    }
}
