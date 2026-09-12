//! Thin axum adapter between WebSocket binary frames and the Sans-IO
//! [`Session`]: decode `ClientMessage` → `Session::handle` → encode and
//! route the emitted `ServerMessage`s.
//!
//! Also owns broadcast delivery: every joined session registers an
//! outbound `mpsc` channel here, and `ToPeers` outputs are fanned out to
//! the other sessions in the same room. All shared state lives in [`Hub`]
//! behind a plain `Mutex` — this is the control plane (joins, publishes,
//! subscription updates), *not* the media hot path that AGENTS' lock-free
//! rules apply to (D12). The lock is never held across an `.await`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::sync::mpsc;
use wroom_core::room::Registry;

use crate::auth::TokenVerifier;
use crate::media::{MediaControl, MediaSink};
use crate::proto::{self, server_message, ClientMessage, ServerMessage};
use crate::session::{disconnect_message, Output, Session};

/// Per-session outbound queue depth. Bounded: a client that can't keep up
/// with room state is already far behind — overflow logs and drops rather
/// than applying backpressure to the whole room.
const OUTBOUND_CAPACITY: usize = 256;

/// Shared signaling state: the room registry plus one outbound channel
/// per joined session, keyed by participant id.
///
/// One `Mutex` serializes session handling. That's fine for a control
/// plane — message volume is tiny next to media — and it makes every
/// registry mutation + fan-out atomic: no session can observe a half-
/// applied `RoomDelta`.
pub struct Hub {
    inner: Mutex<HubInner>,
    verifier: Arc<dyn TokenVerifier>,
    /// Optional channel to the media runtime (wroomd wires it in; tests
    /// leave it `None`).
    media: Option<MediaSink>,
}

struct HubInner {
    registry: Registry,
    /// participant_id → that session's outbound queue. Entries are added
    /// on join (inside `dispatch`, under the lock, so no broadcast can
    /// slip between "in the room" and "reachable") and removed on close.
    outbounds: HashMap<String, mpsc::Sender<ServerMessage>>,
}

impl Hub {
    pub fn new(verifier: Arc<dyn TokenVerifier>) -> Self {
        Self {
            inner: Mutex::new(HubInner {
                registry: Registry::new(),
                outbounds: HashMap::new(),
            }),
            verifier,
            media: None,
        }
    }

    /// Attach the media-plane control channel (wroomd's media runtime).
    pub fn set_media(&mut self, sink: MediaSink) {
        self.media = Some(sink);
    }

    /// Post an event to the media plane, when one is attached.
    fn post_media(&self, msg: MediaControl) {
        if let Some(m) = &self.media {
            m.send(msg);
        }
    }

    /// A fresh Sans-IO session for a new socket.
    fn new_session(&self) -> Session {
        Session::new(Arc::clone(&self.verifier))
    }

    /// Read-only access to the registry (tests, diagnostics).
    pub fn with_registry<R>(&self, f: impl FnOnce(&Registry) -> R) -> R {
        f(&self.lock().registry)
    }

    fn lock(&self) -> MutexGuard<'_, HubInner> {
        // A poisoned lock would mean a session panicked mid-mutation;
        // the registry is still the best state we have — recover it.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Feed one decoded message through the session and deliver every
    /// resulting output: replies to this session, broadcasts to the
    /// room's other live sessions. Returns `true` when the session ended
    /// and the socket should close after flushing queued output.
    fn dispatch(
        &self,
        session: &mut Session,
        self_tx: &mpsc::Sender<ServerMessage>,
        msg: ClientMessage,
    ) -> bool {
        let mut inner = self.lock();
        let outputs = session.handle(msg, &mut inner.registry);
        if session.is_joined()
            && let Some(pid) = session.participant_id()
            && let std::collections::hash_map::Entry::Vacant(e) =
                inner.outbounds.entry(pid.to_string())
        {
            e.insert(self_tx.clone());
            if let Some(room) = session.room_id() {
                self.post_media(MediaControl::Joined {
                    room: room.to_string(),
                    participant: pid.to_string(),
                    reply: self_tx.clone(),
                });
            }
        }
        // Notify the media plane of newly parked SDP.
        let dirty = session.take_transport_dirty();
        let (room, pid) = match (session.room_id(), session.participant_id()) {
            (Some(r), Some(p)) => (r.to_string(), p.to_string()),
            _ => (String::new(), String::new()),
        };
        if dirty.publisher_sdp
            && let Some(sd) = &session.transport().publisher_sdp
            && !room.is_empty()
        {
            self.post_media(MediaControl::PublisherOffer {
                room: room.clone(),
                participant: pid.clone(),
                sdp: sd.sdp.clone(),
            });
        }
        if dirty.subscriber_sdp
            && let Some(sd) = &session.transport().subscriber_sdp
            && !room.is_empty()
        {
            self.post_media(MediaControl::SubscriberAnswer {
                room,
                participant: pid,
                sdp: sd.sdp.clone(),
            });
        }
        self.deliver(&mut inner, session, Some(self_tx), outputs)
    }

    /// The socket closed or errored without `LeaveRequest`: drop the
    /// participant from the room and fan out the `left` delta.
    fn on_transport_close(&self, session: &mut Session) {
        let mut inner = self.lock();
        let outputs = session.close(&mut inner.registry);
        if let Some(pid) = session.participant_id() {
            inner.outbounds.remove(pid);
            if let Some(room) = session.room_id() {
                self.post_media(MediaControl::Left {
                    room: room.to_string(),
                    participant: pid.to_string(),
                });
            }
        }
        // Self-directed output is moot — the socket is gone.
        self.deliver(&mut inner, session, None, outputs);
    }

    /// Route a batch of session outputs. Holds the lock the whole time so
    /// a peer observing a `RoomDelta` always sees post-update state.
    fn deliver(
        &self,
        inner: &mut HubInner,
        session: &Session,
        self_tx: Option<&mpsc::Sender<ServerMessage>>,
        outputs: Vec<Output>,
    ) -> bool {
        let mut close = false;
        for out in outputs {
            match out {
                Output::ToSelf(m) => {
                    if let Some(tx) = self_tx
                        && tx.try_send(m).is_err()
                    {
                        tracing::warn!("own outbound queue full; dropping reply");
                    }
                }
                Output::ToPeers(m) => {
                    // Mirror room-state changes into the media plane.
                    if let Some(room_id) = session.room_id()
                        && let Some(server_message::Msg::RoomDelta(d)) = &m.msg
                    {
                        if !d.published.is_empty() {
                            // One event per publisher per delta — a batch of
                            // tracks must produce a single re-offer, not one
                            // offer per track (racing offers wedge the
                            // subscriber PC).
                            let mut by_pid: HashMap<&str, Vec<proto::Track>> = HashMap::new();
                            for pub_track in &d.published {
                                if let Some(track) = &pub_track.track {
                                    by_pid
                                        .entry(pub_track.participant_id.as_str())
                                        .or_default()
                                        .push(track.clone());
                                }
                            }
                            for (pid, tracks) in by_pid {
                                self.post_media(MediaControl::TracksPublished {
                                    room: room_id.to_string(),
                                    participant: pid.to_string(),
                                    tracks,
                                });
                            }
                        }
                        for pid in &d.left {
                            self.post_media(MediaControl::Left {
                                room: room_id.to_string(),
                                participant: pid.clone(),
                            });
                        }
                    }
                    let Some(room_id) = session.room_id() else { continue };
                    let Some(room) = inner.registry.room(room_id) else {
                        continue;
                    };
                    let self_pid = session.participant_id();
                    for peer in room.participant_ids() {
                        if Some(peer) == self_pid {
                            continue;
                        }
                        match inner.outbounds.get(peer) {
                            Some(tx) => {
                                if tx.try_send(m.clone()).is_err() {
                                    // A full queue means the peer's
                                    // socket is wedged; the write half of
                                    // its task will error out and close.
                                    tracing::warn!(
                                        participant = peer,
                                        "outbound queue full; dropping room update"
                                    );
                                }
                            }
                            None => {
                                // Joined the registry but sender not yet
                                // registered cannot happen (same lock);
                                // a stale entry after close can.
                                tracing::warn!(
                                    participant = peer,
                                    "room member without outbound channel"
                                );
                            }
                        }
                    }
                }
                Output::Close => close = true,
            }
        }
        if close
            && let Some(pid) = session.participant_id()
        {
            inner.outbounds.remove(pid);
        }
        close
    }
}

/// Axum handler for `GET /ws`.
pub async fn handler(State(hub): State<Arc<Hub>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| run(socket, hub))
}

async fn run(socket: WebSocket, hub: Arc<Hub>) {
    let mut session = hub.new_session();
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(OUTBOUND_CAPACITY);

    loop {
        tokio::select! {
            // Outbound first (biased): keep replies and deltas flowing.
            biased;
            out = rx.recv() => match out {
                Some(msg) => {
                    if !send(&mut sink, msg).await {
                        break;
                    }
                }
                None => break, // impossible while `tx` lives below
            },
            frame = stream.next() => match frame {
                Some(Ok(WsMessage::Binary(bytes))) => match ClientMessage::decode(bytes) {
                    Ok(msg) => {
                        if hub.dispatch(&mut session, &tx, msg) {
                            flush(&mut rx, &mut sink).await;
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "undecodable client message");
                        let _ = tx.try_send(disconnect_message(
                            crate::proto::Reason::Unspecified,
                            "malformed message",
                        ));
                        flush(&mut rx, &mut sink).await;
                        break;
                    }
                },
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Err(e)) => {
                    tracing::debug!(error = %e, "websocket error");
                    break;
                }
                // Text frames don't exist in this protocol (D15: binary
                // protobuf); ws-level ping/pong is handled by tungstenite.
                Some(Ok(_)) => {}
            },
        }
    }

    hub.on_transport_close(&mut session);
    let _ = sink.close().await;
}

async fn send(sink: &mut SplitSink<WebSocket, WsMessage>, msg: ServerMessage) -> bool {
    sink.send(WsMessage::Binary(msg.encode_to_vec().into()))
        .await
        .is_ok()
}

/// Push out whatever is still queued — used right before we close the
/// socket so a `Disconnect` actually reaches the client.
async fn flush(rx: &mut mpsc::Receiver<ServerMessage>, sink: &mut SplitSink<WebSocket, WsMessage>) {
    while let Ok(msg) = rx.try_recv() {
        if !send(sink, msg).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DevTokenVerifier;
    use crate::proto::{self, client_message, server_message};
    use axum::{routing::get, Router};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message as TMsg;
    use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

    type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    async fn serve() -> String {
        let hub = Arc::new(Hub::new(Arc::new(DevTokenVerifier)));
        let app = Router::new()
            .route("/ws", get(handler))
            .with_state(hub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("ws://{addr}/ws")
    }

    fn encode(msg: client_message::Msg) -> TMsg {
        TMsg::Binary(
            ClientMessage { msg: Some(msg) }
                .encode_to_vec()
                .into(),
        )
    }

    fn join(token: &str) -> TMsg {
        encode(client_message::Msg::Join(proto::JoinRequest {
            token: token.to_string(),
            client: None,
            publisher_offer: None,
        }))
    }

    async fn recv(ws: &mut WsStream) -> ServerMessage {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for server message")
            .expect("stream ended")
            .expect("ws error");
        match frame {
            TMsg::Binary(b) => ServerMessage::decode(b).unwrap(),
            other => panic!("expected binary server message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_round_trip() {
        let url = serve().await;

        // Alice joins.
        let (mut a, _) = connect_async(&url).await.unwrap();
        a.send(join("room1:alice")).await.unwrap();
        let jr = match recv(&mut a).await.msg {
            Some(server_message::Msg::Join(j)) => j,
            other => panic!("expected JoinResponse, got {other:?}"),
        };
        let alice_id = jr.participant_id.clone();
        assert_eq!(jr.room.as_ref().unwrap().participants.len(), 1);
        assert!(jr.subscriber_offer.is_none());

        // Bob joins the same room; Alice sees the joined delta.
        let (mut b, _) = connect_async(&url).await.unwrap();
        b.send(join("room1:bob")).await.unwrap();
        let jr_b = match recv(&mut b).await.msg {
            Some(server_message::Msg::Join(j)) => j,
            other => panic!("expected JoinResponse, got {other:?}"),
        };
        let bob_id = jr_b.participant_id.clone();
        assert_ne!(alice_id, bob_id);
        assert_eq!(jr_b.room.as_ref().unwrap().participants.len(), 2);

        let delta = match recv(&mut a).await.msg {
            Some(server_message::Msg::RoomDelta(d)) => d,
            other => panic!("expected RoomDelta, got {other:?}"),
        };
        assert_eq!(delta.joined.len(), 1);
        assert_eq!(delta.joined[0].id, bob_id);
        assert_eq!(delta.joined[0].name, "bob");

        // Bob publishes a track; Alice sees it.
        b.send(encode(client_message::Msg::UpdateLocalTracks(
            proto::UpdateLocalTracks {
                publish: vec![proto::Track {
                    id: "cam".to_string(),
                    kind: proto::TrackKind::Video as i32,
                    source: proto::TrackSource::Camera as i32,
                    muted: false,
                    layers: vec![proto::Layer {
                        spatial: 0,
                        temporal: 0,
                    }],
                    mid: String::new(),
                }],
                unpublish: vec![],
            },
        )))
        .await
        .unwrap();
        let delta = match recv(&mut a).await.msg {
            Some(server_message::Msg::RoomDelta(d)) => d,
            other => panic!("expected RoomDelta, got {other:?}"),
        };
        assert_eq!(delta.published.len(), 1);
        assert_eq!(delta.published[0].participant_id, bob_id);
        assert_eq!(delta.published[0].track.as_ref().unwrap().id, "cam");

        // Bob's socket drops; Alice sees the left delta.
        b.close(None).await.unwrap();
        drop(b);
        let delta = match recv(&mut a).await.msg {
            Some(server_message::Msg::RoomDelta(d)) => d,
            other => panic!("expected RoomDelta, got {other:?}"),
        };
        assert_eq!(delta.left, vec![bob_id]);
    }

    #[tokio::test]
    async fn websocket_rejects_non_join_first() {
        let url = serve().await;
        let (mut c, _) = connect_async(&url).await.unwrap();
        c.send(encode(client_message::Msg::Pong(proto::Pong {
            timestamp_ms: 1,
        })))
        .await
        .unwrap();
        let msg = recv(&mut c).await;
        assert!(matches!(
            msg.msg,
            Some(server_message::Msg::Disconnect(_))
        ));
    }
}
