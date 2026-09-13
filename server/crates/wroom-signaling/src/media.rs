//! The control channel from the signaling plane to the media runtime.
//!
//! Signaling carries intent; the media worker owns all packet state
//! (AGENTS §4, share-nothing). These messages are how the session layer
//! tells the media plane what changed — participant joined, offer
//! parked, tracks published, gone. The media runtime keeps its own copy
//! of whatever it needs; nothing here is shared mutable state.

use tokio::sync::mpsc;

use crate::proto::{self, ServerMessage};

/// One room-state or negotiation event the media plane must react to.
#[derive(Debug)]
pub enum MediaControl {
    /// A session completed join: register its outbound channel so
    /// server-initiated signaling (subscriber offers) can reach it.
    Joined {
        room: String,
        participant: String,
        reply: mpsc::Sender<ServerMessage>,
    },
    /// The participant parked a publisher-leg SDP offer; answer it.
    PublisherOffer {
        room: String,
        participant: String,
        sdp: String,
    },
    /// The participant parked a subscriber-leg SDP answer.
    SubscriberAnswer {
        room: String,
        participant: String,
        sdp: String,
    },
    /// The participant published tracks (RoomDelta.published seen).
    TracksPublished {
        room: String,
        participant: String,
        tracks: Vec<proto::Track>,
    },
    /// The participant's subscription set changed — the full resolved
    /// wanted-track list, not a delta (the media plane keeps its own
    /// copy; latest wins).
    SubscriptionsChanged {
        room: String,
        participant: String,
        /// (owner participant, track id) pairs this member now wants.
        tracks: Vec<(String, String)>,
    },
    /// The participant's socket closed (or it left).
    Left { room: String, participant: String },
}

/// Cheap cloneable handle the hub uses to reach the media runtime.
#[derive(Clone)]
pub struct MediaSink(pub mpsc::UnboundedSender<MediaControl>);

impl MediaSink {
    pub fn send(&self, msg: MediaControl) {
        // Unbounded send only fails if the media task is gone; control
        // traffic volume is bounded by room churn, not packet rate.
        let _ = self.0.send(msg);
    }
}
