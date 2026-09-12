#![forbid(unsafe_code)]

//! The media-object model: the transport-agnostic core of the engine.
//!
//! Tracks, layers, and subscriptions. No RTP, socket, or transport types
//! belong in this crate — edges adapt transport to these objects.

/// In-memory room registry: participants, published tracks, subscriptions.
pub mod room;

/// A scalable layer: 0 is lowest on each axis.
///
/// `Ord` is lexicographic on `(spatial, temporal)`, so `a > b` means "a is
/// the higher-fidelity layer" for the dimensions receivers can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Layer {
    pub spatial: u32,
    pub temporal: u32,
}

/// Identifies a track within a room.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrackRef {
    pub participant_id: String,
    pub track_id: String,
}

/// A receiver's intent: which track, capped at which layer, at which priority.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub track: TrackRef,
    pub max_layer: Layer,
    pub priority: u32,
}
