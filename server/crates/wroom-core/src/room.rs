//! In-memory room registry: participants, published tracks, and
//! per-participant subscription sets.
//!
//! This is control-plane state: it answers "who is in the room, what did
//! they publish, who wants what". It is *not* the media hot path — the
//! forwarding plane will consume flat snapshots derived from this data, so
//! these structures favor clarity and boundedness over per-packet cost.
//!
//! Everything is bounded (see the `MAX_*` constants); excess is rejected,
//! never silently grown.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{Layer, Subscription, TrackRef};

// ── Bounds ─────────────────────────────────────────────────────────────

/// Rooms are ephemeral and destroyed when empty; this only bounds
/// pathological accumulation between the last leave and the cleanup.
pub const MAX_ROOMS: usize = 1024;
/// "Hundreds of active cameras per room" is the design target.
pub const MAX_PARTICIPANTS_PER_ROOM: usize = 512;
/// Camera + mic + screenshare + screenshare-audio, with headroom.
pub const MAX_TRACKS_PER_PARTICIPANT: usize = 16;
/// Spatial × temporal encodings a single track may advertise.
pub const MAX_LAYERS_PER_TRACK: usize = 8;
/// One subscription per remote track at full occupancy, with headroom.
/// Overflow rejects the whole update rather than evicting by accident —
/// receivers learn from the (absent) grants what was not applied.
pub const MAX_SUBSCRIPTIONS_PER_PARTICIPANT: usize = 2048;
/// Wire-facing string caps; anything longer is rejected, not truncated.
pub const MAX_ID_LEN: usize = 128;
pub const MAX_NAME_LEN: usize = 128;
/// An m-line index string; real mids are tiny.
pub const MAX_MID_LEN: usize = 64;

/// What a published track carries. Media metadata only — no RTP or
/// transport concepts belong here (D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackKind {
    Unspecified,
    Audio,
    Video,
}

/// What the track is sourced from; drives receiver defaults (e.g. a
/// screenshare wants full layers, a camera tile may not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackSource {
    Unspecified,
    Camera,
    Microphone,
    Screenshare,
    ScreenshareAudio,
}

/// Everything the room needs to know about one published track.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackMeta {
    pub kind: TrackKind,
    pub source: TrackSource,
    pub muted: bool,
    /// Layers the publisher can produce (simulcast encodings or SVC
    /// layers). Truncated to [`MAX_LAYERS_PER_TRACK`] on publish.
    pub layers: Vec<Layer>,
    /// m-line binding on the transport, set once negotiated.
    pub mid: String,
}

/// What changed when [`Registry::publish`] accepted a track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishOutcome {
    /// True when the track id was not previously published.
    pub is_new: bool,
    /// `Some(muted)` when an existing track's mute flag flipped.
    /// Non-mute field updates (layers, mid) are applied silently.
    pub mute_change: Option<bool>,
}

/// A room member: identity, published tracks, and the set of remote
/// tracks it wants delivered.
#[derive(Debug)]
pub struct Participant {
    id: String,
    name: String,
    /// track_id → metadata. BTreeMap for deterministic snapshot ordering.
    tracks: BTreeMap<String, TrackMeta>,
    /// track ref → receiver intent. Keyed flatly by remote track so
    /// "replace existing for the same track" is a single upsert.
    subscriptions: BTreeMap<TrackRef, Subscription>,
    /// Last client `UpdateSubscriptions.revision` the registry applied.
    /// `None` until the first update lands; stale revisions are rejected
    /// so a delayed batch cannot resurrect old intent.
    applied_subscription_revision: Option<u64>,
}

impl Participant {
    fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            tracks: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            applied_subscription_revision: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// (track_id, meta) pairs in deterministic (sorted) order.
    pub fn tracks(&self) -> impl Iterator<Item = (&str, &TrackMeta)> {
        self.tracks.iter().map(|(id, m)| (id.as_str(), m))
    }

    pub fn track(&self, track_id: &str) -> Option<&TrackMeta> {
        self.tracks.get(track_id)
    }

    pub fn subscriptions(&self) -> impl Iterator<Item = &Subscription> {
        self.subscriptions.values()
    }

    /// The last client subscription revision actually applied, if any.
    pub fn applied_subscription_revision(&self) -> Option<u64> {
        self.applied_subscription_revision
    }
}

/// One meeting: a set of participants keyed by server-assigned id.
#[derive(Debug)]
pub struct Room {
    id: String,
    /// participant_id → participant. Flat; lookups are by id, iteration
    /// order is deterministic for snapshots and tests.
    participants: BTreeMap<String, Participant>,
}

impl Room {
    fn new(id: String) -> Self {
        Self {
            id,
            participants: BTreeMap::new(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn participants(&self) -> impl Iterator<Item = &Participant> {
        self.participants.values()
    }

    pub fn participant_ids(&self) -> impl Iterator<Item = &str> {
        self.participants.keys().map(String::as_str)
    }

    pub fn participant(&self, participant_id: &str) -> Option<&Participant> {
        self.participants.get(participant_id)
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
}

/// Why a registry operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Empty or over-long identifier / name.
    InvalidInput,
    /// Server-wide room cap reached.
    TooManyRooms,
    /// Room is at [`MAX_PARTICIPANTS_PER_ROOM`].
    RoomFull,
    NoSuchRoom,
    NoSuchParticipant,
    NoSuchTrack,
    /// Participant is at [`MAX_TRACKS_PER_PARTICIPANT`].
    TooManyTracks,
    /// The update would exceed [`MAX_SUBSCRIPTIONS_PER_PARTICIPANT`];
    /// nothing was applied.
    TooManySubscriptions,
    /// The revision is not newer than the one already applied; nothing
    /// was applied. Carries the current applied revision to echo back.
    StaleRevision { applied: u64 },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid input"),
            Self::TooManyRooms => write!(f, "too many rooms"),
            Self::RoomFull => write!(f, "room is full"),
            Self::NoSuchRoom => write!(f, "no such room"),
            Self::NoSuchParticipant => write!(f, "no such participant"),
            Self::NoSuchTrack => write!(f, "no such track"),
            Self::TooManyTracks => write!(f, "too many tracks"),
            Self::TooManySubscriptions => write!(f, "too many subscriptions"),
            Self::StaleRevision { applied } => {
                write!(f, "stale subscription revision (applied: {applied})")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// The room directory. Rooms are created lazily on join and destroyed as
/// soon as they empty (D16: a room ends when empty).
///
/// Participant ids are server-assigned from a monotonically increasing
/// sequence (`p0`, `p1`, …) so they are unguessable-agnostic and unique
/// for the life of the registry — an id is never reused.
#[derive(Debug, Default)]
pub struct Registry {
    rooms: BTreeMap<String, Room>,
    next_participant_seq: u64,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn room(&self, room_id: &str) -> Option<&Room> {
        self.rooms.get(room_id)
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Add a participant, creating the room if needed. Returns the
    /// server-assigned participant id.
    pub fn join(&mut self, room_id: &str, name: &str) -> Result<String, RegistryError> {
        if room_id.is_empty() || room_id.len() > MAX_ID_LEN {
            return Err(RegistryError::InvalidInput);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(RegistryError::InvalidInput);
        }
        if !self.rooms.contains_key(room_id) {
            if self.rooms.len() >= MAX_ROOMS {
                return Err(RegistryError::TooManyRooms);
            }
            self.rooms.insert(room_id.to_string(), Room::new(room_id.to_string()));
        }
        let room = self.rooms.get_mut(room_id).expect("room just ensured");
        if room.participants.len() >= MAX_PARTICIPANTS_PER_ROOM {
            return Err(RegistryError::RoomFull);
        }
        let participant_id = format!("p{}", self.next_participant_seq);
        self.next_participant_seq += 1;
        room.participants.insert(
            participant_id.clone(),
            Participant::new(participant_id.clone(), name.to_string()),
        );
        Ok(participant_id)
    }

    /// Remove a participant; destroys the room once it is empty.
    /// Returns whether the participant was present.
    pub fn leave(&mut self, room_id: &str, participant_id: &str) -> bool {
        let Some(room) = self.rooms.get_mut(room_id) else {
            return false;
        };
        let removed = room.participants.remove(participant_id).is_some();
        if room.participants.is_empty() {
            self.rooms.remove(room_id);
        }
        removed
    }

    /// Insert or update a published track. Publishing an existing track id
    /// is an update; a flipped `muted` flag is reported so callers can
    /// fan it out.
    pub fn publish(
        &mut self,
        room_id: &str,
        participant_id: &str,
        track_id: &str,
        mut meta: TrackMeta,
    ) -> Result<PublishOutcome, RegistryError> {
        if track_id.is_empty() || track_id.len() > MAX_ID_LEN {
            return Err(RegistryError::InvalidInput);
        }
        meta.layers.truncate(MAX_LAYERS_PER_TRACK);
        meta.mid.truncate(MAX_MID_LEN);
        let participant = self.participant_mut(room_id, participant_id)?;
        let is_new = !participant.tracks.contains_key(track_id);
        if is_new && participant.tracks.len() >= MAX_TRACKS_PER_PARTICIPANT {
            return Err(RegistryError::TooManyTracks);
        }
        match participant.tracks.entry(track_id.to_string()) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let mute_change = (e.get().muted != meta.muted).then_some(meta.muted);
                *e.get_mut() = meta;
                Ok(PublishOutcome {
                    is_new: false,
                    mute_change,
                })
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(meta);
                Ok(PublishOutcome {
                    is_new: true,
                    mute_change: None,
                })
            }
        }
    }

    /// Remove a published track. Returns whether it existed.
    pub fn unpublish(
        &mut self,
        room_id: &str,
        participant_id: &str,
        track_id: &str,
    ) -> Result<bool, RegistryError> {
        let participant = self.participant_mut(room_id, participant_id)?;
        Ok(participant.tracks.remove(track_id).is_some())
    }

    /// Flip a track's mute flag. Returns whether it changed.
    pub fn set_muted(
        &mut self,
        room_id: &str,
        participant_id: &str,
        track_id: &str,
        muted: bool,
    ) -> Result<bool, RegistryError> {
        let participant = self.participant_mut(room_id, participant_id)?;
        let track = participant
            .tracks
            .get_mut(track_id)
            .ok_or(RegistryError::NoSuchTrack)?;
        if track.muted == muted {
            return Ok(false);
        }
        track.muted = muted;
        Ok(true)
    }

    /// Apply a batched subscription delta for a participant.
    ///
    /// Removes are applied first, then upserts (an upsert wins over a
    /// remove for the same track). The batch is all-or-nothing: if the
    /// revision is stale or the result would exceed the per-participant
    /// cap, nothing is applied and the error says why.
    ///
    /// Subscribing to a not-yet-published or nonexistent track is allowed —
    /// a track can appear after the subscription; grants decide what is
    /// actually forwarded.
    ///
    /// Returns the applied revision on success.
    pub fn update_subscriptions(
        &mut self,
        room_id: &str,
        participant_id: &str,
        upsert: Vec<Subscription>,
        remove: Vec<TrackRef>,
        revision: u64,
    ) -> Result<u64, RegistryError> {
        let participant = self.participant_mut(room_id, participant_id)?;
        if let Some(applied) = participant.applied_subscription_revision
            && revision <= applied
        {
            return Err(RegistryError::StaleRevision { applied });
        }

        // Project the post-update size without applying, so the cap check
        // is atomic: remove what's really gone, add what's really new.
        // Both lists are deduped — a repeated key must only count once.
        let upsert_keys: BTreeSet<&TrackRef> = upsert.iter().map(|s| &s.track).collect();
        let remove_keys: BTreeSet<&TrackRef> = remove.iter().collect();
        let mut projected = participant.subscriptions.len();
        for t in &remove_keys {
            if participant.subscriptions.contains_key(*t) && !upsert_keys.contains(*t) {
                projected -= 1;
            }
        }
        for key in &upsert_keys {
            if !participant.subscriptions.contains_key(*key) {
                projected += 1;
            }
        }
        if projected > MAX_SUBSCRIPTIONS_PER_PARTICIPANT {
            return Err(RegistryError::TooManySubscriptions);
        }

        for t in &remove {
            participant.subscriptions.remove(t);
        }
        for sub in upsert {
            participant.subscriptions.insert(sub.track.clone(), sub);
        }
        participant.applied_subscription_revision = Some(revision);
        Ok(revision)
    }

    fn participant_mut(
        &mut self,
        room_id: &str,
        participant_id: &str,
    ) -> Result<&mut Participant, RegistryError> {
        self.rooms
            .get_mut(room_id)
            .ok_or(RegistryError::NoSuchRoom)?
            .participants
            .get_mut(participant_id)
            .ok_or(RegistryError::NoSuchParticipant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tref(pid: &str, tid: &str) -> TrackRef {
        TrackRef {
            participant_id: pid.to_string(),
            track_id: tid.to_string(),
        }
    }

    fn meta(muted: bool) -> TrackMeta {
        TrackMeta {
            kind: TrackKind::Video,
            source: TrackSource::Camera,
            muted,
            layers: vec![
                Layer {
                    spatial: 0,
                    temporal: 0,
                },
                Layer {
                    spatial: 1,
                    temporal: 0,
                },
            ],
            mid: "0".to_string(),
        }
    }

    fn sub(pid: &str, tid: &str, priority: u32) -> Subscription {
        Subscription {
            track: tref(pid, tid),
            max_layer: Layer {
                spatial: 1,
                temporal: 0,
            },
            priority,
        }
    }

    #[test]
    fn join_assigns_unique_ids_and_snapshots() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();
        let b = reg.join("room", "bob").unwrap();
        assert_ne!(a, b);

        let room = reg.room("room").unwrap();
        assert_eq!(room.len(), 2);
        let names: Vec<&str> = room.participants().map(|p| p.name()).collect();
        assert!(names.contains(&"alice") && names.contains(&"bob"));
        assert_eq!(room.participant(&a).unwrap().id(), a);
    }

    #[test]
    fn join_rejects_bad_input() {
        let mut reg = Registry::new();
        assert_eq!(reg.join("", "alice"), Err(RegistryError::InvalidInput));
        assert_eq!(reg.join("room", ""), Err(RegistryError::InvalidInput));
        assert_eq!(
            reg.join("room", &"x".repeat(MAX_NAME_LEN + 1)),
            Err(RegistryError::InvalidInput)
        );
    }

    #[test]
    fn leave_removes_participant_and_empty_room() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();
        assert!(!reg.leave("room", "ghost"));
        assert!(reg.leave("room", &a));
        assert!(!reg.leave("room", &a));
        assert!(reg.room("room").is_none(), "empty room must be destroyed");
        assert_eq!(reg.room_count(), 0);
    }

    #[test]
    fn room_capacity_is_bounded() {
        let mut reg = Registry::new();
        for i in 0..MAX_PARTICIPANTS_PER_ROOM {
            reg.join("room", &format!("user{i}")).unwrap();
        }
        assert_eq!(reg.join("room", "one-too-many"), Err(RegistryError::RoomFull));
        // A different room still works.
        reg.join("other", "fine").unwrap();
    }

    #[test]
    fn room_count_is_bounded() {
        let mut reg = Registry::new();
        for i in 0..MAX_ROOMS {
            reg.join(&format!("room{i}"), "alice").unwrap();
        }
        assert_eq!(
            reg.join("one-more-room", "alice"),
            Err(RegistryError::TooManyRooms)
        );
    }

    #[test]
    fn publish_unpublish_and_mute() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();

        let out = reg.publish("room", &a, "cam", meta(false)).unwrap();
        assert!(out.is_new && out.mute_change.is_none());

        // Re-publish with the same mute flag: an update, not a delta.
        let out = reg.publish("room", &a, "cam", meta(false)).unwrap();
        assert!(!out.is_new && out.mute_change.is_none());

        // Mute flip via re-publish is reported.
        let out = reg.publish("room", &a, "cam", meta(true)).unwrap();
        assert!(!out.is_new && out.mute_change == Some(true));

        // Explicit mute op agrees.
        assert!(!reg.set_muted("room", &a, "cam", true).unwrap());
        assert!(reg.set_muted("room", &a, "cam", false).unwrap());
        assert_eq!(
            reg.set_muted("room", &a, "ghost", true),
            Err(RegistryError::NoSuchTrack)
        );

        assert!(reg.unpublish("room", &a, "cam").unwrap());
        assert!(!reg.unpublish("room", &a, "cam").unwrap());
        assert_eq!(
            reg.unpublish("room", "ghost-participant", "cam"),
            Err(RegistryError::NoSuchParticipant)
        );
    }

    #[test]
    fn track_count_is_bounded_and_layers_truncated() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();
        for i in 0..MAX_TRACKS_PER_PARTICIPANT {
            reg.publish("room", &a, &format!("t{i}"), meta(false)).unwrap();
        }
        assert_eq!(
            reg.publish("room", &a, "overflow", meta(false)),
            Err(RegistryError::TooManyTracks)
        );
        // Re-publishing an existing id is an update, not growth.
        reg.publish("room", &a, "t0", meta(false)).unwrap();

        let mut fat = meta(false);
        fat.layers = vec![
            Layer {
                spatial: 0,
                temporal: 0
            };
            MAX_LAYERS_PER_TRACK + 3
        ];
        reg.publish("room", &a, "t0", fat).unwrap();
        assert_eq!(
            reg.room("room").unwrap().participant(&a).unwrap().track("t0").unwrap().layers.len(),
            MAX_LAYERS_PER_TRACK
        );
    }

    #[test]
    fn subscriptions_upsert_remove_and_revision() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();
        let b = reg.join("room", "bob").unwrap();
        reg.publish("room", &b, "cam", meta(false)).unwrap();

        // First update applies and records the revision.
        let rev = reg
            .update_subscriptions("room", &a, vec![sub(&b, "cam", 1)], vec![], 1)
            .unwrap();
        assert_eq!(rev, 1);
        let room = reg.room("room").unwrap();
        let pa = room.participant(&a).unwrap();
        assert_eq!(pa.applied_subscription_revision(), Some(1));
        assert_eq!(pa.subscriptions().count(), 1);
        assert_eq!(pa.subscriptions().next().unwrap().priority, 1);

        // Re-upsert of the same track replaces, doesn't grow.
        reg.update_subscriptions("room", &a, vec![sub(&b, "cam", 9)], vec![], 2)
            .unwrap();
        let pa = reg.room("room").unwrap().participant(&a).unwrap();
        assert_eq!(pa.subscriptions().count(), 1);
        assert_eq!(pa.subscriptions().next().unwrap().priority, 9);

        // Stale revision is rejected and nothing changes.
        assert_eq!(
            reg.update_subscriptions("room", &a, vec![], vec![tref(&b, "cam")], 1),
            Err(RegistryError::StaleRevision { applied: 2 })
        );
        let pa = reg.room("room").unwrap().participant(&a).unwrap();
        assert_eq!(pa.subscriptions().count(), 1);

        // Remove works; subscribing to a nonexistent track is allowed.
        reg.update_subscriptions("room", &a, vec![], vec![tref(&b, "cam")], 3)
            .unwrap();
        reg.update_subscriptions("room", &a, vec![sub("ghost", "t", 0)], vec![], 4)
            .unwrap();
        let pa = reg.room("room").unwrap().participant(&a).unwrap();
        assert_eq!(pa.subscriptions().count(), 1);
    }

    #[test]
    fn subscription_cap_is_atomic() {
        let mut reg = Registry::new();
        let a = reg.join("room", "alice").unwrap();
        let upserts: Vec<Subscription> = (0..MAX_SUBSCRIPTIONS_PER_PARTICIPANT)
            .map(|i| sub("pub", &format!("t{i}"), 0))
            .collect();
        reg.update_subscriptions("room", &a, upserts, vec![], 1).unwrap();

        // One more would exceed the cap → whole batch rejected.
        assert_eq!(
            reg.update_subscriptions("room", &a, vec![sub("pub", "extra", 0)], vec![], 2),
            Err(RegistryError::TooManySubscriptions)
        );
        let pa = reg.room("room").unwrap().participant(&a).unwrap();
        assert_eq!(pa.subscriptions().count(), MAX_SUBSCRIPTIONS_PER_PARTICIPANT);
        assert_eq!(pa.applied_subscription_revision(), Some(1));

        // Remove one, then the same upsert fits again.
        reg.update_subscriptions("room", &a, vec![], vec![tref("pub", "t0")], 2)
            .unwrap();
        reg.update_subscriptions("room", &a, vec![sub("pub", "extra", 0)], vec![], 3)
            .unwrap();
    }
}
