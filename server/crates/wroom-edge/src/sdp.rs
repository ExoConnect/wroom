//! SDP offer parsing and answer generation for the WebRTC edge.
//!
//! Signaling (`wroom.signaling.v1.SessionDescription`) carries SDP as an
//! opaque blob; this module is the one place that blob is understood.
//!
//! * [`SessionDescription::parse`] turns a browser offer into typed data:
//!   transport credentials, per-m-line payload descriptions, header
//!   extensions, simulcast layers, and announced SSRCs. Unknown lines are
//!   skipped; malformed known lines produce a typed [`SdpError`].
//! * [`SessionDescription::answer`] produces a minimal bundle-only,
//!   rtcp-mux, ICE-lite answer a browser accepts, driven by
//!   [`AnswerConfig`].
//!
//! The parser is hand-rolled: SDP (RFC 4566 plus the WebRTC extensions) is
//! a line-based text format and negotiation runs once per PeerConnection at
//! join time, so a dependency-free line parser is sufficient.

use std::collections::BTreeMap;
use std::fmt;

/// Largest SDP blob we accept. Browser offers are a few KiB up to a few
/// tens of KiB even with many m-lines; anything larger is rejected up
/// front so a hostile blob cannot make us allocate without bound.
const MAX_SDP_BYTES: usize = 512 * 1024;

/// Most media sections we will hold for one session description.
const MAX_MEDIA_SECTIONS: usize = 256;

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors from parsing an SDP document or generating an answer.
#[derive(Debug, thiserror::Error)]
pub enum SdpError {
    /// The blob exceeds [`MAX_SDP_BYTES`].
    #[error("session description too large ({0} bytes)")]
    TooLarge(usize),

    /// A line did not have the `<type>=<value>` shape.
    #[error("line {0}: expected <type>=<value>")]
    InvalidLine(usize),

    /// The `v=` line was missing or not `v=0`.
    #[error("missing or unsupported SDP version")]
    UnsupportedVersion,

    /// A required session-level line never appeared.
    #[error("required {0} line missing")]
    Missing(&'static str),

    /// A recognized line or attribute had a malformed value.
    #[error("line {line}: malformed {what}")]
    Malformed {
        /// 1-based line number in the document.
        line: usize,
        /// What failed to parse, e.g. `"m= line"` or `"a=rtpmap attribute"`.
        what: &'static str,
    },

    /// More than [`MAX_MEDIA_SECTIONS`] `m=` sections.
    #[error("too many media sections")]
    TooManyMedia,

    /// [`SessionDescription::answer`] was asked for something impossible.
    #[error("cannot generate answer: {0}")]
    Answer(&'static str),
}

// ── Session-level value types ────────────────────────────────────────────

/// The `o=` origin line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    /// e.g. `"IN"`.
    pub net_type: String,
    /// e.g. `"IP4"` / `"IP6"`.
    pub addr_type: String,
    pub address: String,
}

/// A `c=` connection line (`IN IP4 0.0.0.0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionData {
    pub net_type: String,
    pub addr_type: String,
    /// Address, including any `/ttl` or `/count` suffix.
    pub address: String,
}

/// A `t=` timing line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    pub start: u64,
    pub stop: u64,
}

/// An `a=group:<semantics> <mid>...` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// e.g. `"BUNDLE"`, `"LS"`, `"FID"` (media-level FID groups are on
    /// `a=ssrc-group` instead).
    pub semantics: String,
    pub mids: Vec<String>,
}

/// A DTLS certificate fingerprint (`a=fingerprint:<alg> <value>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Hash algorithm token, e.g. `"sha-256"`.
    pub algorithm: String,
    /// Hex fingerprint, colon-separated as written on the wire.
    pub value: String,
}

impl Fingerprint {
    /// A sha-256 fingerprint, as used for our own certificate.
    pub fn sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: "sha-256".to_string(),
            value: value.into(),
        }
    }

    /// Whether `algorithm` names SHA-256 (case-insensitive).
    pub fn is_sha256(&self) -> bool {
        self.algorithm.eq_ignore_ascii_case("sha-256")
    }
}

/// The `a=setup` DTLS role (RFC 5763).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// Endpoint initiates the DTLS handshake (DTLS client).
    Active,
    /// Endpoint waits for the handshake (DTLS server) — the role we take.
    Passive,
    /// Offerer is willing to be either.
    ActPass,
    /// Legacy "hold connection" value.
    HoldConn,
}

impl Setup {
    /// The token used on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
            Self::HoldConn => "holdconn",
        }
    }
}

/// Media direction (`a=sendrecv`/`sendonly`/`recvonly`/`inactive`).
///
/// Absent a direction attribute an m-line defaults to `sendrecv`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    /// The direction the *other* side of the session takes — what we emit
    /// in an answer for a direction we were offered.
    pub fn flip(self) -> Self {
        match self {
            Self::SendRecv => Self::SendRecv,
            Self::SendOnly => Self::RecvOnly,
            Self::RecvOnly => Self::SendOnly,
            Self::Inactive => Self::Inactive,
        }
    }

    /// The token used on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }
}

/// Transport attributes that can appear at session level (applying to every
/// m-line) or inside an m-line (overriding the session value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportAttrs {
    pub ice_ufrag: Option<String>,
    pub ice_pwd: Option<String>,
    /// `a=ice-options` tags (e.g. `trickle`).
    pub ice_options: Vec<String>,
    /// `a=ice-lite` — the peer is an ICE-lite implementation (us, in answers).
    pub ice_lite: bool,
    /// `a=fingerprint` lines; browsers offer sha-256.
    pub fingerprints: Vec<Fingerprint>,
    /// `a=setup` DTLS role.
    pub setup: Option<Setup>,
}

// ── Media-level value types ──────────────────────────────────────────────

/// The media kind on an `m=` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
    Text,
    Application,
    Message,
    /// Outside the RFC 4566 registry (e.g. `image`). Kept so the section
    /// can be mirrored back — rejected — in an answer.
    Other(String),
}

impl MediaKind {
    fn parse(tok: &str) -> Self {
        match tok {
            "audio" => Self::Audio,
            "video" => Self::Video,
            "text" => Self::Text,
            "application" => Self::Application,
            "message" => Self::Message,
            other => Self::Other(other.to_string()),
        }
    }

    /// The token used on the `m=` line.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Text => "text",
            Self::Application => "application",
            Self::Message => "message",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// An `a=extmap` RTP header extension mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtMap {
    /// Local identifier, 1–255 (`id` may carry a `/direction` suffix on the
    /// wire, captured separately).
    pub id: u8,
    /// Optional direction suffix (`a=extmap:3/sendonly <uri>`).
    pub direction: Option<Direction>,
    /// Extension URI, e.g. `urn:ietf:params:rtp-hdrext:sdes:mid`.
    pub uri: String,
    /// Rare trailing extension attribute (e.g. for `rtp-hdrext:encrypt`).
    pub ext_attributes: Option<String>,
}

/// An `a=rtpmap:<pt> <codec>/<clock>[/<params>]` payload description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    /// Encoding name as written: `opus`, `VP8`, `H264`, `rtx`, `red`, …
    /// Compare with [`RtpMap::codec_is`].
    pub codec: String,
    /// RTP clock rate, e.g. 48000 for Opus, 90000 for video.
    pub clock: u32,
    /// Optional encoding parameters — for Opus the channel count `"2"`.
    pub params: Option<String>,
}

impl RtpMap {
    /// Case-insensitive codec-name comparison (`VP8` == `vp8`).
    pub fn codec_is(&self, name: &str) -> bool {
        self.codec.eq_ignore_ascii_case(name)
    }
}

/// An `a=rtcp-fb` codec feedback declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpFb {
    /// Payload type the feedback applies to; `None` for a `*` wildcard line.
    pub pt: Option<u8>,
    /// Feedback type token: `nack`, `ccm`, `goog-remb`, `transport-cc`, …
    pub typ: String,
    /// Optional parameter: `pli`, `fir`, `tmmbr`, …
    pub param: Option<String>,
}

impl RtcpFb {
    /// `(type, param)` pair used to declare supported feedback in
    /// [`AnswerConfig`]; `pt` is left `None` and ignored there.
    pub fn supported(typ: impl Into<String>, param: Option<impl Into<String>>) -> Self {
        Self {
            pt: None,
            typ: typ.into(),
            param: param.map(Into::into),
        }
    }

    /// Whether two entries name the same feedback kind, ignoring case.
    fn same_kind(&self, other: &RtcpFb) -> bool {
        self.typ.eq_ignore_ascii_case(&other.typ)
            && match (&self.param, &other.param) {
                (None, None) => true,
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            }
    }
}

/// Direction of an `a=rid` restriction or `a=simulcast` list (RFC 8853).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RidDirection {
    Send,
    Recv,
}

impl RidDirection {
    /// The direction the other side of the session takes.
    pub fn flip(self) -> Self {
        match self {
            Self::Send => Self::Recv,
            Self::Recv => Self::Send,
        }
    }

    /// The token used on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }
}

/// An `a=rid:<id> <send|recv> [params]` line — one simulcast layer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rid {
    pub id: String,
    pub direction: RidDirection,
    /// Optional restriction list verbatim, e.g. `pt=96,97;max-width=1280`.
    pub params: Option<String>,
}

/// An `a=simulcast` line: the layer structure over rids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simulcast {
    pub direction: RidDirection,
    /// Rid set list verbatim — `;` separates alternatives, `,` separates
    /// fallback rids within an alternative, `~` marks paused rids.
    /// e.g. `h;m;l` or `1,4;2,5;3,6`.
    pub list: String,
}

/// A parsed `a=candidate` line (RFC 5245 §15.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub foundation: String,
    /// Component id: 1 (RTP) or 2 (RTCP).
    pub component: u8,
    /// `udp` or `tcp`.
    pub transport: String,
    pub priority: u32,
    pub address: String,
    pub port: u16,
    /// `host`, `srflx`, `prflx`, `relay`.
    pub typ: String,
    /// Attribute pairs after `typ`, e.g. `raddr`/`rport`, `generation`,
    /// `network-id`. A trailing flag token is stored with an empty value.
    pub extras: Vec<(String, String)>,
}

impl Candidate {
    /// A UDP host candidate, the only kind an ICE-lite endpoint advertises.
    pub fn host(
        foundation: impl Into<String>,
        priority: u32,
        address: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            foundation: foundation.into(),
            component: 1,
            transport: "udp".to_string(),
            priority,
            address: address.into(),
            port,
            typ: "host".to_string(),
            extras: Vec::new(),
        }
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address,
            self.port,
            self.typ
        )?;
        for (k, v) in &self.extras {
            if v.is_empty() {
                write!(f, " {k}")?;
            } else {
                write!(f, " {k} {v}")?;
            }
        }
        Ok(())
    }
}

/// One `a=ssrc:<ssrc> <attr>[:<value>]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssrc {
    pub ssrc: u32,
    /// Attribute name: `cname`, `msid`, `mslabel`, `label`, or a bare flag.
    pub attribute: String,
    /// Everything after the attribute's `:` (may contain spaces), or `None`
    /// for flag-form ssrc attributes.
    pub value: Option<String>,
}

/// An `a=ssrc-group:<semantics> <ssrc>...` line — SSRC associations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcGroup {
    /// `FID` (RTX repair flow), `SIM` (simulcast), `FEC-FR`, `FID-SR`, …
    pub semantics: String,
    pub ssrcs: Vec<u32>,
}

/// An `a=msid:<stream> [<track>]` line tying the m-line to a MediaStream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msid {
    pub stream: String,
    pub track: Option<String>,
}

// ── Media description ────────────────────────────────────────────────────

/// One `m=` section with everything we care about extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDescription {
    pub kind: MediaKind,
    /// Port from the `m=` line (9 under trickle ICE, 0 when rejected).
    pub port: u16,
    /// Port count when written as `<port>/<count>` (rare).
    pub port_count: Option<u16>,
    /// Transport proto, e.g. `UDP/TLS/RTP/SAVPF` or `UDP/DTLS/SCTP`.
    pub proto: String,
    /// Format list from the `m=` line: payload types for RTP sections,
    /// tokens like `webrtc-datachannel` for `application` sections.
    pub formats: Vec<String>,
    /// `c=` line scoped to this section, if present.
    pub connection: Option<ConnectionData>,

    /// Transport attributes declared at this level (overriding session).
    pub transport: TransportAttrs,
    /// Candidates gathered into the offer itself (non-trickle peers).
    pub candidates: Vec<Candidate>,
    pub end_of_candidates: bool,

    pub mid: Option<String>,
    /// `a=rtcp-mux` — browsers always offer it.
    pub rtcp_mux: bool,
    /// Port from `a=rtcp:<port>`, when announced.
    pub rtcp_port: Option<u16>,
    /// Direction attribute; `sendrecv` when absent.
    pub direction: Direction,

    /// `a=extmap` entries declared at this level.
    pub extmaps: Vec<ExtMap>,
    /// `a=rtpmap` by payload type.
    pub rtpmaps: BTreeMap<u8, RtpMap>,
    /// `a=fmtp` parameter strings by payload type (usually one per pt).
    pub fmtps: BTreeMap<u8, Vec<String>>,
    /// `a=rtcp-fb` lines, both per-pt and `*` wildcards.
    pub rtcp_feedback: Vec<RtcpFb>,

    /// `a=rid` lines — simulcast/SVC layer identities.
    pub rids: Vec<Rid>,
    /// `a=simulcast` lines (at most one send and one recv per RFC 8853).
    pub simulcasts: Vec<Simulcast>,

    /// `a=ssrc` attribute lines.
    pub ssrcs: Vec<Ssrc>,
    /// `a=ssrc-group` associations (FID → RTX pairing, SIM, …).
    pub ssrc_groups: Vec<SsrcGroup>,
    /// `a=msid` lines.
    pub msids: Vec<Msid>,
}

impl MediaDescription {
    /// Numeric payload types from the `m=` format list, in offer order.
    /// Non-numeric formats (e.g. `webrtc-datachannel`) are skipped.
    pub fn payload_types(&self) -> impl Iterator<Item = u8> + '_ {
        self.formats.iter().filter_map(|f| f.parse::<u8>().ok())
    }

    /// Whether this section negotiates RTP media (vs. SCTP data channels).
    pub fn is_rtp(&self) -> bool {
        self.proto.contains("RTP")
    }

    /// A section rejected by port 0 (in answers).
    pub fn is_rejected(&self) -> bool {
        self.port == 0
    }

    /// `a=rtpmap` for a payload type, if declared.
    pub fn rtpmap(&self, pt: u8) -> Option<&RtpMap> {
        self.rtpmaps.get(&pt)
    }

    /// `a=fmtp` parameter strings for a payload type.
    pub fn fmtp(&self, pt: u8) -> &[String] {
        self.fmtps.get(&pt).map_or(&[], Vec::as_slice)
    }

    /// `a=rtcp-fb` entries applying to `pt`: its own plus `*` wildcards.
    pub fn feedback_for(&self, pt: u8) -> impl Iterator<Item = &RtcpFb> {
        self.rtcp_feedback
            .iter()
            .filter(move |f| f.pt.is_none() || f.pt == Some(pt))
    }

    /// `a=rid` entries for one direction.
    pub fn rids_for(&self, dir: RidDirection) -> impl Iterator<Item = &Rid> {
        self.rids.iter().filter(move |r| r.direction == dir)
    }

    /// The `a=simulcast` line for one direction, if present.
    pub fn simulcast_for(&self, dir: RidDirection) -> Option<&Simulcast> {
        self.simulcasts.iter().find(|s| s.direction == dir)
    }

    /// Unique SSRCs announced on this section — from `a=ssrc` lines and
    /// every `a=ssrc-group` (so FID repair SSRCs are included).
    pub fn ssrc_list(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .ssrcs
            .iter()
            .map(|s| s.ssrc)
            .chain(
                self.ssrc_groups
                    .iter()
                    .flat_map(|g| g.ssrcs.iter().copied()),
            )
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// First `a=msid` on the section, if any.
    pub fn msid(&self) -> Option<&Msid> {
        self.msids.first()
    }
}

// ── Session description ──────────────────────────────────────────────────

/// A parsed SDP document — in our usage, a browser's offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDescription {
    pub origin: Origin,
    /// `s=` session name (`"-"` from browsers).
    pub session_name: String,
    /// `t=` timing (always `0 0` for offers).
    pub timing: Timing,
    /// Session-level `c=` line, if present.
    pub connection: Option<ConnectionData>,

    /// `a=group` lines; see [`SessionDescription::bundle_mids`].
    pub groups: Vec<Group>,
    /// Transport attributes declared at session level.
    pub transport: TransportAttrs,
    /// Session-level `a=extmap` (applies to all m-lines).
    pub extmaps: Vec<ExtMap>,
    /// `a=extmap-allow-mixed` — peer accepts both extmap header forms.
    pub extmap_allow_mixed: bool,
    /// `a=msid-semantic` tokens (`WMS` + stream ids).
    pub msid_semantic: Vec<String>,

    /// `m=` sections in document order.
    pub media: Vec<MediaDescription>,
}

/// The parsed form of a client offer — alias for intent.
pub type Offer = SessionDescription;

impl SessionDescription {
    /// Parse an SDP document.
    ///
    /// Unknown lines and attributes are skipped. Malformed known lines
    /// produce a typed [`SdpError`]; the parser never panics on input.
    pub fn parse(input: &str) -> Result<Self, SdpError> {
        if input.len() > MAX_SDP_BYTES {
            return Err(SdpError::TooLarge(input.len()));
        }

        let mut version_seen = false;
        let mut origin = None;
        let mut session_name = String::new();
        let mut timing = None;
        let mut connection = None;
        let mut groups = Vec::new();
        let mut transport = TransportAttrs::default();
        let mut extmaps = Vec::new();
        let mut extmap_allow_mixed = false;
        let mut msid_semantic = Vec::new();
        let mut media: Vec<MediaDescription> = Vec::new();
        let mut current: Option<MediaDescription> = None;

        for (idx, raw) in input.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let (ty, value) = line
                .split_once('=')
                .ok_or(SdpError::InvalidLine(line_no))?;
            let ty = match ty.as_bytes() {
                [t] => *t,
                _ => return Err(SdpError::InvalidLine(line_no)),
            };
            let value = value.trim();

            if ty == b'm' {
                if let Some(done) = current.take() {
                    media.push(done);
                }
                if media.len() >= MAX_MEDIA_SECTIONS {
                    return Err(SdpError::TooManyMedia);
                }
                current = Some(parse_mline(value, line_no)?);
                continue;
            }

            match current.as_mut() {
                Some(m) => media_line(m, ty, value, line_no)?,
                None => match ty {
                    b'v' => {
                        if value != "0" {
                            return Err(SdpError::UnsupportedVersion);
                        }
                        version_seen = true;
                    }
                    b'o' => {
                        origin = Some(parse_origin(value).ok_or(SdpError::Malformed {
                            line: line_no,
                            what: "o= line",
                        })?);
                    }
                    b's' => session_name = value.to_string(),
                    b't' => {
                        timing = Some(parse_timing(value).ok_or(SdpError::Malformed {
                            line: line_no,
                            what: "t= line",
                        })?);
                    }
                    b'c' => {
                        connection =
                            Some(parse_connection(value).ok_or(SdpError::Malformed {
                                line: line_no,
                                what: "c= line",
                            })?);
                    }
                    b'a' => {
                        let (name, val) = split_attr(value);
                        match name {
                            "group" => groups.push(parse_group(req(val, line_no, "a=group")?).ok_or(
                                malformed(line_no, "a=group"),
                            )?),
                            "extmap" => extmaps.push(parse_extmap(
                                req(val, line_no, "a=extmap")?,
                            )
                            .ok_or(malformed(line_no, "a=extmap"))?),
                            "extmap-allow-mixed" => extmap_allow_mixed = true,
                            "msid-semantic" => {
                                msid_semantic = val
                                    .map(|v| {
                                        v.split_whitespace().map(String::from).collect()
                                    })
                                    .unwrap_or_default();
                            }
                            _ => {
                                if !transport_attr(&mut transport, name, val, line_no)? {
                                    tracing::trace!(
                                        line = line_no,
                                        attr = name,
                                        "skipping unrecognized session attribute"
                                    );
                                }
                            }
                        }
                    }
                    // i=, u=, e=, p=, b=, k=, z=, r= — not needed to drive
                    // transport or forwarding.
                    _ => {}
                },
            }
        }
        if let Some(done) = current.take() {
            media.push(done);
        }

        if !version_seen {
            return Err(SdpError::UnsupportedVersion);
        }
        let origin = origin.ok_or(SdpError::Missing("o="))?;
        let timing = timing.ok_or(SdpError::Missing("t="))?;

        Ok(Self {
            origin,
            session_name,
            timing,
            connection,
            groups,
            transport,
            extmaps,
            extmap_allow_mixed,
            msid_semantic,
            media,
        })
    }

    /// Mids named by `a=group:BUNDLE`, in order. Empty when the offer has
    /// no BUNDLE group.
    pub fn bundle_mids(&self) -> impl Iterator<Item = &str> {
        self.groups
            .iter()
            .find(|g| g.semantics.eq_ignore_ascii_case("bundle"))
            .map(|g| g.mids.iter().map(String::as_str))
            .into_iter()
            .flatten()
    }

    /// The media section carrying `a=mid:<mid>`, if any.
    pub fn media_by_mid(&self, mid: &str) -> Option<&MediaDescription> {
        self.media.iter().find(|m| m.mid.as_deref() == Some(mid))
    }

    /// All sections of one media kind.
    pub fn media_of_kind(&self, kind: &MediaKind) -> impl Iterator<Item = &MediaDescription> {
        self.media.iter().filter(move |m| &m.kind == kind)
    }

    /// Resolved ICE ufrag: first m-line value, else session-level.
    /// (M-line attributes override session ones; under BUNDLE they are
    /// identical on every section anyway.)
    pub fn ice_ufrag(&self) -> Option<&str> {
        self.media
            .iter()
            .find_map(|m| m.transport.ice_ufrag.as_deref())
            .or(self.transport.ice_ufrag.as_deref())
    }

    /// Resolved ICE password; see [`SessionDescription::ice_ufrag`].
    pub fn ice_pwd(&self) -> Option<&str> {
        self.media
            .iter()
            .find_map(|m| m.transport.ice_pwd.as_deref())
            .or(self.transport.ice_pwd.as_deref())
    }

    /// Resolved `a=setup` role; see [`SessionDescription::ice_ufrag`].
    pub fn setup(&self) -> Option<Setup> {
        self.media
            .iter()
            .find_map(|m| m.transport.setup)
            .or(self.transport.setup)
    }

    /// The sha-256 DTLS fingerprint offered for this session.
    pub fn sha256_fingerprint(&self) -> Option<&Fingerprint> {
        self.media
            .iter()
            .flat_map(|m| m.transport.fingerprints.iter())
            .find(|f| f.is_sha256())
            .or_else(|| self.transport.fingerprints.iter().find(|f| f.is_sha256()))
    }

    /// Generate a minimal bundle-only, rtcp-mux, ICE-lite answer.
    ///
    /// The answer mirrors the offer's m-line layout and payload-type
    /// numbering; codecs, header extensions, and RTCP feedback are
    /// intersected with what [`AnswerConfig`] declares we understand.
    /// Sections we cannot use (`application` datachannels, kinds with no
    /// codec in common) come back rejected with port 0.
    pub fn answer(&self, config: &AnswerConfig) -> Result<Answer, SdpError> {
        if self.media.is_empty() {
            return Err(SdpError::Answer("offer has no media sections"));
        }
        if config.ice_ufrag.is_empty() {
            return Err(SdpError::Answer("ice_ufrag is empty"));
        }
        if config.ice_pwd.is_empty() {
            return Err(SdpError::Answer("ice_pwd is empty"));
        }
        if config.candidates.is_empty() {
            return Err(SdpError::Answer(
                "ice-lite requires at least one candidate (no trickle)",
            ));
        }

        // Decide each section's fate before writing, so the BUNDLE group
        // lists only accepted mids.
        struct Plan<'m> {
            media: &'m MediaDescription,
            payloads: Vec<u8>,
        }
        let plans: Vec<Plan> = self
            .media
            .iter()
            .map(|m| Plan {
                media: m,
                payloads: select_payloads(m, config),
            })
            .collect();
        let bundled: Vec<&str> = plans
            .iter()
            .filter(|p| !p.payloads.is_empty())
            .filter_map(|p| p.media.mid.as_deref())
            .collect();

        // The browser is the DTLS client; a passive offerer is the one
        // case we must take the active role.
        let our_setup = match self.setup() {
            Some(Setup::Passive) => Setup::Active,
            _ => Setup::Passive,
        };

        let mut out = String::with_capacity(2048);
        push_line(&mut out, format_args!("v=0"));
        push_line(
            &mut out,
            format_args!(
                "o=- {} {} IN IP4 0.0.0.0",
                config.session_id, config.session_version
            ),
        );
        push_line(&mut out, format_args!("s=-"));
        push_line(&mut out, format_args!("t=0 0"));
        push_line(&mut out, format_args!("a=ice-lite"));
        if !bundled.is_empty() {
            push_line(&mut out, format_args!("a=group:BUNDLE {}", bundled.join(" ")));
        }
        push_line(&mut out, format_args!("a=msid-semantic: WMS"));
        if self.extmap_allow_mixed {
            push_line(&mut out, format_args!("a=extmap-allow-mixed"));
        }

        for plan in &plans {
            let m = plan.media;
            if plan.payloads.is_empty() {
                // Rejected section: mirror kind/proto/formats, port 0.
                push_line(
                    &mut out,
                    format_args!("m={} 0 {} {}", m.kind.as_str(), m.proto, m.formats.join(" ")),
                );
                push_line(&mut out, format_args!("c=IN IP4 0.0.0.0"));
                if let Some(mid) = &m.mid {
                    push_line(&mut out, format_args!("a=mid:{mid}"));
                }
                push_line(&mut out, format_args!("a=inactive"));
                continue;
            }

            let pts = plan
                .payloads
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            push_line(
                &mut out,
                format_args!("m={} 9 {} {}", m.kind.as_str(), m.proto, pts),
            );
            push_line(&mut out, format_args!("c=IN IP4 0.0.0.0"));
            push_line(&mut out, format_args!("a=rtcp:9 IN IP4 0.0.0.0"));
            push_line(&mut out, format_args!("a=ice-ufrag:{}", config.ice_ufrag));
            push_line(&mut out, format_args!("a=ice-pwd:{}", config.ice_pwd));
            push_line(&mut out, format_args!("a=ice-options:trickle"));
            push_line(
                &mut out,
                format_args!(
                    "a=fingerprint:{} {}",
                    config.fingerprint.algorithm, config.fingerprint.value
                ),
            );
            push_line(&mut out, format_args!("a=setup:{}", our_setup.as_str()));
            if let Some(mid) = &m.mid {
                push_line(&mut out, format_args!("a=mid:{mid}"));
            }
            for ext in self.extmaps.iter().chain(&m.extmaps) {
                if config.header_extensions.iter().any(|u| u == &ext.uri) {
                    push_line(&mut out, format_args!("a=extmap:{} {}", ext.id, ext.uri));
                }
            }
            push_line(
                &mut out,
                format_args!("a={}", m.direction.flip().as_str()),
            );
            push_line(&mut out, format_args!("a=rtcp-mux"));

            for &pt in &plan.payloads {
                if let Some(rm) = m.rtpmaps.get(&pt) {
                    match &rm.params {
                        Some(p) => push_line(
                            &mut out,
                            format_args!("a=rtpmap:{pt} {}/{}/{p}", rm.codec, rm.clock),
                        ),
                        None => push_line(
                            &mut out,
                            format_args!("a=rtpmap:{pt} {}/{}", rm.codec, rm.clock),
                        ),
                    }
                }
                let mut seen: Vec<(&str, Option<&str>)> = Vec::new();
                for fb in m.feedback_for(pt) {
                    let key = (fb.typ.as_str(), fb.param.as_deref());
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.push(key);
                    if config.rtcp_feedback.iter().any(|s| s.same_kind(fb)) {
                        match &fb.param {
                            Some(p) => push_line(
                                &mut out,
                                format_args!("a=rtcp-fb:{pt} {} {p}", fb.typ),
                            ),
                            None => {
                                push_line(&mut out, format_args!("a=rtcp-fb:{pt} {}", fb.typ))
                            }
                        }
                    }
                }
                for f in m.fmtp(pt) {
                    push_line(&mut out, format_args!("a=fmtp:{pt} {f}"));
                }
            }

            for rid in &m.rids {
                match &rid.params {
                    Some(p) => push_line(
                        &mut out,
                        format_args!("a=rid:{} {} {p}", rid.id, rid.direction.flip().as_str()),
                    ),
                    None => push_line(
                        &mut out,
                        format_args!("a=rid:{} {}", rid.id, rid.direction.flip().as_str()),
                    ),
                }
            }
            for sc in &m.simulcasts {
                push_line(
                    &mut out,
                    format_args!("a=simulcast:{} {}", sc.direction.flip().as_str(), sc.list),
                );
            }

            // ICE-lite: the full candidate set goes in the answer.
            for c in &config.candidates {
                push_line(&mut out, format_args!("a=candidate:{c}"));
            }
            push_line(&mut out, format_args!("a=end-of-candidates"));
        }

        tracing::debug!(
            m_lines = plans.len(),
            bundled = bundled.len(),
            "generated SDP answer"
        );
        Ok(Answer { sdp: out })
    }
}

/// A generated SDP answer — drop into
/// `wroom.signaling.v1.SessionDescription { type: ANSWER, sdp }`.
///
/// Deliberately minimal: no `a=ssrc`/`a=msid` declarations for our own
/// send direction yet (receivers learn SSRCs from the packets and mids).
pub struct Answer {
    sdp: String,
}

impl Answer {
    /// The SDP document, CRLF line endings.
    pub fn as_str(&self) -> &str {
        &self.sdp
    }

    /// Consume into the owned SDP string.
    pub fn into_string(self) -> String {
        self.sdp
    }
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sdp)
    }
}

impl From<Answer> for String {
    fn from(a: Answer) -> Self {
        a.sdp
    }
}

// ── Answer configuration ─────────────────────────────────────────────────

/// Audio codecs we accept by default: Opus.
pub const DEFAULT_AUDIO_CODECS: &[&str] = &["opus"];

/// Video codecs we accept by default: VP8 and H.264 baseline plus AV1,
/// the scalability target (Architecture.md "Connectivity and media").
pub const DEFAULT_VIDEO_CODECS: &[&str] = &["VP8", "H264", "AV1"];

/// RTP header extensions we understand and accept by default: mid, rid
/// (rtp-stream-id), transport-wide CC, abs-send-time, audio-level.
pub const DEFAULT_HEADER_EXTENSIONS: &[&str] = &[
    "urn:ietf:params:rtp-hdrext:sdes:mid",
    "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
];

/// RTCP feedback kinds we accept by default: generic NACK, PLI, FIR,
/// REMB, transport-wide CC.
pub const DEFAULT_RTCP_FEEDBACK: &[(&str, &str)] = &[
    ("nack", ""),
    ("nack", "pli"),
    ("ccm", "fir"),
    ("goog-remb", ""),
    ("transport-cc", ""),
];

/// What our answers look like: local transport identity plus the codec,
/// extension, and feedback sets we are willing to negotiate.
#[derive(Debug, Clone)]
pub struct AnswerConfig {
    /// `o=` session id/version for the generated origin line.
    pub session_id: u64,
    pub session_version: u64,
    /// Our ICE credentials, repeated on every bundled m-line.
    pub ice_ufrag: String,
    pub ice_pwd: String,
    /// Fingerprint of our DTLS certificate (sha-256).
    pub fingerprint: Fingerprint,
    /// Our host candidates. ICE-lite answers carry the full set (no
    /// trickle), so at least one is required.
    pub candidates: Vec<Candidate>,
    /// Acceptable audio codec names (case-insensitive vs `a=rtpmap`).
    /// The offer's order is kept — we honor the offerer's preference.
    pub audio_codecs: Vec<String>,
    /// Acceptable video codec names.
    pub video_codecs: Vec<String>,
    /// Extension URIs we accept (exact match).
    pub header_extensions: Vec<String>,
    /// RTCP feedback `(type, param)` we accept; `pt` is ignored.
    pub rtcp_feedback: Vec<RtcpFb>,
}

impl AnswerConfig {
    /// Local transport identity with the default codec/extension/feedback
    /// sets (`DEFAULT_*` constants).
    pub fn new(
        session_id: u64,
        ice_ufrag: impl Into<String>,
        ice_pwd: impl Into<String>,
        fingerprint: Fingerprint,
        candidates: Vec<Candidate>,
    ) -> Self {
        Self {
            session_id,
            session_version: 0,
            ice_ufrag: ice_ufrag.into(),
            ice_pwd: ice_pwd.into(),
            fingerprint,
            candidates,
            audio_codecs: DEFAULT_AUDIO_CODECS.iter().map(|s| s.to_string()).collect(),
            video_codecs: DEFAULT_VIDEO_CODECS.iter().map(|s| s.to_string()).collect(),
            header_extensions: DEFAULT_HEADER_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rtcp_feedback: DEFAULT_RTCP_FEEDBACK
                .iter()
                .map(|(t, p)| {
                    RtcpFb::supported(*t, (!p.is_empty()).then(|| p.to_string()))
                })
                .collect(),
        }
    }
}

// ── Payload selection ────────────────────────────────────────────────────

/// Payload types we accept on one offered section, in offer order: every
/// supported codec plus the RTX repair payloads bound to a selected codec
/// by `a=fmtp: apt=`. Empty when the kind is unsupported or no codec
/// intersects — the section is then rejected in the answer.
fn select_payloads(m: &MediaDescription, config: &AnswerConfig) -> Vec<u8> {
    if !m.is_rtp() {
        return Vec::new();
    }
    let supported = match &m.kind {
        MediaKind::Audio => &config.audio_codecs,
        MediaKind::Video => &config.video_codecs,
        _ => return Vec::new(),
    };

    let mut codecs: Vec<u8> = m
        .payload_types()
        .filter(|&pt| {
            m.rtpmaps
                .get(&pt)
                .is_some_and(|r| supported.iter().any(|c| r.codec_is(c)))
        })
        .collect();

    let rtx: Vec<u8> = m
        .payload_types()
        .filter(|pt| {
            !codecs.contains(pt)
                && m.rtpmaps
                    .get(pt)
                    .is_some_and(|r| r.codec_is("rtx"))
                && m.fmtp(*pt)
                    .iter()
                    .filter_map(|f| rtx_apt(f))
                    .any(|apt| codecs.contains(&apt))
        })
        .collect();

    codecs.extend(rtx.iter().copied());
    m.payload_types()
        .filter(|pt| codecs.contains(pt))
        .collect()
}

/// `apt=<pt>` inside an `a=fmtp` parameter string (RTX → codec binding).
fn rtx_apt(fmtp: &str) -> Option<u8> {
    fmtp.split(';').find_map(|param| {
        let (k, v) = param.trim().split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("apt")
            .then(|| v.trim().parse().ok())?
    })
}

// ── Line and attribute parsers ───────────────────────────────────────────
//
// Each `parse_*` returns `Option`; call sites wrap `None` into the typed
// `SdpError::Malformed` naming the attribute, so errors carry context
// while parsers stay small.

fn malformed(line: usize, what: &'static str) -> SdpError {
    SdpError::Malformed { line, what }
}

/// A required attribute value: error when absent or empty.
fn req<'a>(val: Option<&'a str>, line: usize, what: &'static str) -> Result<&'a str, SdpError> {
    match val {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(malformed(line, what)),
    }
}

/// `a=name:value` → `("name", Some("value"))`; `a=flag` → `("flag", None)`.
fn split_attr(v: &str) -> (&str, Option<&str>) {
    match v.split_once(':') {
        Some((n, rest)) => (n.trim(), Some(rest.trim())),
        None => (v.trim(), None),
    }
}

/// First whitespace split on an already-trimmed string.
fn split_once_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(char::is_whitespace)?;
    Some((&s[..idx], s[idx..].trim_start()))
}

fn parse_origin(v: &str) -> Option<Origin> {
    let mut t = v.split_whitespace();
    Some(Origin {
        username: t.next()?.to_string(),
        session_id: t.next()?.parse().ok()?,
        session_version: t.next()?.parse().ok()?,
        net_type: t.next()?.to_string(),
        addr_type: t.next()?.to_string(),
        address: t.next()?.to_string(),
    })
}

fn parse_timing(v: &str) -> Option<Timing> {
    let mut t = v.split_whitespace();
    Some(Timing {
        start: t.next()?.parse().ok()?,
        stop: t.next()?.parse().ok()?,
    })
}

fn parse_connection(v: &str) -> Option<ConnectionData> {
    let mut t = v.split_whitespace();
    Some(ConnectionData {
        net_type: t.next()?.to_string(),
        addr_type: t.next()?.to_string(),
        address: t.next()?.to_string(),
    })
}

fn parse_group(v: &str) -> Option<Group> {
    let mut t = v.split_whitespace();
    Some(Group {
        semantics: t.next()?.to_string(),
        mids: t.map(String::from).collect(),
    })
}

fn parse_fingerprint(v: &str) -> Option<Fingerprint> {
    let (alg, value) = split_once_ws(v)?;
    Some(Fingerprint {
        algorithm: alg.to_string(),
        value: value.to_string(),
    })
}

fn parse_setup(v: &str) -> Option<Setup> {
    Some(match v {
        s if s.eq_ignore_ascii_case("active") => Setup::Active,
        s if s.eq_ignore_ascii_case("passive") => Setup::Passive,
        s if s.eq_ignore_ascii_case("actpass") => Setup::ActPass,
        s if s.eq_ignore_ascii_case("holdconn") => Setup::HoldConn,
        _ => return None,
    })
}

fn parse_direction(v: &str) -> Option<Direction> {
    Some(match v {
        s if s.eq_ignore_ascii_case("sendrecv") => Direction::SendRecv,
        s if s.eq_ignore_ascii_case("sendonly") => Direction::SendOnly,
        s if s.eq_ignore_ascii_case("recvonly") => Direction::RecvOnly,
        s if s.eq_ignore_ascii_case("inactive") => Direction::Inactive,
        _ => return None,
    })
}

fn parse_rid_dir(v: &str) -> Option<RidDirection> {
    Some(match v {
        s if s.eq_ignore_ascii_case("send") => RidDirection::Send,
        s if s.eq_ignore_ascii_case("recv") => RidDirection::Recv,
        _ => return None,
    })
}

/// `m=<kind> <port>[/<count>] <proto> <fmt>...`
fn parse_mline(v: &str, line: usize) -> Result<MediaDescription, SdpError> {
    let bad = || malformed(line, "m= line");
    let mut t = v.split_whitespace();
    let kind = MediaKind::parse(t.next().ok_or_else(bad)?);
    let port_tok = t.next().ok_or_else(bad)?;
    let (port, port_count) = match port_tok.split_once('/') {
        Some((p, c)) => (
            p.parse().map_err(|_| bad())?,
            Some(c.parse().map_err(|_| bad())?),
        ),
        None => (port_tok.parse().map_err(|_| bad())?, None),
    };
    let proto = t.next().ok_or_else(bad)?.to_string();
    let formats: Vec<String> = t.map(String::from).collect();
    if formats.is_empty() {
        return Err(bad());
    }
    Ok(MediaDescription {
        kind,
        port,
        port_count,
        proto,
        formats,
        connection: None,
        transport: TransportAttrs::default(),
        candidates: Vec::new(),
        end_of_candidates: false,
        mid: None,
        rtcp_mux: false,
        rtcp_port: None,
        direction: Direction::default(),
        extmaps: Vec::new(),
        rtpmaps: BTreeMap::new(),
        fmtps: BTreeMap::new(),
        rtcp_feedback: Vec::new(),
        rids: Vec::new(),
        simulcasts: Vec::new(),
        ssrcs: Vec::new(),
        ssrc_groups: Vec::new(),
        msids: Vec::new(),
    })
}

/// `<id>[/<direction>] <uri> [extattr]`
fn parse_extmap(v: &str) -> Option<ExtMap> {
    let (id_tok, rest) = split_once_ws(v)?;
    let (id_s, direction) = match id_tok.split_once('/') {
        Some((i, d)) => (i, Some(parse_direction(d)?)),
        None => (id_tok, None),
    };
    let id: u8 = id_s.parse().ok()?;
    if id == 0 {
        return None;
    }
    let (uri, attr) = match split_once_ws(rest) {
        Some((u, a)) => (u, Some(a.to_string())),
        None => (rest, None),
    };
    if uri.is_empty() {
        return None;
    }
    Some(ExtMap {
        id,
        direction,
        uri: uri.to_string(),
        ext_attributes: attr,
    })
}

/// `<pt> <codec>/<clock>[/<params>]`
fn parse_rtpmap(v: &str) -> Option<(u8, RtpMap)> {
    let (pt_s, enc) = split_once_ws(v)?;
    let pt: u8 = pt_s.parse().ok()?;
    let mut e = enc.splitn(3, '/');
    let codec = e.next()?.to_string();
    if codec.is_empty() {
        return None;
    }
    let clock: u32 = e.next()?.parse().ok()?;
    let params = e.next().map(str::to_string);
    Some((
        pt,
        RtpMap {
            codec,
            clock,
            params,
        },
    ))
}

/// `<pt> <params...>` — parameters kept verbatim.
fn parse_fmtp(v: &str) -> Option<(u8, String)> {
    let (pt_s, params) = split_once_ws(v)?;
    let pt: u8 = pt_s.parse().ok()?;
    if params.is_empty() {
        return None;
    }
    Some((pt, params.to_string()))
}

/// `<pt|*> <type> [param]`
fn parse_rtcp_fb(v: &str) -> Option<RtcpFb> {
    let (pt_s, rest) = split_once_ws(v)?;
    let pt = if pt_s == "*" {
        None
    } else {
        Some(pt_s.parse().ok()?)
    };
    let (typ, param) = match split_once_ws(rest) {
        Some((t, p)) => (t, Some(p.to_string())),
        None => (rest, None),
    };
    if typ.is_empty() {
        return None;
    }
    Some(RtcpFb {
        pt,
        typ: typ.to_string(),
        param,
    })
}

/// `<id> <send|recv> [params]`
fn parse_rid(v: &str) -> Option<Rid> {
    let (id, rest) = split_once_ws(v)?;
    if id.is_empty() {
        return None;
    }
    let (dir_s, params) = match split_once_ws(rest) {
        Some((d, p)) => (d, Some(p.to_string())),
        None => (rest, None),
    };
    Some(Rid {
        id: id.to_string(),
        direction: parse_rid_dir(dir_s)?,
        params,
    })
}

/// `<send|recv> <list> [send|recv <list>]` — RFC 8853 allows both lists on
/// one attribute.
fn parse_simulcast(v: &str, out: &mut Vec<Simulcast>) -> Option<()> {
    let mut tokens = v.split_whitespace();
    let mut found = false;
    while let Some(dir_tok) = tokens.next() {
        let direction = parse_rid_dir(dir_tok)?;
        let list = tokens.next()?.to_string();
        out.push(Simulcast { direction, list });
        found = true;
    }
    found.then_some(())
}

/// `foundation component transport priority address port typ <type> [pairs]`
fn parse_candidate(v: &str) -> Option<Candidate> {
    let t: Vec<&str> = v.split_whitespace().collect();
    if t.len() < 8 || !t[6].eq_ignore_ascii_case("typ") {
        return None;
    }
    let extras: Vec<(String, String)> = t[8..]
        .chunks(2)
        .map(|pair| match pair {
            [k, v] => (k.to_string(), v.to_string()),
            [k] => (k.to_string(), String::new()),
            _ => unreachable!("chunks(2) yields 1 or 2 elements"),
        })
        .collect();
    Some(Candidate {
        foundation: t[0].to_string(),
        component: t[1].parse().ok()?,
        transport: t[2].to_string(),
        priority: t[3].parse().ok()?,
        address: t[4].to_string(),
        port: t[5].parse().ok()?,
        typ: t[7].to_string(),
        extras,
    })
}

/// `<ssrc> <attr>[:<value>]` — value may itself contain `:` and spaces.
fn parse_ssrc(v: &str) -> Option<Ssrc> {
    let (ssrc_s, rest) = split_once_ws(v)?;
    let ssrc: u32 = ssrc_s.parse().ok()?;
    let (attribute, value) = match rest.split_once(':') {
        Some((a, val)) => (a.trim(), Some(val.trim().to_string())),
        None => (rest, None),
    };
    Some(Ssrc {
        ssrc,
        attribute: attribute.to_string(),
        value,
    })
}

/// `<semantics> <ssrc>...`
fn parse_ssrc_group(v: &str) -> Option<SsrcGroup> {
    let mut t = v.split_whitespace();
    let semantics = t.next()?.to_string();
    let ssrcs: Option<Vec<u32>> = t.map(|s| s.parse().ok()).collect();
    let ssrcs = ssrcs?;
    if ssrcs.is_empty() {
        return None;
    }
    Some(SsrcGroup { semantics, ssrcs })
}

/// `<stream> [<track>]`
fn parse_msid(v: &str) -> Option<Msid> {
    let (stream, track) = match split_once_ws(v) {
        Some((s, t)) => (s, Some(t.to_string())),
        None => (v, None),
    };
    if stream.is_empty() {
        return None;
    }
    Some(Msid {
        stream: stream.to_string(),
        track,
    })
}

/// Non-attribute lines inside a media section.
fn media_line(
    m: &mut MediaDescription,
    ty: u8,
    value: &str,
    line: usize,
) -> Result<(), SdpError> {
    match ty {
        b'a' => media_attr(m, value, line)?,
        b'c' => {
            m.connection = Some(parse_connection(value).ok_or(SdpError::Malformed {
                line,
                what: "c= line",
            })?);
        }
        // i=, b=, k= and anything else: recognized or not, not needed here.
        _ => {}
    }
    Ok(())
}

fn media_attr(m: &mut MediaDescription, value: &str, line: usize) -> Result<(), SdpError> {
    let (name, val) = split_attr(value);
    match name {
        "mid" => m.mid = Some(req(val, line, "a=mid")?.to_string()),
        "rtcp-mux" => m.rtcp_mux = true,
        "rtcp" => {
            let v = req(val, line, "a=rtcp")?;
            let port_tok = v.split_whitespace().next().ok_or(malformed(line, "a=rtcp"))?;
            m.rtcp_port = Some(port_tok.parse().map_err(|_| malformed(line, "a=rtcp"))?);
        }
        "sendrecv" => m.direction = Direction::SendRecv,
        "sendonly" => m.direction = Direction::SendOnly,
        "recvonly" => m.direction = Direction::RecvOnly,
        "inactive" => m.direction = Direction::Inactive,
        "extmap" => m.extmaps.push(
            parse_extmap(req(val, line, "a=extmap")?).ok_or(malformed(line, "a=extmap"))?,
        ),
        "rtpmap" => {
            let (pt, rm) = parse_rtpmap(req(val, line, "a=rtpmap")?)
                .ok_or(malformed(line, "a=rtpmap"))?;
            m.rtpmaps.insert(pt, rm);
        }
        "fmtp" => {
            let (pt, params) =
                parse_fmtp(req(val, line, "a=fmtp")?).ok_or(malformed(line, "a=fmtp"))?;
            m.fmtps.entry(pt).or_default().push(params);
        }
        "rtcp-fb" => m.rtcp_feedback.push(
            parse_rtcp_fb(req(val, line, "a=rtcp-fb")?).ok_or(malformed(line, "a=rtcp-fb"))?,
        ),
        "rid" => m
            .rids
            .push(parse_rid(req(val, line, "a=rid")?).ok_or(malformed(line, "a=rid"))?),
        "simulcast" => {
            parse_simulcast(req(val, line, "a=simulcast")?, &mut m.simulcasts)
                .ok_or(malformed(line, "a=simulcast"))?;
        }
        "candidate" => m.candidates.push(
            parse_candidate(req(val, line, "a=candidate")?)
                .ok_or(malformed(line, "a=candidate"))?,
        ),
        "ssrc" => m
            .ssrcs
            .push(parse_ssrc(req(val, line, "a=ssrc")?).ok_or(malformed(line, "a=ssrc"))?),
        "ssrc-group" => m.ssrc_groups.push(
            parse_ssrc_group(req(val, line, "a=ssrc-group")?)
                .ok_or(malformed(line, "a=ssrc-group"))?,
        ),
        "msid" => m
            .msids
            .push(parse_msid(req(val, line, "a=msid")?).ok_or(malformed(line, "a=msid"))?),
        "end-of-candidates" => m.end_of_candidates = true,
        _ => {
            if !transport_attr(&mut m.transport, name, val, line)? {
                tracing::trace!(
                    line,
                    attr = name,
                    "skipping unrecognized media attribute"
                );
            }
        }
    }
    Ok(())
}

/// `a=ice-*`, `a=fingerprint`, `a=setup` — valid at both session and media
/// level. Returns `Ok(true)` when the attribute was consumed.
fn transport_attr(
    t: &mut TransportAttrs,
    name: &str,
    val: Option<&str>,
    line: usize,
) -> Result<bool, SdpError> {
    match name {
        "ice-ufrag" => t.ice_ufrag = Some(req(val, line, "a=ice-ufrag")?.to_string()),
        "ice-pwd" => t.ice_pwd = Some(req(val, line, "a=ice-pwd")?.to_string()),
        "ice-options" => t.ice_options.extend(
            req(val, line, "a=ice-options")?
                .split_whitespace()
                .map(String::from),
        ),
        "ice-lite" => t.ice_lite = true,
        "fingerprint" => t.fingerprints.push(
            parse_fingerprint(req(val, line, "a=fingerprint")?)
                .ok_or(malformed(line, "a=fingerprint"))?,
        ),
        "setup" => {
            t.setup = Some(
                parse_setup(req(val, line, "a=setup")?).ok_or(malformed(line, "a=setup"))?,
            )
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn push_line(out: &mut String, args: fmt::Arguments<'_>) {
    use fmt::Write as _;
    // Writing to a String cannot fail.
    let _ = out.write_fmt(args);
    out.push_str("\r\n");
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures ────────────────────────────────────────────────────────

    /// Chrome-style Unified Plan offer: per-m-line ICE/DTLS attributes,
    /// extmap-allow-mixed, rid-based 3-layer simulcast, a codec zoo
    /// (VP8/H264/AV1 + RTX, plus ulpfec/flexfec/red we must drop), an
    /// audio section with opus + red + telephone-event, and a data-channel
    /// section we must reject.
    const CHROME_OFFER: &str = "\
v=0
o=- 8123456789012345678 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1 2
a=extmap-allow-mixed
a=msid-semantic: WMS stream-a
m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:uChRoMe1
a=ice-pwd:ChromePwd0123456789abcdef
a=ice-options:trickle
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=sendonly
a=msid:stream-a track-a0
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:63 red/48000/2
a=fmtp:63 111/111
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:126 telephone-event/8000
a=fmtp:126 0-15
m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103 104 105 106 107 108 109 116 125 39 40
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:uChRoMe1
a=ice-pwd:ChromePwd0123456789abcdef
a=ice-options:trickle
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00
a=setup:actpass
a=mid:1
a=extmap:14 urn:ietf:params:rtp-hdrext:toffset
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type
a=extmap:13 http://www.webrtc.org/experiments/rtp-hdrext/video-timing
a=sendonly
a=msid:stream-v track-v0
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=fmtp:96 x-google-start-bitrate=1000
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
a=rtpmap:102 H264/90000
a=rtcp-fb:102 goog-remb
a=rtcp-fb:102 transport-cc
a=rtcp-fb:102 ccm fir
a=rtcp-fb:102 nack
a=rtcp-fb:102 nack pli
a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
a=rtpmap:103 rtx/90000
a=fmtp:103 apt=102
a=rtpmap:104 H264/90000
a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
a=rtpmap:105 rtx/90000
a=fmtp:105 apt=104
a=rtpmap:106 AV1/90000
a=rtcp-fb:106 transport-cc
a=rtcp-fb:106 nack pli
a=rtpmap:107 rtx/90000
a=fmtp:107 apt=106
a=rtpmap:108 H264/90000
a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=rtpmap:109 rtx/90000
a=fmtp:109 apt=108
a=rtpmap:116 ulpfec/90000
a=rtpmap:125 flexfec-03/90000
a=rtcp-fb:125 goog-remb
a=fmtp:125 repair-window=10000000
a=rtpmap:39 red/90000
a=rtpmap:40 rtx/90000
a=fmtp:40 apt=39
a=rid:h send
a=rid:m send
a=rid:l send
a=simulcast:send h;m;l
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:uChRoMe1
a=ice-pwd:ChromePwd0123456789abcdef
a=ice-options:trickle
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00
a=setup:actpass
a=mid:2
a=sctp-port:5000
a=max-message-size:262144
";

    /// Firefox-style offer: session-level fingerprint + ice-options,
    /// alphabetized attributes, candidates gathered into the offer,
    /// ssrc lines with a FID group, a wildcard rtcp-fb, and VP9 we must
    /// drop (its RTX must go too).
    const FIREFOX_OFFER: &str = "\
v=0
o=mozilla...THIS_IS_SDPARTA-99.0 9123412345678901234 0 IN IP4 0.0.0.0
s=-
t=0 0
a=extmap-allow-mixed
a=fingerprint:sha-256 22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11
a=group:BUNDLE 0 1
a=ice-options:trickle
a=msid-semantic:WMS *
m=audio 9 UDP/TLS/RTP/SAVPF 109 9 0 8 101
c=IN IP4 0.0.0.0
a=candidate:0 1 UDP 2122252543 192.168.1.10 53412 typ host
a=candidate:2 1 UDP 1686052863 203.0.113.5 53412 typ srflx raddr 192.168.1.10 rport 53412
a=end-of-candidates
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=fmtp:101 0-15
a=fmtp:109 maxplaybackrate=48000;stereo=1;useinbandfec=1
a=ice-pwd:FirefoxPwd0123456789abcdef
a=ice-ufrag:uFiReFoX1
a=mid:0
a=msid:{5a5a5a5a-0000-1111-2222-333344445555} {6b6b6b6b-aaaa-bbbb-cccc-ddddeeeeffff}
a=rtcp-fb:* transport-cc
a=rtcp-mux
a=rtpmap:109 opus/48000/2
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
a=setup:actpass
a=ssrc:20304050 cname:{7c7c7c7c-8d8d-9e9e-afaf-b0b0b0b0b0b0}
m=video 9 UDP/TLS/RTP/SAVPF 120 124 121 125 126 127 108 109
c=IN IP4 0.0.0.0
a=candidate:0 1 UDP 2122252543 192.168.1.10 53413 typ host
a=end-of-candidates
a=extmap:1 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=fmtp:108 profile-level-id=42e01f;level-asymmetry-allowed=1
a=fmtp:124 apt=120
a=fmtp:125 apt=121
a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1
a=fmtp:127 apt=126
a=fmtp:109 apt=108
a=ice-pwd:FirefoxPwd0123456789abcdef
a=ice-ufrag:uFiReFoX1
a=mid:1
a=msid:{5a5a5a5a-0000-1111-2222-333344445555} {8d8d8d8d-eeee-ffff-0000-111122223333}
a=rtcp-fb:120 nack
a=rtcp-fb:120 nack pli
a=rtcp-fb:120 ccm fir
a=rtcp-fb:120 goog-remb
a=rtcp-fb:120 transport-cc
a=rtcp-fb:121 nack
a=rtcp-fb:121 nack pli
a=rtcp-fb:121 transport-cc
a=rtcp-fb:126 nack
a=rtcp-fb:126 nack pli
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 goog-remb
a=rtcp-fb:126 transport-cc
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtcp-mux
a=rtpmap:120 VP8/90000
a=rtpmap:124 rtx/90000
a=rtpmap:121 VP9/90000
a=rtpmap:125 rtx/90000
a=rtpmap:126 H264/90000
a=rtpmap:127 rtx/90000
a=rtpmap:108 H264/90000
a=rtpmap:109 rtx/90000
a=sendrecv
a=setup:actpass
a=ssrc:40506070 cname:{7c7c7c7c-8d8d-9e9e-afaf-b0b0b0b0b0b0}
a=ssrc:40506070 msid:{5a5a5a5a-0000-1111-2222-333344445555} {8d8d8d8d-eeee-ffff-0000-111122223333}
a=ssrc:40506071 cname:{7c7c7c7c-8d8d-9e9e-afaf-b0b0b0b0b0b0}
a=ssrc-group:FID 40506070 40506071
";

    /// Safari-style offer: per-m-line attributes, H264-only video plus
    /// legacy codecs (ISAC, CN), `a=rtcp-rsize`, ssrc lines with a FID
    /// group, and a direction-qualified extmap.
    const SAFARI_OFFER: &str = "\
v=0
o=- 7763412345678901234 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS
m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 105 106 110
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:uSaFaRi01
a=ice-pwd:SafariPwd0123456789abcdefg
a=ice-options:trickle
a=fingerprint:sha-256 33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22
a=setup:actpass
a=mid:0
a=sendrecv
a=msid:safari-stream safari-audio
a=rtcp-mux
a=rtcp-rsize
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:105 CN/16000
a=rtpmap:106 CN/32000
a=rtpmap:110 telephone-event/16000
a=fmtp:110 0-15
m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:uSaFaRi01
a=ice-pwd:SafariPwd0123456789abcdefg
a=ice-options:trickle
a=fingerprint:sha-256 33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22
a=setup:actpass
a=mid:1
a=sendrecv
a=msid:safari-stream safari-video
a=rtcp-mux
a=rtcp-rsize
a=extmap:1/sendrecv http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:7 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=rtpmap:96 H264/90000
a=rtcp-fb:96 nack pli
a=rtcp-fb:96 ccm fir
a=fmtp:96 packetization-mode=1;profile-level-id=42e01f;level-asymmetry-allowed=1
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
a=rtpmap:98 H264/90000
a=rtcp-fb:98 nack pli
a=fmtp:98 packetization-mode=1;profile-level-id=42001f;level-asymmetry-allowed=1
a=rtpmap:99 rtx/90000
a=fmtp:99 apt=98
a=rtpmap:100 VP8/90000
a=rtcp-fb:100 nack pli
a=rtpmap:101 rtx/90000
a=fmtp:101 apt=100
a=ssrc:777000111 cname:safari-cname
a=ssrc:777000111 msid:safari-stream safari-video
a=ssrc:777000222 cname:safari-cname
a=ssrc-group:FID 777000111 777000222
";

    // ── Helpers ─────────────────────────────────────────────────────────

    fn test_config() -> AnswerConfig {
        AnswerConfig::new(
            4242,
            "wroomUfrag",
            "wroomPwd0123456789abcdef",
            Fingerprint::sha256(
                "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            ),
            vec![Candidate::host("wroom1", 2_130_706_431, "192.0.2.10", 50_000)],
        )
    }

    fn pts(m: &MediaDescription) -> Vec<u8> {
        m.payload_types().collect()
    }

    /// Asserts the negotiated invariants every answer must satisfy, and
    /// returns the re-parsed answer for fixture-specific assertions.
    fn check_answer(
        offer: &SessionDescription,
        config: &AnswerConfig,
        expected_bundle_mids: &[&str],
    ) -> SessionDescription {
        let answer = offer.answer(config).expect("answer() must succeed");
        let sdp = answer.as_str().to_string();
        assert!(sdp.contains("\r\n"), "answer must use CRLF line endings");
        assert!(sdp.contains("a=ice-lite"));
        assert!(sdp.contains("a=end-of-candidates"));
        // Minimal: we declare no SSRCs for our send direction yet.
        assert!(!sdp.contains("a=ssrc"));

        // The answer must itself be a parseable session description.
        let parsed = SessionDescription::parse(&sdp)
            .expect("generated answer must parse with our own parser");

        // ICE-lite session identity and our credentials.
        assert!(parsed.transport.ice_lite, "session must carry a=ice-lite");
        assert_eq!(parsed.ice_ufrag(), Some(config.ice_ufrag.as_str()));
        assert_eq!(parsed.ice_pwd(), Some(config.ice_pwd.as_str()));
        assert_eq!(
            parsed.sha256_fingerprint(),
            Some(&config.fingerprint),
            "answer must carry our sha-256 fingerprint"
        );
        assert_eq!(parsed.setup(), Some(Setup::Passive));

        // BUNDLE contains exactly the accepted mids.
        let bundled: Vec<&str> = parsed.bundle_mids().collect();
        assert_eq!(bundled, expected_bundle_mids);

        // Same number and order of m-lines, same kinds.
        assert_eq!(parsed.media.len(), offer.media.len());
        for (am, om) in parsed.media.iter().zip(&offer.media) {
            assert_eq!(am.kind, om.kind);
            assert_eq!(am.mid, om.mid);
            if am.is_rejected() {
                assert_eq!(am.direction, Direction::Inactive);
                continue;
            }
            assert!(am.rtcp_mux, "accepted m-line must be rtcp-mux");
            assert_eq!(
                am.direction,
                om.direction.flip(),
                "answer direction must flip the offer"
            );
            assert_eq!(am.candidates, config.candidates);
            assert!(am.end_of_candidates);
            // Every extension we claimed was both offered and supported.
            for ext in &am.extmaps {
                assert!(om.extmaps.iter().any(|e| e.uri == ext.uri));
                assert!(config.header_extensions.contains(&ext.uri));
            }
            // Every payload we accepted was offered with a supported codec
            // (or is RTX bound to one).
            for pt in pts(am) {
                assert!(om.formats.contains(&pt.to_string()));
                let rm = am.rtpmap(pt).expect("answer pt must have rtpmap");
                let supported = match am.kind {
                    MediaKind::Audio => &config.audio_codecs,
                    _ => &config.video_codecs,
                };
                assert!(
                    rm.codec_is("rtx")
                        || supported.iter().any(|c| rm.codec_is(c)),
                    "unsupported codec in answer: {}",
                    rm.codec
                );
            }
        }
        parsed
    }

    // ── Chrome ──────────────────────────────────────────────────────────

    #[test]
    fn chrome_offer_parses() {
        let offer = SessionDescription::parse(CHROME_OFFER).unwrap();

        assert_eq!(offer.origin.username, "-");
        assert_eq!(offer.origin.session_id, 8_123_456_789_012_345_678);
        assert_eq!(offer.bundle_mids().collect::<Vec<_>>(), ["0", "1", "2"]);
        assert!(offer.extmap_allow_mixed);
        assert_eq!(offer.ice_ufrag(), Some("uChRoMe1"));
        assert_eq!(offer.ice_pwd(), Some("ChromePwd0123456789abcdef"));
        assert!(offer.sha256_fingerprint().is_some_and(Fingerprint::is_sha256));
        assert_eq!(offer.setup(), Some(Setup::ActPass));
        assert_eq!(offer.media.len(), 3);

        let audio = &offer.media[0];
        assert_eq!(audio.kind, MediaKind::Audio);
        assert_eq!(audio.mid.as_deref(), Some("0"));
        assert_eq!(audio.direction, Direction::SendOnly);
        assert!(audio.rtcp_mux);
        assert_eq!(audio.rtcp_port, Some(9));
        assert_eq!(audio.rtpmap(111).unwrap().codec, "opus");
        assert_eq!(audio.rtpmap(111).unwrap().params.as_deref(), Some("2"));
        assert_eq!(audio.extmaps.len(), 4);
        assert_eq!(audio.msid().unwrap().track.as_deref(), Some("track-a0"));

        let video = &offer.media[1];
        assert_eq!(video.kind, MediaKind::Video);
        assert_eq!(video.extmaps.len(), 9);
        assert_eq!(
            video.rids_for(RidDirection::Send).count(),
            3,
            "three simulcast layers"
        );
        let sc = video.simulcast_for(RidDirection::Send).unwrap();
        assert_eq!(sc.list, "h;m;l");
        assert_eq!(video.fmtp(102), ["level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"]);
        assert!(video.rtpmap(40).unwrap().codec_is("rtx"));
        assert_eq!(rtx_apt(&video.fmtp(40)[0]), Some(39));

        let app = &offer.media[2];
        assert_eq!(app.kind, MediaKind::Application);
        assert!(!app.is_rtp());
    }

    #[test]
    fn chrome_answer() {
        let offer = SessionDescription::parse(CHROME_OFFER).unwrap();
        let config = test_config();
        // The datachannel mid must be absent from BUNDLE.
        let parsed = check_answer(&offer, &config, &["0", "1"]);
        let sdp = parsed_to_string(&parsed, &offer, &config);

        // Audio: opus only, our recvonly.
        let audio = &parsed.media[0];
        assert_eq!(pts(audio), [111]);
        assert_eq!(audio.direction, Direction::RecvOnly);
        assert_eq!(audio.extmaps.len(), 4);
        assert!(audio
            .feedback_for(111)
            .any(|f| f.typ == "transport-cc"));

        // Video: codec zoo intersected — VP8/H264/AV1 plus their RTX;
        // ulpfec, flexfec, red (and red's RTX) all dropped.
        let video = &parsed.media[1];
        assert_eq!(
            pts(video),
            [96, 97, 102, 103, 104, 105, 106, 107, 108, 109]
        );
        assert_eq!(video.direction, Direction::RecvOnly);
        let ext_uris: Vec<&str> = video.extmaps.iter().map(|e| e.uri.as_str()).collect();
        assert_eq!(ext_uris.len(), 4, "only mid/rid/twcc/abs-send-time kept");
        for rid in &video.rids {
            assert_eq!(rid.direction, RidDirection::Recv);
        }
        let sc = video.simulcast_for(RidDirection::Recv).unwrap();
        assert_eq!(sc.list, "h;m;l", "simulcast layer structure mirrored");

        assert!(!sdp.contains("telephone-event"), "dtmf dropped: {sdp}");
        assert!(!sdp.contains("ulpfec"), "{sdp}");
        assert!(!sdp.contains("flexfec"), "{sdp}");
        assert!(!sdp.contains("G722"), "{sdp}");
        assert!(!sdp.contains("red/48000"), "{sdp}");
        assert!(!sdp.contains("a=rtpmap:63"), "{sdp}");

        // Application: rejected, mid preserved, not bundled.
        let app = &parsed.media[2];
        assert!(app.is_rejected());
        assert_eq!(app.mid.as_deref(), Some("2"));
        assert_eq!(app.kind, MediaKind::Application);
    }

    // ── Firefox ─────────────────────────────────────────────────────────

    #[test]
    fn firefox_offer_parses() {
        let offer = SessionDescription::parse(FIREFOX_OFFER).unwrap();

        assert_eq!(offer.origin.username, "mozilla...THIS_IS_SDPARTA-99.0");
        assert_eq!(offer.bundle_mids().collect::<Vec<_>>(), ["0", "1"]);
        // Session-level fingerprint + ice-options resolve globally.
        assert!(offer.sha256_fingerprint().is_some());
        assert!(offer.transport.ice_options.contains(&"trickle".to_string()));
        assert_eq!(offer.msid_semantic, ["WMS", "*"]);
        assert_eq!(offer.setup(), Some(Setup::ActPass));

        let audio = &offer.media[0];
        assert_eq!(audio.direction, Direction::SendRecv);
        assert!(audio.end_of_candidates);
        assert_eq!(audio.candidates.len(), 2);
        let srflx = &audio.candidates[1];
        assert_eq!(srflx.typ, "srflx");
        assert!(srflx
            .extras
            .contains(&("raddr".to_string(), "192.168.1.10".to_string())));
        // Wildcard rtcp-fb kept and resolves per pt.
        assert!(audio
            .feedback_for(109)
            .any(|f| f.pt.is_none() && f.typ == "transport-cc"));

        let video = &offer.media[1];
        assert_eq!(video.candidates.len(), 1);
        let fid = video
            .ssrc_groups
            .iter()
            .find(|g| g.semantics == "FID")
            .expect("FID group parsed");
        assert_eq!(fid.ssrcs, [40_506_070, 40_506_071]);
        assert_eq!(video.ssrc_list(), [40_506_070, 40_506_071]);
        assert_eq!(video.rtpmap(121).unwrap().codec, "VP9");
    }

    #[test]
    fn firefox_answer() {
        let offer = SessionDescription::parse(FIREFOX_OFFER).unwrap();
        let config = test_config();
        let parsed = check_answer(&offer, &config, &["0", "1"]);

        let audio = &parsed.media[0];
        assert_eq!(pts(audio), [109], "opus only");
        assert_eq!(audio.direction, Direction::SendRecv);
        // Wildcard transport-cc materializes as a concrete fb line.
        assert!(audio
            .feedback_for(109)
            .any(|f| f.typ == "transport-cc"));

        let video = &parsed.media[1];
        // VP9 121 dropped; its RTX 125 must go with it.
        assert_eq!(pts(video), [120, 124, 126, 127, 108, 109]);
        assert!(video.rtpmap(121).is_none());
        assert!(video.rtpmap(125).is_none());
        // Offered feedback we support is mirrored.
        let fb120: Vec<(&str, Option<&str>)> = video
            .feedback_for(120)
            .map(|f| (f.typ.as_str(), f.param.as_deref()))
            .collect();
        for expected in [
            ("nack", None),
            ("nack", Some("pli")),
            ("ccm", Some("fir")),
            ("goog-remb", None),
            ("transport-cc", None),
        ] {
            assert!(fb120.contains(&expected), "missing fb {expected:?}");
        }
    }

    // ── Safari ──────────────────────────────────────────────────────────

    #[test]
    fn safari_offer_parses() {
        let offer = SessionDescription::parse(SAFARI_OFFER).unwrap();

        assert_eq!(offer.bundle_mids().collect::<Vec<_>>(), ["0", "1"]);
        assert_eq!(offer.ice_ufrag(), Some("uSaFaRi01"));

        let audio = &offer.media[0];
        assert_eq!(audio.rtpmap(103).unwrap().codec, "ISAC");
        assert_eq!(audio.rtpmap(103).unwrap().clock, 16_000);
        assert_eq!(audio.extmaps.len(), 2);

        let video = &offer.media[1];
        // Direction-qualified extmap parsed.
        assert_eq!(
            video.extmaps[0].direction,
            Some(Direction::SendRecv)
        );
        assert_eq!(video.extmaps[0].id, 1);
        let fid = video
            .ssrc_groups
            .iter()
            .find(|g| g.semantics == "FID")
            .unwrap();
        assert_eq!(fid.ssrcs, [777_000_111, 777_000_222]);
        let msid_attr = video
            .ssrcs
            .iter()
            .find(|s| s.attribute == "msid")
            .unwrap();
        assert_eq!(
            msid_attr.value.as_deref(),
            Some("safari-stream safari-video")
        );
    }

    #[test]
    fn safari_answer() {
        let offer = SessionDescription::parse(SAFARI_OFFER).unwrap();
        let config = test_config();
        let parsed = check_answer(&offer, &config, &["0", "1"]);

        assert_eq!(pts(&parsed.media[0]), [111], "ISAC/CN/PCMU dropped");
        // H264 + VP8 with their RTX — everything Safari offered.
        assert_eq!(pts(&parsed.media[1]), [96, 97, 98, 99, 100, 101]);
        // Only supported extensions mirrored (audio-level, mid, twcc,
        // abs-send-time) — id preserved from the offer.
        let video_exts: Vec<u8> = parsed.media[1].extmaps.iter().map(|e| e.id).collect();
        assert_eq!(video_exts, [1, 4, 7]);
    }

    // ── Cross-cutting ───────────────────────────────────────────────────

    /// Re-emit check: answers parse to the same doc regardless of helper.
    fn parsed_to_string(
        parsed: &SessionDescription,
        offer: &SessionDescription,
        config: &AnswerConfig,
    ) -> String {
        let _ = parsed;
        offer.answer(config).unwrap().into_string()
    }

    #[test]
    fn crlf_and_lf_both_parse() {
        let lf = SessionDescription::parse(CHROME_OFFER).unwrap();
        let crlf = SessionDescription::parse(&CHROME_OFFER.replace('\n', "\r\n")).unwrap();
        assert_eq!(lf, crlf);
    }

    #[test]
    fn rejects_malformed_documents() {
        assert!(matches!(
            SessionDescription::parse(""),
            Err(SdpError::UnsupportedVersion)
        ));
        assert!(matches!(
            SessionDescription::parse("v=1\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"),
            Err(SdpError::UnsupportedVersion)
        ));
        // Line without '='.
        assert!(matches!(
            SessionDescription::parse("v=0\no=- 1 2 IN IP4 0.0.0.0\ns=-\nt=0 0\ngarbage\n"),
            Err(SdpError::InvalidLine(5))
        ));
        // Missing o= / t=.
        assert!(matches!(
            SessionDescription::parse("v=0\ns=-\nt=0 0\n"),
            Err(SdpError::Missing("o="))
        ));
        assert!(matches!(
            SessionDescription::parse("v=0\no=- 1 2 IN IP4 0.0.0.0\ns=-\n"),
            Err(SdpError::Missing("t="))
        ));
        // Bad m= port.
        assert!(matches!(
            SessionDescription::parse(
                "v=0\no=- 1 2 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio x UDP/TLS/RTP/SAVPF 111\n"
            ),
            Err(SdpError::Malformed {
                what: "m= line",
                ..
            })
        ));
        // Bad known attributes.
        for (attr_line, what) in [
            ("a=rtpmap:xyz opus/48000", "a=rtpmap"),
            ("a=candidate:1 2 udp", "a=candidate"),
            ("a=setup:bogus", "a=setup"),
            ("a=ssrc-group:FID notanumber", "a=ssrc-group"),
            ("a=extmap:0 urn:ietf:params:rtp-hdrext:sdes:mid", "a=extmap"),
        ] {
            let doc = format!(
                "v=0\no=- 1 2 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 9 UDP/TLS/RTP/SAVPF 111\n{attr_line}\n"
            );
            assert!(
                matches!(
                    SessionDescription::parse(&doc),
                    Err(SdpError::Malformed { line: 6, what: w }) if w == what
                ),
                "expected Malformed {what} for {attr_line}"
            );
        }
    }

    #[test]
    fn answer_requires_config_and_media() {
        // No candidates → ICE-lite cannot answer without trickle.
        let offer = SessionDescription::parse(SAFARI_OFFER).unwrap();
        let mut config = test_config();
        config.candidates.clear();
        assert!(matches!(
            offer.answer(&config),
            Err(SdpError::Answer(_))
        ));

        // No media sections at all.
        let empty =
            SessionDescription::parse("v=0\no=- 1 2 IN IP4 0.0.0.0\ns=-\nt=0 0\n").unwrap();
        assert!(matches!(
            empty.answer(&test_config()),
            Err(SdpError::Answer(_))
        ));
    }

    #[test]
    fn direction_flips() {
        assert_eq!(Direction::SendOnly.flip(), Direction::RecvOnly);
        assert_eq!(Direction::RecvOnly.flip(), Direction::SendOnly);
        assert_eq!(Direction::SendRecv.flip(), Direction::SendRecv);
        assert_eq!(Direction::Inactive.flip(), Direction::Inactive);
    }
}
