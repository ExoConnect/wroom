//! RTP packet handling for the forwarding path: RFC 3550 headers and
//! RFC 8285 header extensions.
//!
//! Everything is zero-copy and allocation-free: [`RtpPacket`] borrows the
//! datagram it parses and [`RtpPacket::rewrite_into`] renders the forwarded
//! packet into a caller-provided scratch buffer. No function in this module
//! panics on malformed input.

use thiserror::Error;

/// Length of the fixed RTP header prefix, before the CSRC list and the
/// header extension block.
pub const FIXED_HEADER_LEN: usize = 12;

/// RFC 8285 profile identifier for the one-byte extension element form.
pub const PROFILE_ONE_BYTE: u16 = 0xBEDE;

/// Profile identifier prefix for the two-byte element form. The low nibble
/// carries application-defined "appbits", so two-byte profiles match
/// `profile & PROFILE_TWO_BYTE_MASK == PROFILE_TWO_BYTE`.
pub const PROFILE_TWO_BYTE: u16 = 0x1000;

/// Mask selecting the profile bits that identify the two-byte form.
pub const PROFILE_TWO_BYTE_MASK: u16 = 0xFFF0;

/// Errors returned when parsing or rewriting an RTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RtpError {
    /// Fewer bytes than the fixed 12-byte header.
    #[error("packet shorter than the 12-byte fixed header")]
    TooShort,
    /// The version field was not 2.
    #[error("unsupported RTP version {0}")]
    BadVersion(u8),
    /// CSRC list or extension block overruns the packet.
    #[error("RTP header extends past the end of the packet")]
    TruncatedHeader,
    /// Padding bit set but the padding count byte is missing or invalid.
    #[error("invalid RTP padding")]
    BadPadding,
    /// The scratch buffer is too small for the rewritten packet. `needed`
    /// is the exact size required, so the caller can resize and retry.
    #[error("output buffer too small: need {needed} bytes, have {have}")]
    BufferTooSmall { needed: usize, have: usize },
}

/// Header extensions the edge knows how to interpret. Variants correspond
/// to the extension URIs negotiated in SDP (`a=extmap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownExt {
    /// `urn:ietf:params:rtp-hdrext:sdes:mid`
    Mid,
    /// `urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`
    Rid,
    /// `urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id`
    RepairedRid,
    /// `urn:ietf:params:rtp-hdrext:transport-wide-cc-extensions-01`
    Twcc,
    /// `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time`
    AbsSendTime,
    /// `urn:ietf:params:rtp-hdrext:ssrc-audio-level` (RFC 6464)
    AudioLevel,
}

impl KnownExt {
    /// All known extension kinds, for iterating [`ExtMap`] contents.
    pub const ALL: [Self; 6] = [
        Self::Mid,
        Self::Rid,
        Self::RepairedRid,
        Self::Twcc,
        Self::AbsSendTime,
        Self::AudioLevel,
    ];

    /// The extension URI negotiated on the wire (SDP `a=extmap`).
    pub fn uri(self) -> &'static str {
        match self {
            Self::Mid => "urn:ietf:params:rtp-hdrext:sdes:mid",
            Self::Rid => "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
            Self::RepairedRid => "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
            Self::Twcc => "urn:ietf:params:rtp-hdrext:transport-wide-cc-extensions-01",
            Self::AbsSendTime => {
                "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
            }
            Self::AudioLevel => "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
        }
    }

    /// The extension kind for a negotiated URI, if it is one we model.
    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.uri() == uri)
    }
}

const KIND_COUNT: usize = KnownExt::ALL.len();

/// The per-leg negotiated mapping between extension IDs and extension kinds.
///
/// Fixed-size and allocation-free: the forwarding path builds one of these
/// per direction at negotiation time and reuses it per packet.
#[derive(Debug, Clone)]
pub struct ExtMap {
    /// Wire ID (1-based) -> kind. Index 0 is unused; ID 0 is padding.
    by_id: [Option<KnownExt>; 256],
    /// Kind -> wire ID. 0 means "not negotiated"; wire IDs are 1-based.
    id_by_kind: [u8; KIND_COUNT],
}

impl Default for ExtMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl ExtMap {
    /// An empty map: no extensions negotiated.
    pub const fn empty() -> Self {
        Self {
            by_id: [None; 256],
            id_by_kind: [0; KIND_COUNT],
        }
    }

    /// A map from `(id, kind)` pairs, as produced by SDP `extmap`
    /// negotiation. Entries with ID 0 are ignored (0 is the padding ID).
    pub fn from_pairs(pairs: &[(u8, KnownExt)]) -> Self {
        let mut m = Self::empty();
        for &(id, kind) in pairs {
            m.insert(id, kind);
        }
        m
    }

    /// Adds or replaces a mapping. ID 0 is rejected silently.
    pub fn insert(&mut self, id: u8, kind: KnownExt) {
        if id == 0 {
            return;
        }
        self.by_id[id as usize] = Some(kind);
        self.id_by_kind[kind as usize] = id;
    }

    /// The extension kind carried under `id`, if negotiated.
    pub fn kind(&self, id: u8) -> Option<KnownExt> {
        self.by_id[id as usize]
    }

    /// The negotiated wire ID for `kind`, if any.
    pub fn id(&self, kind: KnownExt) -> Option<u8> {
        let id = self.id_by_kind[kind as usize];
        (id != 0).then_some(id)
    }

    /// True when no extensions are mapped.
    pub fn is_empty(&self) -> bool {
        self.id_by_kind.iter().all(|&id| id == 0)
    }
}

/// Decoded audio-level extension value (RFC 6464).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioLevel {
    /// The V bit: whether the encoder believes the packet carries voice.
    pub vad: bool,
    /// Audio level in -dBov, 0 (loudest) through 127 (muted).
    pub level: u8,
}

/// A parsed RTP packet: a zero-copy view over the original datagram.
#[derive(Debug, Clone)]
pub struct RtpPacket<'a> {
    buf: &'a [u8],
    /// Offset of the payload region (payload + padding bytes), i.e. the
    /// total header length including CSRC list and extension block.
    payload_off: usize,
    /// Number of padding bytes at the tail; 0 unless the P bit is set.
    padding: usize,
    /// Extension block location, when the X bit is set.
    ext: Option<Ext>,
}

#[derive(Debug, Clone, Copy)]
struct Ext {
    /// Raw 16-bit profile identifier from the extension header.
    profile: u16,
    /// Byte offset/length of the extension element area (after the 4-byte
    /// extension header).
    off: usize,
    len: usize,
}

impl<'a> RtpPacket<'a> {
    /// Parses `buf` as a single RTP packet. `buf` must contain exactly one
    /// packet (post-SRTP-decrypt, minus the auth tag).
    pub fn parse(buf: &'a [u8]) -> Result<Self, RtpError> {
        if buf.len() < FIXED_HEADER_LEN {
            return Err(RtpError::TooShort);
        }
        let version = buf[0] >> 6;
        if version != 2 {
            return Err(RtpError::BadVersion(version));
        }
        let csrc_count = (buf[0] & 0x0f) as usize;
        let has_ext = buf[0] & 0x10 != 0;
        let mut off = FIXED_HEADER_LEN + 4 * csrc_count;
        if off > buf.len() {
            return Err(RtpError::TruncatedHeader);
        }
        let ext = if has_ext {
            if off + 4 > buf.len() {
                return Err(RtpError::TruncatedHeader);
            }
            let profile = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let words = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            let data_off = off + 4;
            let data_len = words * 4;
            if data_off + data_len > buf.len() {
                return Err(RtpError::TruncatedHeader);
            }
            off = data_off + data_len;
            Some(Ext {
                profile,
                off: data_off,
                len: data_len,
            })
        } else {
            None
        };
        let padding = if buf[0] & 0x20 != 0 {
            // P set: last byte is the padding count, which must be nonzero
            // and fit inside the payload region.
            if off >= buf.len() {
                return Err(RtpError::BadPadding);
            }
            let n = buf[buf.len() - 1] as usize;
            if n == 0 || n > buf.len() - off {
                return Err(RtpError::BadPadding);
            }
            n
        } else {
            0
        };
        Ok(Self {
            buf,
            payload_off: off,
            padding,
            ext,
        })
    }

    /// The RTP version; always 2 for a successfully parsed packet.
    pub fn version(&self) -> u8 {
        2
    }

    /// The marker bit.
    pub fn marker(&self) -> bool {
        self.buf[1] & 0x80 != 0
    }

    /// The 7-bit payload type.
    pub fn payload_type(&self) -> u8 {
        self.buf[1] & 0x7f
    }

    /// The 16-bit sequence number.
    pub fn sequence_number(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }

    /// The 32-bit RTP timestamp.
    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
    }

    /// The synchronization source identifier.
    pub fn ssrc(&self) -> u32 {
        u32::from_be_bytes([self.buf[8], self.buf[9], self.buf[10], self.buf[11]])
    }

    /// Number of CSRC entries in the header.
    pub fn csrc_count(&self) -> usize {
        (self.buf[0] & 0x0f) as usize
    }

    /// The `i`-th CSRC, if `i < csrc_count()`.
    pub fn csrc(&self, i: usize) -> Option<u32> {
        if i >= self.csrc_count() {
            return None;
        }
        let off = FIXED_HEADER_LEN + 4 * i;
        Some(u32::from_be_bytes([
            self.buf[off],
            self.buf[off + 1],
            self.buf[off + 2],
            self.buf[off + 3],
        ]))
    }

    /// Whether the padding bit is set.
    pub fn has_padding(&self) -> bool {
        self.buf[0] & 0x20 != 0
    }

    /// Number of padding bytes at the tail of the payload region.
    pub fn padding_len(&self) -> usize {
        self.padding
    }

    /// Whether the extension bit is set.
    pub fn has_extension(&self) -> bool {
        self.ext.is_some()
    }

    /// Total header length: fixed header + CSRCs + extension block.
    pub fn header_len(&self) -> usize {
        self.payload_off
    }

    /// Total packet length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Always false: a parsed packet holds at least the fixed header.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The original packet bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.buf
    }

    /// The media payload, excluding padding bytes.
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.payload_off..self.buf.len() - self.padding]
    }

    /// The raw 16-bit extension profile identifier, when the X bit is set.
    pub fn extension_profile(&self) -> Option<u16> {
        self.ext.map(|e| e.profile)
    }

    /// The raw extension element area (before per-element decoding), when
    /// the X bit is set. Also returned for unrecognized profiles.
    pub fn extension_data(&self) -> Option<&'a [u8]> {
        self.ext.map(|e| &self.buf[e.off..e.off + e.len])
    }

    /// Iterates the extension elements as `(id, value)` pairs.
    ///
    /// Only RFC 8285 one-byte (`0xBEDE`) and two-byte (`0x100x`) profiles
    /// are decoded; for any other profile the iterator is empty. Malformed
    /// elements (overrunning the block, or the reserved one-byte ID 15)
    /// terminate the iteration early.
    pub fn extensions(&self) -> ExtIter<'a> {
        let Some(ext) = self.ext else {
            return ExtIter::empty();
        };
        let data = &self.buf[ext.off..ext.off + ext.len];
        if ext.profile == PROFILE_ONE_BYTE {
            ExtIter {
                data,
                pos: 0,
                two_byte: false,
            }
        } else if ext.profile & PROFILE_TWO_BYTE_MASK == PROFILE_TWO_BYTE {
            ExtIter {
                data,
                pos: 0,
                two_byte: true,
            }
        } else {
            ExtIter::empty()
        }
    }

    /// The value of the extension element carried under wire `id`, if the
    /// packet contains one.
    pub fn extension(&self, id: u8) -> Option<&'a [u8]> {
        self.extensions().find(|&(i, _)| i == id).map(|(_, v)| v)
    }

    /// The value of a known extension, looked up through the negotiated map.
    pub fn ext_value(&self, map: &ExtMap, kind: KnownExt) -> Option<&'a [u8]> {
        self.extension(map.id(kind)?)
    }

    /// The MID extension value (ASCII opaque identifier).
    pub fn mid(&self, map: &ExtMap) -> Option<&'a [u8]> {
        self.ext_value(map, KnownExt::Mid)
    }

    /// The RID extension value.
    pub fn rid(&self, map: &ExtMap) -> Option<&'a [u8]> {
        self.ext_value(map, KnownExt::Rid)
    }

    /// The transport-wide sequence number, if the packet carries a
    /// well-formed (2-byte) TWCC element.
    pub fn twcc_seq(&self, map: &ExtMap) -> Option<u16> {
        let v = self.ext_value(map, KnownExt::Twcc)?;
        if v.len() != 2 {
            return None;
        }
        Some(u16::from_be_bytes([v[0], v[1]]))
    }

    /// The abs-send-time value as a 24-bit fixed-point timestamp
    /// (6.18 format, seconds in the top bits), if well-formed.
    pub fn abs_send_time(&self, map: &ExtMap) -> Option<u32> {
        let v = self.ext_value(map, KnownExt::AbsSendTime)?;
        if v.len() != 3 {
            return None;
        }
        Some((u32::from(v[0]) << 16) | (u32::from(v[1]) << 8) | u32::from(v[2]))
    }

    /// The audio-level value, if the packet carries a 1-byte RFC 6464
    /// element.
    pub fn audio_level(&self, map: &ExtMap) -> Option<AudioLevel> {
        let v = self.ext_value(map, KnownExt::AudioLevel)?;
        if v.len() != 1 {
            return None;
        }
        Some(AudioLevel {
            vad: v[0] & 0x80 != 0,
            level: v[0] & 0x7f,
        })
    }

    /// Whether the extension block uses the two-byte element form.
    fn ext_is_two_byte(&self) -> bool {
        matches!(
            self.ext,
            Some(e) if e.profile & PROFILE_TWO_BYTE_MASK == PROFILE_TWO_BYTE
        )
    }

    /// Renders the forwarded form of this packet into `out`.
    ///
    /// The header is rewritten per `rw` (sequence number, timestamp, SSRC,
    /// optional payload-type remap), the CSRC list, marker bit, padding and
    /// payload are preserved, and the extension block is rebuilt by mapping
    /// each source element's ID through `in_map`/`out_map`:
    ///
    /// - elements whose kind is not negotiated on the outgoing leg are
    ///   dropped (sending an ID the subscriber did not negotiate would be a
    ///   protocol violation, and unknown element kinds cannot be mapped
    ///   safely),
    /// - the TWCC element is rewritten to `twcc_seq` when provided, and
    ///   synthesized when the source packet lacks one but the outgoing leg
    ///   negotiates TWCC,
    /// - if no elements survive and none is inserted, the extension block is
    ///   omitted entirely.
    ///
    /// `out` must not overlap the source packet. On
    /// [`RtpError::BufferTooSmall`] the `needed` field carries the exact
    /// required size so the caller can retry once with a bigger buffer.
    pub fn rewrite_into(&self, out: &mut [u8], rw: &Rewrite<'_>) -> Result<usize, RtpError> {
        let cc = self.csrc_count();
        let twcc_out_id = rw.out_map.id(KnownExt::Twcc);
        let twcc_bytes = rw.twcc_seq.map(u16::to_be_bytes);

        // Pass 1: which elements survive the remap, and how large the
        // rebuilt extension block will be.
        let mut count = 0usize;
        let mut data_bytes = 0usize;
        let mut max_id = 0u8;
        let mut max_len = 0usize;
        let mut twcc_emitted = false;
        for (in_id, data) in self.extensions() {
            let Some(kind) = rw.in_map.kind(in_id) else { continue };
            let Some(out_id) = rw.out_map.id(kind) else { continue };
            let out_len = if kind == KnownExt::Twcc && twcc_bytes.is_some() {
                2
            } else {
                data.len()
            };
            count += 1;
            data_bytes += out_len;
            max_id = max_id.max(out_id);
            max_len = max_len.max(out_len);
            if kind == KnownExt::Twcc {
                twcc_emitted = true;
            }
        }
        let twcc_insert = !twcc_emitted && twcc_bytes.is_some() && twcc_out_id.is_some();
        if twcc_insert {
            count += 1;
            data_bytes += 2;
            max_len = max_len.max(2);
            if let Some(id) = twcc_out_id {
                max_id = max_id.max(id);
            }
        }

        let emit_ext = count > 0;
        // Keep the source element form when possible; upgrade to two-byte
        // when an emitted ID or length cannot be expressed in the
        // one-byte form.
        let two_byte =
            emit_ext && (self.ext_is_two_byte() || max_id > 14 || max_len > 16);
        let per_el: usize = if two_byte { 2 } else { 1 };
        let elements_len = data_bytes + count * per_el;
        let ext_data_len = elements_len.div_ceil(4) * 4;
        let ext_block_len = if emit_ext { 4 + ext_data_len } else { 0 };
        let payload_len = self.buf.len() - self.payload_off;
        let needed = FIXED_HEADER_LEN + 4 * cc + ext_block_len + payload_len;
        if out.len() < needed {
            return Err(RtpError::BufferTooSmall {
                needed,
                have: out.len(),
            });
        }

        // Pass 2: write the outgoing packet. Every offset below is bounded
        // by `needed <= out.len()`.
        let mut b0: u8 = 0x80 | cc as u8;
        if self.has_padding() {
            b0 |= 0x20;
        }
        if emit_ext {
            b0 |= 0x10;
        }
        out[0] = b0;
        out[1] = (self.buf[1] & 0x80)
            | rw.payload_type
                .map(|p| p & 0x7f)
                .unwrap_or_else(|| self.payload_type());
        out[2..4].copy_from_slice(&rw.sequence_number.to_be_bytes());
        out[4..8].copy_from_slice(&rw.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&rw.ssrc.to_be_bytes());
        let mut w = FIXED_HEADER_LEN;
        let csrc_end = w + 4 * cc;
        out[w..csrc_end].copy_from_slice(&self.buf[w..csrc_end]);
        w = csrc_end;

        if emit_ext {
            let profile = if two_byte {
                match self.extension_profile() {
                    Some(p) if p & PROFILE_TWO_BYTE_MASK == PROFILE_TWO_BYTE => p,
                    _ => PROFILE_TWO_BYTE,
                }
            } else {
                PROFILE_ONE_BYTE
            };
            out[w..w + 2].copy_from_slice(&profile.to_be_bytes());
            out[w + 2..w + 4].copy_from_slice(&((ext_data_len / 4) as u16).to_be_bytes());
            w += 4;
            let elems_end = w + ext_data_len;
            out[w..elems_end].fill(0);
            for (in_id, data) in self.extensions() {
                let Some(kind) = rw.in_map.kind(in_id) else { continue };
                let Some(out_id) = rw.out_map.id(kind) else { continue };
                let value: &[u8] = if kind == KnownExt::Twcc {
                    twcc_bytes.as_ref().map_or(data, |b| &b[..])
                } else {
                    data
                };
                if two_byte {
                    out[w] = out_id;
                    out[w + 1] = value.len() as u8;
                    w += 2;
                } else {
                    out[w] = (out_id << 4) | (value.len() as u8).saturating_sub(1);
                    w += 1;
                }
                out[w..w + value.len()].copy_from_slice(value);
                w += value.len();
            }
            if twcc_insert {
                let seq = twcc_bytes.unwrap_or_default();
                if let Some(id) = twcc_out_id {
                    if two_byte {
                        out[w] = id;
                        out[w + 1] = 2;
                        w += 2;
                    } else {
                        out[w] = (id << 4) | 1;
                        w += 1;
                    }
                    out[w..w + 2].copy_from_slice(&seq);
                }
            }
            w = elems_end;
        }

        let end = w + payload_len;
        out[w..end].copy_from_slice(&self.buf[self.payload_off..]);
        Ok(end)
    }
}

/// Field remapping applied by [`RtpPacket::rewrite_into`] when forwarding a
/// packet out a subscriber leg.
#[derive(Debug, Clone, Copy)]
pub struct Rewrite<'m> {
    /// Extension ID -> kind mapping negotiated on the incoming
    /// (publisher) leg.
    pub in_map: &'m ExtMap,
    /// Kind -> extension ID mapping negotiated on the outgoing
    /// (subscriber) leg.
    pub out_map: &'m ExtMap,
    /// Sequence number on the outgoing leg.
    pub sequence_number: u16,
    /// RTP timestamp on the outgoing leg.
    pub timestamp: u32,
    /// SSRC on the outgoing leg.
    pub ssrc: u32,
    /// New transport-wide sequence number. Written into the TWCC element
    /// (or into a synthesized element) when the outgoing leg negotiates
    /// TWCC; ignored otherwise.
    pub twcc_seq: Option<u16>,
    /// Remapped payload type; `None` forwards the source PT unchanged.
    pub payload_type: Option<u8>,
}

/// Iterator over a packet's RFC 8285 extension elements.
///
/// Yields `(id, value)` pairs. Terminates early on malformed input; empty
/// for unrecognized extension profiles.
#[derive(Debug, Clone)]
pub struct ExtIter<'a> {
    data: &'a [u8],
    pos: usize,
    two_byte: bool,
}

impl<'a> ExtIter<'a> {
    fn empty() -> Self {
        Self {
            data: &[],
            pos: 0,
            two_byte: false,
        }
    }
}

impl<'a> Iterator for ExtIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.data.len() {
            if self.two_byte {
                let id = self.data[self.pos];
                if id == 0 {
                    // Padding byte.
                    self.pos += 1;
                    continue;
                }
                if self.pos + 2 > self.data.len() {
                    break;
                }
                let len = self.data[self.pos + 1] as usize;
                let start = self.pos + 2;
                if start + len > self.data.len() {
                    break;
                }
                self.pos = start + len;
                return Some((id, &self.data[start..start + len]));
            }
            let b = self.data[self.pos];
            let id = b >> 4;
            if id == 15 {
                // Reserved: stops the extension block.
                break;
            }
            if id == 0 {
                // Padding byte.
                self.pos += 1;
                continue;
            }
            let len = (b & 0x0f) as usize + 1;
            let start = self.pos + 1;
            if start + len > self.data.len() {
                break;
            }
            self.pos = start + len;
            return Some((id, &self.data[start..start + len]));
        }
        self.pos = self.data.len();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps() -> (ExtMap, ExtMap) {
        let in_map = ExtMap::from_pairs(&[
            (1, KnownExt::Mid),
            (4, KnownExt::Twcc),
            (9, KnownExt::AudioLevel),
        ]);
        let out_map = ExtMap::from_pairs(&[
            (2, KnownExt::Mid),
            (7, KnownExt::Twcc),
            (11, KnownExt::AudioLevel),
        ]);
        (in_map, out_map)
    }

    /// A one-byte-extension packet: X=1, M=1, PT=96, seq=0x1234,
    /// ts=0xA0B0C0D0, ssrc=0x11223344; ext 0xBEDE with mid(id1)="hi",
    /// twcc(id4)=0xBEEF, level(id9)=0x85; payload "PAYL".
    fn one_byte_packet() -> Vec<u8> {
        let elements = [
            0x11, b'h', b'i', // id 1, len 2
            0x41, 0xBE, 0xEF, // id 4, len 2
            0x90, 0x85, // id 9, len 1
            0, 0, 0, 0, // padding to 4 bytes
        ];
        let mut p = vec![
            0x90, 0xE0, 0x12, 0x34, 0xA0, 0xB0, 0xC0, 0xD0, 0x11, 0x22, 0x33, 0x44, 0xBE, 0xDE,
            0x00, 0x03,
        ];
        p.extend_from_slice(&elements);
        p.extend_from_slice(b"PAYL");
        p
    }

    #[test]
    fn parses_fixed_header_fields() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        assert_eq!(pkt.version(), 2);
        assert!(pkt.marker());
        assert_eq!(pkt.payload_type(), 96);
        assert_eq!(pkt.sequence_number(), 0x1234);
        assert_eq!(pkt.timestamp(), 0xA0B0C0D0);
        assert_eq!(pkt.ssrc(), 0x11223344);
        assert_eq!(pkt.csrc_count(), 0);
        assert_eq!(pkt.csrc(0), None);
        assert!(pkt.has_extension());
        assert!(!pkt.has_padding());
        assert_eq!(pkt.header_len(), 12 + 4 + 12);
        assert_eq!(pkt.payload(), b"PAYL");
    }

    #[test]
    fn parses_one_byte_extensions() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        assert_eq!(pkt.extension_profile(), Some(0xBEDE));
        let els: Vec<(u8, &[u8])> = pkt.extensions().collect();
        assert_eq!(els, [(1, b"hi".as_slice()), (4, &[0xBE, 0xEF][..]), (9, &[0x85][..])]);
        let (in_map, _) = maps();
        assert_eq!(pkt.mid(&in_map), Some(b"hi".as_slice()));
        assert_eq!(pkt.twcc_seq(&in_map), Some(0xBEEF));
        assert_eq!(
            pkt.audio_level(&in_map),
            Some(AudioLevel {
                vad: true,
                level: 5
            })
        );
        assert_eq!(pkt.rid(&in_map), None);
    }

    #[test]
    fn parses_two_byte_extensions() {
        // Profile 0x1002 (appbits 2), elements: id=5 len=3 "abc",
        // id=0 padding, id=200 len=2 twcc, id=42 len=0.
        let elements = [
            5, 3, b'a', b'b', b'c', // id 5
            0, // padding
            200, 2, 0x12, 0x34, // id 200
            42, 0, // id 42, zero-length
        ];
        let mut p = vec![
            0x90, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x02, 0x00, 0x03,
        ];
        p.extend_from_slice(&elements);
        p.extend_from_slice(b"X");
        let pkt = RtpPacket::parse(&p).unwrap();
        assert_eq!(pkt.extension_profile(), Some(0x1002));
        let els: Vec<(u8, &[u8])> = pkt.extensions().collect();
        assert_eq!(
            els,
            [
                (5, b"abc".as_slice()),
                (200, &[0x12, 0x34][..]),
                (42, &[][..])
            ]
        );
        let map = ExtMap::from_pairs(&[(200, KnownExt::Twcc)]);
        assert_eq!(pkt.twcc_seq(&map), Some(0x1234));
        assert_eq!(pkt.extension(42), Some(&[][..]));
        assert_eq!(pkt.payload(), b"X");
    }

    #[test]
    fn parses_csrc_list_and_padding() {
        // V=2, P=1, X=0, CC=2, M=0, PT=0; two CSRCs; payload "AB" + 3 pad
        // bytes (zeros) + count byte 4.
        let mut p = vec![0xA2, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x2A];
        p.extend_from_slice(&[0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
        p.extend_from_slice(b"AB");
        p.extend_from_slice(&[0, 0, 0, 4]);
        let pkt = RtpPacket::parse(&p).unwrap();
        assert_eq!(pkt.csrc_count(), 2);
        assert_eq!(pkt.csrc(0), Some(0xAAAAAAAA));
        assert_eq!(pkt.csrc(1), Some(0xBBBBBBBB));
        assert!(pkt.has_padding());
        assert_eq!(pkt.padding_len(), 4);
        assert_eq!(pkt.payload(), b"AB");
        assert_eq!(pkt.header_len(), 12 + 8);
    }

    #[test]
    fn rewrite_remaps_fields_and_extensions() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let (in_map, out_map) = maps();
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 0x0001,
            timestamp: 0x01020304,
            ssrc: 0xAABBCCDD,
            twcc_seq: Some(0x7777),
            payload_type: Some(111),
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        assert_eq!(fwd.sequence_number(), 1);
        assert_eq!(fwd.timestamp(), 0x01020304);
        assert_eq!(fwd.ssrc(), 0xAABBCCDD);
        assert_eq!(fwd.payload_type(), 111);
        assert!(fwd.marker());
        assert_eq!(fwd.payload(), b"PAYL");
        // Remapped IDs: mid now under 2, twcc under 7 with the new value,
        // audio level under 11 untouched.
        assert_eq!(fwd.mid(&out_map), Some(b"hi".as_slice()));
        assert_eq!(fwd.twcc_seq(&out_map), Some(0x7777));
        assert_eq!(
            fwd.audio_level(&out_map),
            Some(AudioLevel {
                vad: true,
                level: 5
            })
        );
        // The incoming IDs are not present.
        assert_eq!(fwd.extension(1), None);
        assert_eq!(fwd.extension(4), None);
        assert_eq!(fwd.extension(9), None);
    }

    #[test]
    fn rewrite_drops_unmapped_elements() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let in_map = ExtMap::from_pairs(&[(1, KnownExt::Mid), (4, KnownExt::Twcc)]);
        // Outgoing leg only negotiates MID, under a different ID.
        let out_map = ExtMap::from_pairs(&[(3, KnownExt::Mid)]);
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 9,
            timestamp: 9,
            ssrc: 9,
            twcc_seq: Some(0x1111),
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        // TWCC was neither mapped out nor inserted (not negotiated out);
        // the audio-level element is unmapped on input and dropped.
        assert_eq!(fwd.mid(&out_map), Some(b"hi".as_slice()));
        let els: Vec<(u8, &[u8])> = fwd.extensions().collect();
        assert_eq!(els, [(3, b"hi".as_slice())]);
    }

    #[test]
    fn rewrite_synthesizes_twcc_when_source_has_no_extension() {
        // No X bit at all.
        let mut p = vec![0x80, 0x60, 0x00, 0x42, 0, 0, 0, 1, 0, 0, 0, 7];
        p.extend_from_slice(b"DATA");
        let pkt = RtpPacket::parse(&p).unwrap();
        let in_map = ExtMap::empty();
        let out_map = ExtMap::from_pairs(&[(5, KnownExt::Twcc)]);
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 0x1234,
            timestamp: 0x55,
            ssrc: 0x66,
            twcc_seq: Some(0xC0DE),
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        assert!(fwd.has_extension());
        assert_eq!(fwd.twcc_seq(&out_map), Some(0xC0DE));
        assert_eq!(fwd.payload(), b"DATA");
        assert_eq!(fwd.sequence_number(), 0x1234);
    }

    #[test]
    fn rewrite_upgrades_to_two_byte_form_for_high_ids() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let (in_map, _) = maps();
        // Outgoing TWCC under ID 200 — not representable in one-byte form.
        let out_map = ExtMap::from_pairs(&[(200, KnownExt::Twcc), (6, KnownExt::Mid)]);
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 1,
            timestamp: 2,
            ssrc: 3,
            twcc_seq: Some(0x0ABC),
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        assert_eq!(
            fwd.extension_profile().unwrap() & PROFILE_TWO_BYTE_MASK,
            PROFILE_TWO_BYTE
        );
        assert_eq!(fwd.twcc_seq(&out_map), Some(0x0ABC));
        assert_eq!(fwd.mid(&out_map), Some(b"hi".as_slice()));
    }

    #[test]
    fn rewrite_omits_extension_block_when_nothing_survives() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let in_map = ExtMap::from_pairs(&[(1, KnownExt::Mid)]);
        let out_map = ExtMap::empty();
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 1,
            timestamp: 2,
            ssrc: 3,
            twcc_seq: None,
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        assert!(!fwd.has_extension());
        assert_eq!(fwd.payload(), b"PAYL");
    }

    #[test]
    fn rewrite_preserves_padding_and_csrcs() {
        let mut p = vec![0xA2, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0, 0x2A];
        p.extend_from_slice(&[0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
        p.extend_from_slice(b"AB");
        p.extend_from_slice(&[0, 0, 0, 4]);
        let pkt = RtpPacket::parse(&p).unwrap();
        let rw = Rewrite {
            in_map: &ExtMap::empty(),
            out_map: &ExtMap::empty(),
            sequence_number: 77,
            timestamp: 88,
            ssrc: 99,
            twcc_seq: None,
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        assert!(fwd.has_padding());
        assert_eq!(fwd.padding_len(), 4);
        assert_eq!(fwd.payload(), b"AB");
        assert_eq!(fwd.csrc(0), Some(0xAAAAAAAA));
        assert_eq!(fwd.csrc(1), Some(0xBBBBBBBB));
    }

    #[test]
    fn rewrite_reports_exact_needed_size() {
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let (in_map, out_map) = maps();
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 1,
            timestamp: 2,
            ssrc: 3,
            twcc_seq: Some(4),
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let err = pkt.rewrite_into(&mut out[..n - 1], &rw).unwrap_err();
        assert_eq!(
            err,
            RtpError::BufferTooSmall {
                needed: n,
                have: n - 1
            }
        );
    }

    #[test]
    fn rejects_malformed_packets() {
        // Empty and short.
        assert_eq!(RtpPacket::parse(&[]).unwrap_err(), RtpError::TooShort);
        assert_eq!(
            RtpPacket::parse(&[0x80; 11]).unwrap_err(),
            RtpError::TooShort
        );
        // Bad version.
        let mut v1 = [0u8; 12];
        v1[0] = 0x40;
        assert_eq!(
            RtpPacket::parse(&v1).unwrap_err(),
            RtpError::BadVersion(1)
        );
        // CSRC list overruns the packet.
        let mut c = [0u8; 12];
        c[0] = 0x8F;
        assert_eq!(
            RtpPacket::parse(&c).unwrap_err(),
            RtpError::TruncatedHeader
        );
        // X bit set but no room for the extension header.
        let mut x = [0u8; 14];
        x[0] = 0x90;
        assert_eq!(
            RtpPacket::parse(&x).unwrap_err(),
            RtpError::TruncatedHeader
        );
        // Extension length overruns the packet.
        let mut e = vec![0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xBE, 0xDE, 0x00, 0x05];
        e.extend_from_slice(&[0; 4]);
        assert_eq!(
            RtpPacket::parse(&e).unwrap_err(),
            RtpError::TruncatedHeader
        );
        // P set but the payload region is empty (no count byte).
        let mut pz = [0u8; 12];
        pz[0] = 0xA0;
        assert_eq!(RtpPacket::parse(&pz).unwrap_err(), RtpError::BadPadding);
        // Padding count of zero.
        let mut p0 = vec![0xA0, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        p0.extend_from_slice(&[0xAA, 0x00]);
        assert_eq!(RtpPacket::parse(&p0).unwrap_err(), RtpError::BadPadding);
        // Padding count larger than the payload region.
        let mut pb = vec![0xA0, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        pb.extend_from_slice(&[0xAA, 0xBB, 0x10]);
        assert_eq!(RtpPacket::parse(&pb).unwrap_err(), RtpError::BadPadding);
    }

    #[test]
    fn malformed_extension_elements_do_not_panic() {
        // Element declares more bytes than remain.
        let mut p = vec![
            0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xBE, 0xDE, 0x00, 0x01, 0x14, b'a',
        ];
        p.extend_from_slice(&[0, 0]);
        let pkt = RtpPacket::parse(&p).unwrap();
        assert_eq!(pkt.extensions().count(), 0);
        assert_eq!(pkt.extension(1), None);
        // Reserved ID 15 stops iteration.
        let mut q = vec![
            0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xBE, 0xDE, 0x00, 0x01, 0xF0, 0x11,
        ];
        q.extend_from_slice(&[b'x', 0]);
        let pkt = RtpPacket::parse(&q).unwrap();
        assert_eq!(pkt.extensions().count(), 0);
        // Truncated two-byte element header: a lone ID byte at the end of
        // the block, with no room left for its length byte.
        let r = [
            0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0x00, 0x01, 0, 0, 0, 0x05,
        ];
        let pkt = RtpPacket::parse(&r).unwrap();
        assert_eq!(pkt.extensions().count(), 0);
    }

    #[test]
    fn extension_round_trip_through_rewrite() {
        // Parse -> rewrite -> parse again yields a consistent packet.
        let src = one_byte_packet();
        let pkt = RtpPacket::parse(&src).unwrap();
        let (in_map, out_map) = maps();
        let rw = Rewrite {
            in_map: &in_map,
            out_map: &out_map,
            sequence_number: 0xFFFF,
            timestamp: 0x12345678,
            ssrc: 0xCAFEBABE,
            twcc_seq: Some(0x0001),
            payload_type: None,
        };
        let mut out = [0u8; 2048];
        let n = pkt.rewrite_into(&mut out, &rw).unwrap();
        let fwd = RtpPacket::parse(&out[..n]).unwrap();
        // And once more, treating the forwarded packet as input.
        let rw2 = Rewrite {
            in_map: &out_map,
            out_map: &in_map,
            sequence_number: 0xEEEE,
            timestamp: 0x87654321,
            ssrc: 0x0BADF00D,
            twcc_seq: Some(0x0002),
            payload_type: None,
        };
        // `fwd` borrows `out`, so the second rewrite renders into its own
        // scratch buffer.
        let mut out2 = [0u8; 2048];
        let n2 = fwd.rewrite_into(&mut out2, &rw2).unwrap();
        let fwd2 = RtpPacket::parse(&out2[..n2]).unwrap();
        assert_eq!(fwd2.sequence_number(), 0xEEEE);
        assert_eq!(fwd2.twcc_seq(&in_map), Some(0x0002));
        assert_eq!(fwd2.mid(&in_map), Some(b"hi".as_slice()));
        assert_eq!(fwd2.payload(), b"PAYL");
    }
}
