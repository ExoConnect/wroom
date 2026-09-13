//! STUN message codec (RFC 5389) and an ICE-lite agent (RFC 8445).
//!
//! Everything in this module is Sans-IO: the caller owns the socket and
//! the timer wheel, feeds `(datagram, source address, now)` in together
//! with a scratch buffer, and reads response datagrams, timeout deadlines,
//! and events back out. Nothing here performs IO, blocks, locks, or
//! allocates on the packet path.
//!
//! # ICE-lite
//!
//! [`IceLiteAgent`] is the server half of ICE connectivity checks. Per
//! RFC 8445 §2.5 it only ever holds host candidates, never initiates
//! connectivity checks, and only responds to them. Because our peer is
//! always a full agent, the agent is always in the controlled role
//! (RFC 8445 §6.1.1: "the lite agent MUST take the controlled role").
//!
//! A valid check is a STUN Binding request whose USERNAME is
//! `"<local_ufrag>:<remote_ufrag>"` and whose MESSAGE-INTEGRITY verifies
//! against the local ICE password. The answer carries XOR-MAPPED-ADDRESS.
//! A request bearing USE-CANDIDATE nominates the pair; the agent emits
//! [`IceEvent::Nominated`] once per newly selected remote address, so
//! retransmitted nominations are idempotent.
//!
//! # Usage
//!
//! ```ignore
//! let mut agent = IceLiteAgent::new("srvUfrag", "srvPwd", Some("cliUfrag"));
//! let mut scratch = [0u8; ice::MAX_RESPONSE_LEN];
//! let out = agent.handle_datagram(&dgram, src, Instant::now(), &mut scratch);
//! if let Some(n) = out.response {
//!     socket.send_to(&scratch[..n], src);
//! }
//! if let Some(IceEvent::Nominated(addr)) = out.event {
//!     // pair selected — safe to start DTLS on it
//! }
//! // timer integration:
//! if let Some(deadline) = agent.poll_timeout() {
//!     timer.arm(deadline); // on expiry call agent.handle_timeout(now)
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use thiserror::Error;
use tracing::trace;

/// Size of the fixed STUN message header in bytes.
pub const HEADER_LEN: usize = 20;
/// RFC 5389 magic cookie, always at bytes 4..8 of a STUN message.
pub const MAGIC_COOKIE: u32 = 0x2112_a442;
/// XOR mask applied to the CRC-32 in the FINGERPRINT attribute
/// (RFC 5389 §15.5).
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// STUN message type: Binding request.
pub const BINDING_REQUEST: u16 = 0x0001;
/// STUN message type: Binding indication (used for keepalives,
/// RFC 8445 §11). Never answered.
pub const BINDING_INDICATION: u16 = 0x0011;
/// STUN message type: Binding success response.
pub const BINDING_SUCCESS: u16 = 0x0101;
/// STUN message type: Binding error response.
pub const BINDING_ERROR: u16 = 0x0111;

/// STUN method number for Binding (the only method we implement).
pub const METHOD_BINDING: u16 = 0x001;

/// An upper bound on the response datagrams this module produces.
/// Callers should hand [`IceLiteAgent::handle_datagram`] a scratch buffer
/// at least this large.
pub const MAX_RESPONSE_LEN: usize = 256;

/// Maximum number of validated remote addresses tracked at once.
const MAX_PAIRS: usize = 64;
/// How long a validated but non-selected pair is kept without traffic.
/// Keepalives (Binding indications) refresh it; RFC 8445 §11 recommends a
/// 15 s keepalive period, so 30 s tolerates one lost indication.
const PAIR_TTL: Duration = Duration::from_secs(30);
/// Maximum number of unknown attribute types echoed in a 420 response.
const MAX_UNKNOWN_ATTRS: usize = 16;

const SOFTWARE_NAME: &str = "wroom-wroom";

type HmacSha1 = Hmac<Sha1>;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// STUN and ICE attribute types this module knows about.
pub mod attr {
    /// MAPPED-ADDRESS (RFC 5389 §15.1). Parsed but unused by ICE.
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    /// USERNAME (RFC 5389 §15.3).
    pub const USERNAME: u16 = 0x0006;
    /// MESSAGE-INTEGRITY (RFC 5389 §15.4).
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    /// ERROR-CODE (RFC 5389 §15.6).
    pub const ERROR_CODE: u16 = 0x0009;
    /// UNKNOWN-ATTRIBUTES (RFC 5389 §15.9).
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000a;
    /// REALM (RFC 5389 §15.7). Long-term credentials only; unused by ICE.
    pub const REALM: u16 = 0x0014;
    /// NONCE (RFC 5389 §15.8). Long-term credentials only; unused by ICE.
    pub const NONCE: u16 = 0x0015;
    /// XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    /// PRIORITY (RFC 8445 §16.1).
    pub const PRIORITY: u16 = 0x0024;
    /// USE-CANDIDATE (RFC 8445 §16.3).
    pub const USE_CANDIDATE: u16 = 0x0025;
    /// SOFTWARE (RFC 5389 §15.10).
    pub const SOFTWARE: u16 = 0x8022;
    /// FINGERPRINT (RFC 5389 §15.5).
    pub const FINGERPRINT: u16 = 0x8028;
    /// ICE-CONTROLLED (RFC 8445 §16.5).
    pub const ICE_CONTROLLED: u16 = 0x8029;
    /// ICE-CONTROLLING (RFC 8445 §16.4).
    pub const ICE_CONTROLLING: u16 = 0x802a;
}

/// Attributes the ICE-lite agent understands. Everything else in the
/// comprehension-required range (`< 0x8000`) triggers a 420 response per
/// RFC 5389 §7.3.1. REALM/NONCE/MAPPED-ADDRESS are known-but-unused and
/// are ignored rather than rejected (RFC 5389 §7.3).
const KNOWN_ATTRS: &[u16] = &[
    attr::MAPPED_ADDRESS,
    attr::USERNAME,
    attr::MESSAGE_INTEGRITY,
    attr::ERROR_CODE,
    attr::UNKNOWN_ATTRIBUTES,
    attr::REALM,
    attr::NONCE,
    attr::XOR_MAPPED_ADDRESS,
    attr::PRIORITY,
    attr::USE_CANDIDATE,
    attr::SOFTWARE,
    attr::FINGERPRINT,
    attr::ICE_CONTROLLED,
    attr::ICE_CONTROLLING,
];

/// Errors returned by the STUN codec. Malformed input always produces an
/// `Err`, never a panic.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StunError {
    /// Fewer than [`HEADER_LEN`] bytes were provided.
    #[error("datagram shorter than STUN header")]
    TooShort,
    /// The leading bits of the message are not `0b00`.
    #[error("not a STUN message")]
    NotStun,
    /// The magic cookie at bytes 4..8 did not match.
    #[error("magic cookie mismatch")]
    BadCookie,
    /// The message length field is not a multiple of 4.
    #[error("message length not a multiple of 4")]
    BadLength,
    /// The datagram is shorter than the declared message length.
    #[error("datagram truncated")]
    Truncated,
    /// An attribute header or value runs past the end of the message.
    #[error("malformed attribute framing")]
    MalformedAttributes,
    /// The caller-provided output buffer cannot hold the message.
    #[error("output buffer too small")]
    BufferTooSmall,
    /// An attribute value exceeds the 16-bit attribute length field.
    #[error("attribute too large")]
    AttributeTooLarge,
    /// The finished message exceeds the 16-bit message length field.
    #[error("message too large")]
    MessageTooLarge,
    /// Attributes cannot be appended after MESSAGE-INTEGRITY/FINGERPRINT.
    #[error("attribute written after message integrity or fingerprint")]
    AttributeOrder,
}

/// STUN message class, decoded from the message type field
/// (RFC 5389 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Request — expects a response.
    Request,
    /// Indication — never answered.
    Indication,
    /// Success response.
    Success,
    /// Error response.
    Error,
}

/// ICE role asserted by a Binding request (RFC 8445 §16.4/§16.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// The sender claims the controlling role (ICE-CONTROLLING present).
    Controlling,
    /// The sender claims the controlled role (ICE-CONTROLLED present).
    Controlled,
}

/// Round `n` up to a multiple of 4 (STUN attribute padding).
fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
fn encode_type(class: Class, method: u16) -> u16 {
    let class_bits = match class {
        Class::Request => 0,
        Class::Indication => 0x0010,
        Class::Success => 0x0100,
        Class::Error => 0x0110,
    };
    class_bits | (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f80) << 2)
}

/// Cheap datagram classifier for STUN/DTLS/RTP multiplexing (RFC 7983).
///
/// Accepts only first-byte values 0..4 (STUN message types never use
/// them) plus the magic cookie, so DTLS records (first byte 20..64) and
/// RTP/RTCP (first byte >= 128) are reliably excluded.
pub fn is_stun_datagram(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] <= 3 && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// A parsed STUN attribute, borrowing from the message bytes.
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'a> {
    /// The 16-bit attribute type.
    pub attr_type: u16,
    /// Byte offset of the attribute header within the message.
    pub offset: usize,
    /// The attribute value (padding excluded).
    pub value: &'a [u8],
}

impl Attribute<'_> {
    /// Comprehension-required attributes live in 0x0000..=0x7fff
    /// (RFC 5389 §15).
    pub fn is_comprehension_required(&self) -> bool {
        self.attr_type < 0x8000
    }
}

/// Iterator over the attributes of a parsed [`Message`].
///
/// Framing is validated by [`Message::parse`], so iteration is
/// infallible; any internal inconsistency simply ends iteration.
#[derive(Debug, Clone)]
pub struct Attributes<'a> {
    raw: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Attribute<'a>> {
        let hdr = self.raw.get(self.off..self.off + 4)?;
        let attr_type = u16::from_be_bytes([hdr[0], hdr[1]]);
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let value = self.raw.get(self.off + 4..self.off + 4 + len)?;
        let attr = Attribute {
            attr_type,
            offset: self.off,
            value,
        };
        self.off += 4 + pad4(len);
        Some(attr)
    }
}

/// A parsed STUN message. Borrows the input datagram.
#[derive(Debug)]
pub struct Message<'a> {
    /// Header plus attributes, trimmed to the declared message length.
    raw: &'a [u8],
    msg_type: u16,
    transaction_id: [u8; 12],
}

impl<'a> Message<'a> {
    /// Parse and validate a STUN message.
    ///
    /// Attribute framing is checked eagerly so [`Message::attributes`]
    /// can never observe a malformed attribute. Bytes after the declared
    /// message length are ignored.
    pub fn parse(datagram: &'a [u8]) -> Result<Self, StunError> {
        if datagram.len() < HEADER_LEN {
            return Err(StunError::TooShort);
        }
        if datagram[0] & 0xc0 != 0 {
            return Err(StunError::NotStun);
        }
        let msg_type = u16::from_be_bytes([datagram[0], datagram[1]]);
        let declared = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
        if !declared.is_multiple_of(4) {
            return Err(StunError::BadLength);
        }
        if datagram[4..8] != MAGIC_COOKIE.to_be_bytes() {
            return Err(StunError::BadCookie);
        }
        let end = HEADER_LEN + declared;
        if datagram.len() < end {
            return Err(StunError::Truncated);
        }
        let raw = &datagram[..end];

        // Validate attribute framing: every attribute (header + padded
        // value) must fit exactly inside the declared message length.
        // Padding counts toward the length per RFC 5389 §15.
        let mut off = HEADER_LEN;
        while off < end {
            let Some(hdr) = raw.get(off..off + 4) else {
                return Err(StunError::MalformedAttributes);
            };
            let alen = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
            let next = off + 4 + pad4(alen);
            if next > end {
                return Err(StunError::MalformedAttributes);
            }
            off = next;
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&raw[8..20]);
        Ok(Message {
            raw,
            msg_type,
            transaction_id,
        })
    }

    /// The raw 16-bit message type field.
    pub fn message_type(&self) -> u16 {
        self.msg_type
    }

    /// The decoded STUN method (RFC 5389 §6).
    pub fn method(&self) -> u16 {
        (self.msg_type & 0x000f) | ((self.msg_type & 0x00e0) >> 1) | ((self.msg_type & 0x3e00) >> 2)
    }

    /// The decoded message class.
    pub fn class(&self) -> Class {
        match ((self.msg_type >> 4) & 1) | ((self.msg_type >> 7) & 2) {
            0 => Class::Request,
            1 => Class::Indication,
            2 => Class::Success,
            _ => Class::Error,
        }
    }

    /// The 96-bit transaction ID.
    pub fn transaction_id(&self) -> [u8; 12] {
        self.transaction_id
    }

    /// The complete message bytes (header + attributes).
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Iterate over all attributes in wire order.
    pub fn attributes(&self) -> Attributes<'a> {
        Attributes {
            raw: self.raw,
            off: HEADER_LEN,
        }
    }

    /// First attribute of the given type, if present.
    pub fn get(&self, attr_type: u16) -> Option<Attribute<'a>> {
        self.attributes().find(|a| a.attr_type == attr_type)
    }

    /// USERNAME as UTF-8. `None` when absent or not valid UTF-8.
    pub fn username(&self) -> Option<&'a str> {
        self.get(attr::USERNAME)
            .and_then(|a| std::str::from_utf8(a.value).ok())
    }

    /// SOFTWARE as UTF-8. `None` when absent or not valid UTF-8.
    pub fn software(&self) -> Option<&'a str> {
        self.get(attr::SOFTWARE)
            .and_then(|a| std::str::from_utf8(a.value).ok())
    }

    /// Whether USE-CANDIDATE is present (RFC 8445 §16.3).
    pub fn use_candidate(&self) -> bool {
        self.get(attr::USE_CANDIDATE).is_some()
    }

    /// PRIORITY value (RFC 8445 §16.1). `None` when absent or malformed.
    pub fn priority(&self) -> Option<u32> {
        let a = self.get(attr::PRIORITY)?;
        let v: [u8; 4] = a.value.try_into().ok()?;
        Some(u32::from_be_bytes(v))
    }

    /// ICE role asserted by the sender and the 64-bit tiebreaker value.
    /// `None` when neither role attribute is present or the attribute is
    /// malformed (value must be exactly 8 bytes, RFC 8445 §16.4/§16.5).
    /// If both are present the controlled claim wins, since that is the
    /// case requiring conflict handling for a controlled agent.
    pub fn ice_role(&self) -> Option<(IceRole, u64)> {
        if let Some(a) = self.get(attr::ICE_CONTROLLED) {
            let v: [u8; 8] = a.value.try_into().ok()?;
            return Some((IceRole::Controlled, u64::from_be_bytes(v)));
        }
        let a = self.get(attr::ICE_CONTROLLING)?;
        let v: [u8; 8] = a.value.try_into().ok()?;
        Some((IceRole::Controlling, u64::from_be_bytes(v)))
    }

    /// Decoded XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        let a = self.get(attr::XOR_MAPPED_ADDRESS)?;
        let v = a.value;
        if v.len() < 4 {
            return None;
        }
        let xport = u16::from_be_bytes([v[2], v[3]]);
        let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
        match v[1] {
            0x01 => {
                let raw: [u8; 4] = v.get(4..8)?.try_into().ok()?;
                let ip = u32::from_be_bytes(raw) ^ MAGIC_COOKIE;
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            0x02 => {
                let raw: [u8; 16] = v.get(4..20)?.try_into().ok()?;
                let mut ip = [0u8; 16];
                ip[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                ip[4..].copy_from_slice(&self.transaction_id);
                for (o, k) in raw.iter().zip(ip.iter_mut()) {
                    *k ^= o;
                }
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
            }
            _ => None,
        }
    }

    /// Decoded ERROR-CODE (RFC 5389 §15.6): `(code, reason phrase)`.
    pub fn error_code(&self) -> Option<(u16, &'a str)> {
        let v = self.get(attr::ERROR_CODE)?.value;
        if v.len() < 4 {
            return None;
        }
        let class = u16::from(v[2] & 0x07);
        let code = class * 100 + u16::from(v[3]);
        let reason = std::str::from_utf8(&v[4..]).ok()?;
        Some((code, reason))
    }

    /// Types carried by a UNKNOWN-ATTRIBUTES attribute (RFC 5389 §15.9).
    /// Stops early if the value holds a non-even byte count.
    pub fn unknown_attributes(&self) -> impl Iterator<Item = u16> + '_ {
        self.get(attr::UNKNOWN_ATTRIBUTES)
            .into_iter()
            .flat_map(|a| a.value.as_chunks::<2>().0.iter())
            .map(|c| u16::from_be_bytes(*c))
    }

    /// Verify MESSAGE-INTEGRITY against `key` (RFC 5389 §15.4).
    ///
    /// The HMAC covers the message up to but excluding the
    /// MESSAGE-INTEGRITY attribute, with the header length field adjusted
    /// to point to the end of that attribute. Returns `false` when the
    /// attribute is absent or malformed, or the HMAC does not match.
    pub fn verify_message_integrity(&self, key: &[u8]) -> bool {
        let Some(a) = self.get(attr::MESSAGE_INTEGRITY) else {
            return false;
        };
        if a.value.len() != 20 {
            return false;
        }
        let Ok(mut mac) = HmacSha1::new_from_slice(key) else {
            return false; // unreachable for HMAC-SHA1 (any key size works)
        };
        // Adjusted length: everything up to and including the MI
        // attribute (24 wire bytes), counted from after the header.
        // `a.offset + 4 <= u16::MAX` is guaranteed: the attribute fits
        // inside a message of at most 20 + u16::MAX bytes.
        let adjusted = (a.offset + 24 - HEADER_LEN) as u16;
        mac.update(&self.raw[..2]);
        mac.update(&adjusted.to_be_bytes());
        mac.update(&self.raw[4..a.offset]);
        mac.verify_slice(a.value).is_ok()
    }

    /// Verify FINGERPRINT (RFC 5389 §15.5).
    ///
    /// Returns `true` when the attribute is absent (it is optional) or
    /// when it is the last attribute and the CRC matches. Returns `false`
    /// on a CRC mismatch, a malformed value, or a fingerprint that is not
    /// the final attribute.
    pub fn fingerprint_valid(&self) -> bool {
        let Some(a) = self.get(attr::FINGERPRINT) else {
            return true;
        };
        let Ok(want) = <[u8; 4]>::try_from(a.value) else {
            return false;
        };
        if a.offset + 8 != self.raw.len() {
            return false;
        }
        let got = CRC32.checksum(&self.raw[..a.offset]) ^ FINGERPRINT_XOR;
        got == u32::from_be_bytes(want)
    }
}

/// Builds a STUN message into a caller-provided buffer.
///
/// Write order: [`MessageBuilder::new`], plain attributes via
/// [`MessageBuilder::attr`] or the typed helpers, then
/// [`MessageBuilder::message_integrity`], then
/// [`MessageBuilder::fingerprint`], then [`MessageBuilder::finish`].
/// MESSAGE-INTEGRITY and FINGERPRINT must come last (RFC 5389 §15.4/§15.5)
/// and the builder enforces that.
#[derive(Debug)]
pub struct MessageBuilder<'a> {
    buf: &'a mut [u8],
    pos: usize,
    tid: [u8; 12],
    sealed: bool,
    fingerprint_written: bool,
}

impl<'a> MessageBuilder<'a> {
    /// Start a message: writes the 20-byte header with a placeholder
    /// length field that [`MessageBuilder::finish`] patches.
    pub fn new(
        buf: &'a mut [u8],
        msg_type: u16,
        transaction_id: &[u8; 12],
    ) -> Result<Self, StunError> {
        if buf.len() < HEADER_LEN {
            return Err(StunError::BufferTooSmall);
        }
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[2..4].copy_from_slice(&[0, 0]);
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(transaction_id);
        Ok(Self {
            buf,
            pos: HEADER_LEN,
            tid: *transaction_id,
            sealed: false,
            fingerprint_written: false,
        })
    }

    /// Append a raw attribute. `value` is padded to a 4-byte boundary
    /// with zero bytes.
    pub fn attr(&mut self, attr_type: u16, value: &[u8]) -> Result<&mut Self, StunError> {
        if self.sealed {
            return Err(StunError::AttributeOrder);
        }
        if value.len() > u16::MAX as usize {
            return Err(StunError::AttributeTooLarge);
        }
        let need = 4 + pad4(value.len());
        if self.pos + need > self.buf.len() {
            return Err(StunError::BufferTooSmall);
        }
        self.buf[self.pos..self.pos + 2].copy_from_slice(&attr_type.to_be_bytes());
        self.buf[self.pos + 2..self.pos + 4]
            .copy_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf[self.pos + 4..self.pos + 4 + value.len()].copy_from_slice(value);
        for b in &mut self.buf[self.pos + 4 + value.len()..self.pos + need] {
            *b = 0;
        }
        self.pos += need;
        Ok(self)
    }

    /// USERNAME attribute.
    pub fn username(&mut self, value: &str) -> Result<&mut Self, StunError> {
        self.attr(attr::USERNAME, value.as_bytes())
    }

    /// SOFTWARE attribute.
    pub fn software(&mut self, value: &str) -> Result<&mut Self, StunError> {
        self.attr(attr::SOFTWARE, value.as_bytes())
    }

    /// PRIORITY attribute (RFC 8445 §16.1).
    pub fn priority(&mut self, value: u32) -> Result<&mut Self, StunError> {
        self.attr(attr::PRIORITY, &value.to_be_bytes())
    }

    /// ICE-CONTROLLING attribute with the given 64-bit tiebreaker
    /// (RFC 8445 §16.4).
    pub fn ice_controlling(&mut self, tiebreaker: u64) -> Result<&mut Self, StunError> {
        self.attr(attr::ICE_CONTROLLING, &tiebreaker.to_be_bytes())
    }

    /// ICE-CONTROLLED attribute with the given 64-bit tiebreaker
    /// (RFC 8445 §16.5).
    pub fn ice_controlled(&mut self, tiebreaker: u64) -> Result<&mut Self, StunError> {
        self.attr(attr::ICE_CONTROLLED, &tiebreaker.to_be_bytes())
    }

    /// Empty USE-CANDIDATE attribute (RFC 8445 §16.3).
    pub fn use_candidate(&mut self) -> Result<&mut Self, StunError> {
        self.attr(attr::USE_CANDIDATE, &[])
    }

    /// XOR-MAPPED-ADDRESS attribute for the given socket address
    /// (RFC 5389 §15.2). Handles both IPv4 and IPv6.
    pub fn xor_mapped_address(&mut self, addr: SocketAddr) -> Result<&mut Self, StunError> {
        let mut value = [0u8; 20];
        let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        value[2..4].copy_from_slice(&xport.to_be_bytes());
        let len = match addr.ip() {
            IpAddr::V4(ip) => {
                value[1] = 0x01;
                let xip = u32::from(ip) ^ MAGIC_COOKIE;
                value[4..8].copy_from_slice(&xip.to_be_bytes());
                8
            }
            IpAddr::V6(ip) => {
                value[1] = 0x02;
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                key[4..].copy_from_slice(&self.tid);
                for (o, (i, k)) in value[4..20].iter_mut().zip(ip.octets().iter().zip(key.iter())) {
                    *o = i ^ k;
                }
                20
            }
        };
        self.attr(attr::XOR_MAPPED_ADDRESS, &value[..len])
    }

    /// ERROR-CODE attribute (RFC 5389 §15.6). `code` is the full error
    /// code (e.g. 401); `reason` is the UTF-8 reason phrase.
    pub fn error_code(&mut self, code: u16, reason: &str) -> Result<&mut Self, StunError> {
        let mut value = [0u8; 4 + 763];
        let reason_len = reason.len().min(763);
        value[0..4].copy_from_slice(&[
            0,
            0,
            u8::try_from(code / 100).unwrap_or(6) & 0x07,
            u8::try_from(code % 100).unwrap_or(99),
        ]);
        value[4..4 + reason_len].copy_from_slice(&reason.as_bytes()[..reason_len]);
        self.attr(attr::ERROR_CODE, &value[..4 + reason_len])
    }

    /// UNKNOWN-ATTRIBUTES attribute listing comprehension-required
    /// attribute types the server did not understand (RFC 5389 §15.9).
    pub fn unknown_attributes(&mut self, types: &[u16]) -> Result<&mut Self, StunError> {
        let mut value = [0u8; 2 * MAX_UNKNOWN_ATTRS];
        let n = types.len().min(MAX_UNKNOWN_ATTRS);
        for (i, ty) in types[..n].iter().enumerate() {
            value[2 * i..2 * i + 2].copy_from_slice(&ty.to_be_bytes());
        }
        self.attr(attr::UNKNOWN_ATTRIBUTES, &value[..2 * n])
    }

    /// Append MESSAGE-INTEGRITY (RFC 5389 §15.4).
    ///
    /// Must be called after all other attributes except FINGERPRINT. The
    /// header length field is patched to include this attribute before
    /// the HMAC is computed, exactly as receivers verify it.
    pub fn message_integrity(&mut self, key: &[u8]) -> Result<&mut Self, StunError> {
        if self.sealed {
            return Err(StunError::AttributeOrder);
        }
        if self.pos + 24 > self.buf.len() {
            return Err(StunError::BufferTooSmall);
        }
        let off = self.pos;
        self.buf[off..off + 2].copy_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
        self.buf[off + 2..off + 4].copy_from_slice(&20u16.to_be_bytes());
        // Length field must point to the end of this attribute while the
        // HMAC covers only the bytes preceding it.
        let adjusted = (off + 24 - HEADER_LEN) as u16;
        self.buf[2..4].copy_from_slice(&adjusted.to_be_bytes());
        let mut mac = HmacSha1::new_from_slice(key)
            .expect("HMAC-SHA1 accepts keys of any length");
        mac.update(&self.buf[..2]);
        mac.update(&adjusted.to_be_bytes());
        mac.update(&self.buf[4..off]);
        let digest = mac.finalize().into_bytes();
        self.buf[off + 4..off + 24].copy_from_slice(&digest);
        self.pos += 24;
        self.sealed = true;
        Ok(self)
    }

    /// Append FINGERPRINT (RFC 5389 §15.5). Must be the last attribute:
    /// the header length is patched to include it before the CRC is
    /// computed.
    pub fn fingerprint(&mut self) -> Result<&mut Self, StunError> {
        if self.fingerprint_written {
            return Err(StunError::AttributeOrder);
        }
        if self.pos + 8 > self.buf.len() {
            return Err(StunError::BufferTooSmall);
        }
        let off = self.pos;
        self.buf[off..off + 2].copy_from_slice(&attr::FINGERPRINT.to_be_bytes());
        self.buf[off + 2..off + 4].copy_from_slice(&4u16.to_be_bytes());
        let total = (off + 8 - HEADER_LEN) as u16;
        self.buf[2..4].copy_from_slice(&total.to_be_bytes());
        let crc = CRC32.checksum(&self.buf[..off]) ^ FINGERPRINT_XOR;
        self.buf[off + 4..off + 8].copy_from_slice(&crc.to_be_bytes());
        self.pos += 8;
        self.sealed = true;
        self.fingerprint_written = true;
        Ok(self)
    }

    /// Patch the message length field and return the total wire length
    /// in bytes.
    pub fn finish(&mut self) -> Result<usize, StunError> {
        let len = self.pos - HEADER_LEN;
        if len > u16::MAX as usize {
            return Err(StunError::MessageTooLarge);
        }
        self.buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        Ok(self.pos)
    }
}

/// Events emitted by [`IceLiteAgent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceEvent {
    /// The controlling peer nominated this remote address: a valid
    /// Binding request with USE-CANDIDATE was accepted for it
    /// (RFC 8445 §7.3.2). Emitted once per selected address —
    /// retransmitted nominations do not re-emit.
    Nominated(SocketAddr),
}

/// What [`IceLiteAgent::handle_datagram`] produced for one datagram.
#[derive(Debug, Default, Clone, Copy)]
pub struct IceOutput {
    /// Length of a response datagram written into the caller's scratch
    /// buffer, to be sent back to the datagram's source address.
    pub response: Option<usize>,
    /// An event raised while processing the datagram.
    pub event: Option<IceEvent>,
}

/// Counters kept by [`IceLiteAgent`] for instrumentation. All `u64`,
/// incremented on the packet path at negligible cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// Datagrams that were not STUN at all.
    pub non_stun: u64,
    /// STUN datagrams dropped as malformed or with a bad fingerprint.
    pub malformed: u64,
    /// Binding requests rejected with an error response.
    pub rejected: u64,
    /// Valid connectivity checks accepted.
    pub checks: u64,
    /// Response datagrams produced.
    pub responses: u64,
    /// Accepted nominations.
    pub nominations: u64,
}

#[derive(Debug, Clone, Copy)]
struct Pair {
    remote: SocketAddr,
    last_seen: Instant,
}

/// An ICE-lite agent for a single peer connection (RFC 8445 §2.5).
///
/// The agent holds no candidates beyond its listening socket, never
/// initiates connectivity checks, and is always in the controlled role
/// (RFC 8445 §6.1.1). It answers authenticated Binding requests, tracks
/// the remote addresses that produced them in a bounded table, and
/// reports nominations as [`IceEvent::Nominated`].
///
/// Credentials may be provided before the remote ufrag is known —
/// connectivity checks often arrive before the answer does (RFC 8445
/// §7.3). Pass `None` for `remote_ufrag` and call
/// [`IceLiteAgent::set_remote_ufrag`] when the answer arrives; until then
/// any non-empty remote half of the USERNAME is accepted.
pub struct IceLiteAgent {
    local_ufrag: String,
    local_pwd: String,
    remote_ufrag: Option<String>,
    /// The currently nominated remote address, if any.
    selected: Option<SocketAddr>,
    /// Validated remote addresses. Bounded by `MAX_PAIRS`; when full the
    /// least-recently-seen entry is evicted. Eviction can never lose a
    /// nomination — that state lives in `selected`.
    pairs: [Option<Pair>; MAX_PAIRS],
    /// Packet counters.
    pub stats: Stats,
}

impl IceLiteAgent {
    /// Create an agent with the local ICE credentials and, if already
    /// known from signaling, the remote ufrag.
    pub fn new(local_ufrag: &str, local_pwd: &str, remote_ufrag: Option<&str>) -> Self {
        Self {
            local_ufrag: local_ufrag.to_owned(),
            local_pwd: local_pwd.to_owned(),
            remote_ufrag: remote_ufrag.map(str::to_owned),
            selected: None,
            pairs: [None; MAX_PAIRS],
            stats: Stats::default(),
        }
    }

    /// The local ICE username fragment.
    pub fn local_ufrag(&self) -> &str {
        &self.local_ufrag
    }

    /// The remote ICE username fragment, if set.
    pub fn remote_ufrag(&self) -> Option<&str> {
        self.remote_ufrag.as_deref()
    }

    /// The remote address of the nominated pair, if one has been
    /// nominated.
    pub fn selected_pair(&self) -> Option<SocketAddr> {
        self.selected
    }

    /// Number of validated remote addresses currently tracked.
    pub fn pair_count(&self) -> usize {
        self.pairs.iter().flatten().count()
    }

    /// Record or change the remote ufrag.
    ///
    /// A change acts as an ICE restart (RFC 8445 §9): all pair and
    /// nomination state is flushed while the agent retains its
    /// controlled role.
    pub fn set_remote_ufrag(&mut self, ufrag: &str) {
        if self.remote_ufrag.as_deref() == Some(ufrag) {
            return;
        }
        self.remote_ufrag = Some(ufrag.to_owned());
        self.pairs = [None; MAX_PAIRS];
        self.selected = None;
    }

    /// Feed one received datagram into the agent.
    ///
    /// `out` is a scratch buffer for the response datagram (use
    /// [`MAX_RESPONSE_LEN`] bytes); it must not alias `datagram`. The
    /// returned [`IceOutput`] carries the response length and any event.
    /// Non-STUN input, malformed messages, and non-Binding traffic are
    /// ignored without producing output and without panicking.
    pub fn handle_datagram(
        &mut self,
        datagram: &[u8],
        remote: SocketAddr,
        now: Instant,
        out: &mut [u8],
    ) -> IceOutput {
        let mut output = IceOutput::default();
        if !is_stun_datagram(datagram) {
            self.stats.non_stun += 1;
            return output;
        }
        let msg = match Message::parse(datagram) {
            Ok(m) => m,
            Err(e) => {
                trace!(error = %e, "dropping malformed STUN datagram");
                self.stats.malformed += 1;
                return output;
            }
        };
        if !msg.fingerprint_valid() {
            self.stats.malformed += 1;
            return output;
        }
        match (msg.method(), msg.class()) {
            (METHOD_BINDING, Class::Request) => {
                self.on_binding_request(&msg, remote, now, out, &mut output);
            }
            (METHOD_BINDING, Class::Indication) => self.on_binding_indication(remote, now),
            // Success/error responses and requests for other methods:
            // we never issue STUN requests ourselves and implement only
            // Binding, so there is nothing to answer.
            _ => {}
        }
        if output.response.is_some() {
            self.stats.responses += 1;
        }
        output
    }

    /// When [`IceLiteAgent::handle_timeout`] should next run to purge
    /// stale pairs, or `None` when there is nothing to expire. The
    /// selected pair never expires — media-path liveness is for the
    /// layers above (DTLS/consent) to decide.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.pairs
            .iter()
            .flatten()
            .filter(|p| Some(p.remote) != self.selected)
            .map(|p| p.last_seen + PAIR_TTL)
            .min()
    }

    /// Advance timers to `now`: purges validated pairs that have been
    /// silent for [`PAIR_TTL`]. The selected pair is kept.
    pub fn handle_timeout(&mut self, now: Instant) {
        for p in self.pairs.iter_mut() {
            let stale = matches!(p, Some(pair)
                if Some(pair.remote) != self.selected
                    && now.saturating_duration_since(pair.last_seen) > PAIR_TTL);
            if stale {
                *p = None;
            }
        }
    }

    /// RFC 5389 §10.1.2 / §7.3.1 plus RFC 8445 §7.3 handling for one
    /// parsed Binding request.
    fn on_binding_request(
        &mut self,
        msg: &Message<'_>,
        remote: SocketAddr,
        now: Instant,
        out: &mut [u8],
        output: &mut IceOutput,
    ) {
        let tid = msg.transaction_id();

        // Short-term credential checks, in RFC 5389 §10.1.2 order.
        // Authentication failure responses MUST NOT carry
        // MESSAGE-INTEGRITY, so they are built unsigned.
        let username = msg.username();
        let has_integrity = msg.get(attr::MESSAGE_INTEGRITY).is_some();
        let Some(username) = username.filter(|_| has_integrity) else {
            self.reject(out, &tid, 400, "Bad Request", None, false, output);
            return;
        };
        if !self.username_valid(username) {
            self.reject(out, &tid, 401, "Unauthorized", None, false, output);
            return;
        }
        if !msg.verify_message_integrity(self.local_pwd.as_bytes()) {
            self.reject(out, &tid, 401, "Unauthorized", None, false, output);
            return;
        }

        // Authenticated from here on; remaining error responses are
        // signed (RFC 5389 §7.3.1.1, §10.1.2).
        let mut unknown = [0u16; MAX_UNKNOWN_ATTRS];
        let mut n_unknown = 0;
        for a in msg.attributes() {
            if a.is_comprehension_required()
                && !KNOWN_ATTRS.contains(&a.attr_type)
                && n_unknown < unknown.len()
            {
                unknown[n_unknown] = a.attr_type;
                n_unknown += 1;
            }
        }
        if n_unknown > 0 {
            self.reject(
                out,
                &tid,
                420,
                "Unknown Attribute",
                Some(&unknown[..n_unknown]),
                true,
                output,
            );
            return;
        }

        // Role handling (RFC 8445 §7.3.1.1). As a lite agent we are
        // always controlled and have no check machinery, so we can never
        // assume the controlling role ourselves: any role conflict is
        // answered 487, which prompts the peer to take over controlling.
        match msg.ice_role() {
            Some((IceRole::Controlled, _)) => {
                self.reject(out, &tid, 487, "Role Conflict", None, true, output);
                return;
            }
            None => {
                self.reject(out, &tid, 400, "Bad Request", None, true, output);
                return;
            }
            Some((IceRole::Controlling, _)) => {}
        }

        // Valid connectivity check: the pair is valid per RFC 8445
        // §7.3.2. Answer it before touching nomination state so that
        // retransmitted checks always see a response.
        self.touch(remote, now);
        self.stats.checks += 1;
        output.response = self.build_success(out, &tid, remote);

        if msg.use_candidate() && self.selected != Some(remote) {
            self.selected = Some(remote);
            self.stats.nominations += 1;
            output.event = Some(IceEvent::Nominated(remote));
        }
    }

    /// Keepalive handling (RFC 8445 §11). Binding indications carry no
    /// credentials, so they may only refresh an already-validated pair —
    /// never create state — and are never answered.
    fn on_binding_indication(&mut self, remote: SocketAddr, now: Instant) {
        let known = self
            .pairs
            .iter_mut()
            .flatten()
            .any(|p| p.remote == remote);
        if known || self.selected == Some(remote) {
            self.touch(remote, now);
        }
    }

    /// Insert or refresh a validated remote address in the bounded pair
    /// table, evicting the least-recently-seen entry when full.
    fn touch(&mut self, remote: SocketAddr, now: Instant) {
        for p in self.pairs.iter_mut().flatten() {
            if p.remote == remote {
                p.last_seen = now;
                return;
            }
        }
        if let Some(slot) = self.pairs.iter_mut().find(|p| p.is_none()) {
            *slot = Some(Pair {
                remote,
                last_seen: now,
            });
            return;
        }
        // Table full: evict the oldest entry. Losing an entry only
        // forfeits freshness bookkeeping — `selected` still remembers a
        // nomination — so LRU is a sufficient policy here.
        let mut oldest = usize::MAX;
        let mut oldest_seen = now;
        for (i, p) in self.pairs.iter().enumerate() {
            if let Some(pair) = p
                && pair.last_seen <= oldest_seen
            {
                oldest_seen = pair.last_seen;
                oldest = i;
            }
        }
        if oldest < self.pairs.len() {
            self.pairs[oldest] = Some(Pair {
                remote,
                last_seen: now,
            });
        }
    }

    /// RFC 8445 §7.3: the username is valid when its first
    /// colon-separated half equals our local ufrag; when the remote
    /// ufrag is known, the second half must equal it as well.
    fn username_valid(&self, username: &str) -> bool {
        let Some(rest) = username.strip_prefix(self.local_ufrag.as_str()) else {
            return false;
        };
        let Some(remote) = rest.strip_prefix(':') else {
            return false;
        };
        match &self.remote_ufrag {
            Some(r) => remote == r,
            None => !remote.is_empty(),
        }
    }

    /// Build an error response for a rejected request and record it.
    #[allow(clippy::too_many_arguments)]
    fn reject(
        &mut self,
        out: &mut [u8],
        tid: &[u8; 12],
        code: u16,
        reason: &'static str,
        unknown: Option<&[u16]>,
        sign: bool,
        output: &mut IceOutput,
    ) {
        output.response = self.build_error(out, tid, code, reason, unknown, sign);
        self.stats.rejected += 1;
    }

    fn build_success(&self, out: &mut [u8], tid: &[u8; 12], remote: SocketAddr) -> Option<usize> {
        let r = (|| -> Result<usize, StunError> {
            let mut b = MessageBuilder::new(out, BINDING_SUCCESS, tid)?;
            b.xor_mapped_address(remote)?;
            b.software(SOFTWARE_NAME)?;
            b.message_integrity(self.local_pwd.as_bytes())?;
            b.fingerprint()?;
            b.finish()
        })();
        match r {
            Ok(n) => Some(n),
            Err(e) => {
                trace!(error = %e, "could not build binding success response");
                None
            }
        }
    }

    fn build_error(
        &self,
        out: &mut [u8],
        tid: &[u8; 12],
        code: u16,
        reason: &str,
        unknown: Option<&[u16]>,
        sign: bool,
    ) -> Option<usize> {
        let r = (|| -> Result<usize, StunError> {
            let mut b = MessageBuilder::new(out, BINDING_ERROR, tid)?;
            b.error_code(code, reason)?;
            if let Some(types) = unknown {
                b.unknown_attributes(types)?;
            }
            b.software(SOFTWARE_NAME)?;
            if sign {
                b.message_integrity(self.local_pwd.as_bytes())?;
            }
            b.fingerprint()?;
            b.finish()
        })();
        match r {
            Ok(n) => Some(n),
            Err(e) => {
                trace!(error = %e, "could not build binding error response");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 §2.1 sample request.
    const SAMPLE_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e,
        0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20,
        0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
        0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5,
        0x7a, 0x3b, 0xcf,
    ];

    /// RFC 5769 §2.2 sample IPv4 response.
    const SAMPLE_IPV4_RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1,
        0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00,
        0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    /// RFC 5769 §2.3 sample IPv6 response.
    const SAMPLE_IPV6_RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76,
        0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01,
        0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9,
        0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41, 0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb,
        0x0b, 0x4c,
    ];

    /// RFC 5769 §2.4 long-term-credential sample request (no FINGERPRINT).
    const SAMPLE_LONG_TERM_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72,
        0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88,
        0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9, 0x00, 0x00, 0x00,
        0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
        0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73,
        0x41, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72,
        0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02,
        0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
    ];

    const PWD: &str = "VOkJxbRl1RmTxUk/WvJxBt";

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), port)
    }

    #[test]
    fn rfc5769_sample_request() {
        let m = Message::parse(SAMPLE_REQUEST).unwrap();
        assert_eq!(m.message_type(), BINDING_REQUEST);
        assert_eq!(m.class(), Class::Request);
        assert_eq!(m.method(), METHOD_BINDING);
        assert_eq!(
            m.transaction_id(),
            [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae]
        );
        assert_eq!(m.software(), Some("STUN test client"));
        assert_eq!(m.priority(), Some(0x6e00_01ff));
        assert_eq!(
            m.ice_role(),
            Some((IceRole::Controlled, 0x932f_f9b1_5126_3b36))
        );
        assert_eq!(m.username(), Some("evtj:h6vY"));
        assert!(m.verify_message_integrity(PWD.as_bytes()));
        assert!(m.fingerprint_valid());
        assert_eq!(m.raw().len(), 20 + 0x58);
    }

    #[test]
    fn rfc5769_ipv4_response() {
        let m = Message::parse(SAMPLE_IPV4_RESPONSE).unwrap();
        assert_eq!(m.class(), Class::Success);
        assert_eq!(m.method(), METHOD_BINDING);
        assert_eq!(m.software(), Some("test vector"));
        assert_eq!(
            m.xor_mapped_address(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                32853
            ))
        );
        assert!(m.verify_message_integrity(PWD.as_bytes()));
        assert!(m.fingerprint_valid());
    }

    #[test]
    fn rfc5769_ipv6_response() {
        let m = Message::parse(SAMPLE_IPV6_RESPONSE).unwrap();
        assert_eq!(m.class(), Class::Success);
        assert_eq!(
            m.xor_mapped_address(),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x1234, 0x5678, 0x0011, 0x2233, 0x4455, 0x6677
                )),
                32853
            ))
        );
        assert!(m.verify_message_integrity(PWD.as_bytes()));
        assert!(m.fingerprint_valid());
    }

    #[test]
    fn rfc5769_long_term_request_parses() {
        // Not an ICE message (long-term credentials) but must still parse.
        let m = Message::parse(SAMPLE_LONG_TERM_REQUEST).unwrap();
        assert_eq!(m.class(), Class::Request);
        assert!(m.username().is_some());
        assert_eq!(
            m.get(attr::NONCE).map(|a| a.value),
            Some(b"f//499k954d6OL34oL9FSTvy64sA".as_slice())
        );
        assert_eq!(
            m.get(attr::REALM).map(|a| a.value),
            Some(b"example.org".as_slice())
        );
        // No FINGERPRINT attribute at all.
        assert!(m.get(attr::FINGERPRINT).is_none());
        assert!(m.fingerprint_valid());
    }

    #[test]
    fn integrity_and_fingerprint_detect_tampering() {
        // Wrong key fails integrity.
        let m = Message::parse(SAMPLE_REQUEST).unwrap();
        assert!(!m.verify_message_integrity(b"wrong"));

        // Flip a bit in the middle: fingerprint must notice.
        let mut bad = SAMPLE_REQUEST.to_vec();
        bad[40] ^= 0x01;
        let m = Message::parse(&bad).unwrap();
        assert!(!m.fingerprint_valid());
        // ...and integrity too (HMAC input changed).
        assert!(!m.verify_message_integrity(PWD.as_bytes()));
    }

    #[test]
    fn build_parse_roundtrip() {
        let tid = [7u8; 12];
        let mut buf = [0u8; 256];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username("local:remote").unwrap();
            b.priority(0x6e00_0001).unwrap();
            b.ice_controlling(0x1122_3344_5566_7788).unwrap();
            b.use_candidate().unwrap();
            b.message_integrity(PWD.as_bytes()).unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let m = Message::parse(&buf[..n]).unwrap();
        assert_eq!(m.class(), Class::Request);
        assert_eq!(m.method(), METHOD_BINDING);
        assert_eq!(m.transaction_id(), tid);
        assert_eq!(m.username(), Some("local:remote"));
        assert_eq!(m.priority(), Some(0x6e00_0001));
        assert_eq!(
            m.ice_role(),
            Some((IceRole::Controlling, 0x1122_3344_5566_7788))
        );
        assert!(m.use_candidate());
        assert!(m.verify_message_integrity(PWD.as_bytes()));
        assert!(m.fingerprint_valid());
        // Length field accounts for everything after the header.
        assert_eq!(
            u16::from_be_bytes([buf[2], buf[3]]) as usize,
            n - HEADER_LEN
        );
    }

    #[test]
    fn xor_mapped_address_roundtrip() {
        let tid = [0xabu8; 12];
        for addr in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 61234),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6,
                )),
                3478,
            ),
        ] {
            let mut buf = [0u8; 128];
            let n = {
                let mut b = MessageBuilder::new(&mut buf, BINDING_SUCCESS, &tid).unwrap();
                b.xor_mapped_address(addr).unwrap();
                b.finish().unwrap()
            };
            let m = Message::parse(&buf[..n]).unwrap();
            assert_eq!(m.xor_mapped_address(), Some(addr));
        }
    }

    #[test]
    fn error_code_and_unknown_attributes_roundtrip() {
        let tid = [1u8; 12];
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_ERROR, &tid).unwrap();
            b.error_code(420, "Unknown Attribute").unwrap();
            b.unknown_attributes(&[0x0002, 0x0003]).unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let m = Message::parse(&buf[..n]).unwrap();
        assert_eq!(m.class(), Class::Error);
        assert_eq!(m.error_code(), Some((420, "Unknown Attribute")));
        let unknown: Vec<u16> = m.unknown_attributes().collect();
        assert_eq!(unknown, [0x0002, 0x0003]);
        assert!(m.fingerprint_valid());
    }

    #[test]
    fn class_and_method_decode() {
        let tid = [0u8; 12];
        for (ty, class) in [
            (BINDING_REQUEST, Class::Request),
            (BINDING_INDICATION, Class::Indication),
            (BINDING_SUCCESS, Class::Success),
            (BINDING_ERROR, Class::Error),
        ] {
            let mut buf = [0u8; 64];
            let n = {
                let mut b = MessageBuilder::new(&mut buf, ty, &tid).unwrap();
                b.finish().unwrap()
            };
            let m = Message::parse(&buf[..n]).unwrap();
            assert_eq!(m.class(), class);
            assert_eq!(m.method(), METHOD_BINDING);
            assert_eq!(m.message_type(), ty);
        }
        // encode_type agrees with the raw constants.
        assert_eq!(encode_type(Class::Request, METHOD_BINDING), 0x0001);
        assert_eq!(encode_type(Class::Indication, METHOD_BINDING), 0x0011);
        assert_eq!(encode_type(Class::Success, METHOD_BINDING), 0x0101);
        assert_eq!(encode_type(Class::Error, METHOD_BINDING), 0x0111);
    }

    #[test]
    fn demux_classification() {
        assert!(is_stun_datagram(SAMPLE_REQUEST));
        // RTP: version 2 in the top bits.
        let rtp = [0x80u8; 32];
        assert!(!is_stun_datagram(&rtp));
        // DTLS record: content type 22.
        let mut dtls = [0u8; 32];
        dtls[0] = 22;
        assert!(!is_stun_datagram(&dtls));
        // Short buffers and wrong cookie rejected.
        assert!(!is_stun_datagram(&SAMPLE_REQUEST[..19]));
        let mut bad = SAMPLE_REQUEST.to_vec();
        bad[4] ^= 0xff;
        assert!(!is_stun_datagram(&bad));
        assert!(matches!(Message::parse(&bad), Err(StunError::BadCookie)));
    }

    #[test]
    fn malformed_inputs_never_panic() {
        // Every truncation of a valid message.
        for len in 0..SAMPLE_REQUEST.len() {
            let _ = Message::parse(&SAMPLE_REQUEST[..len]);
            let mut agent = IceLiteAgent::new("loc", "pw", Some("rem"));
            let mut out = [0u8; MAX_RESPONSE_LEN];
            let _ = agent.handle_datagram(&SAMPLE_REQUEST[..len], v4(5000), Instant::now(), &mut out);
        }
        // Every single-byte corruption.
        for i in 0..SAMPLE_REQUEST.len() {
            let mut bad = SAMPLE_REQUEST.to_vec();
            bad[i] ^= 0xff;
            let _ = Message::parse(&bad);
            let mut agent = IceLiteAgent::new("loc", "pw", Some("rem"));
            let mut out = [0u8; MAX_RESPONSE_LEN];
            let _ = agent.handle_datagram(&bad, v4(5000), Instant::now(), &mut out);
        }
        // Empty and tiny inputs.
        assert!(matches!(Message::parse(&[]), Err(StunError::TooShort)));
        assert!(matches!(Message::parse(&[0u8; 19]), Err(StunError::TooShort)));
        // Bad length field (not multiple of 4).
        let mut bad = SAMPLE_REQUEST.to_vec();
        bad[3] = 0x57;
        assert!(matches!(Message::parse(&bad), Err(StunError::BadLength)));
        // Declared length beyond the datagram.
        let mut bad = SAMPLE_REQUEST.to_vec();
        bad[2] = 0x02;
        bad[3] = 0x00;
        assert!(matches!(Message::parse(&bad), Err(StunError::Truncated)));
    }

    #[test]
    fn builder_rejects_misuse() {
        let tid = [0u8; 12];
        // Tiny buffer.
        let mut tiny = [0u8; 8];
        assert!(matches!(
            MessageBuilder::new(&mut tiny, BINDING_REQUEST, &tid),
            Err(StunError::BufferTooSmall)
        ));
        // No attributes may follow MESSAGE-INTEGRITY / FINGERPRINT.
        let mut buf = [0u8; 128];
        let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
        b.message_integrity(PWD.as_bytes()).unwrap();
        assert_eq!(
            b.username("x").unwrap_err(),
            StunError::AttributeOrder
        );
        assert_eq!(
            b.message_integrity(PWD.as_bytes()).unwrap_err(),
            StunError::AttributeOrder
        );
        b.fingerprint().unwrap();
        assert_eq!(b.fingerprint().unwrap_err(), StunError::AttributeOrder);
    }

    // ---- agent tests ----

    fn check_request(
        local: &str,
        remote: &str,
        pwd: &str,
        use_candidate: bool,
        tie: u64,
    ) -> Vec<u8> {
        let tid = [9u8; 12];
        let mut buf = [0u8; 256];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username(&format!("{local}:{remote}")).unwrap();
            b.priority(0x6e00_0001).unwrap();
            b.ice_controlling(tie).unwrap();
            if use_candidate {
                b.use_candidate().unwrap();
            }
            b.message_integrity(pwd.as_bytes()).unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        buf[..n].to_vec()
    }

    fn run(
        agent: &mut IceLiteAgent,
        req: &[u8],
        remote: SocketAddr,
        now: Instant,
    ) -> (Option<Vec<u8>>, Option<IceEvent>) {
        let mut out = [0u8; MAX_RESPONSE_LEN];
        let o = agent.handle_datagram(req, remote, now, &mut out);
        (o.response.map(|n| out[..n].to_vec()), o.event)
    }

    fn agent() -> IceLiteAgent {
        IceLiteAgent::new("srv", "localpassword", Some("cli"))
    }

    #[test]
    fn valid_check_gets_signed_success() {
        let mut a = agent();
        let remote = v4(5000);
        let req = check_request("srv", "cli", "localpassword", false, 0xdead_beef);
        let (resp, event) = run(&mut a, &req, remote, Instant::now());
        let resp = resp.expect("must answer a valid check");
        assert_eq!(event, None);

        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.class(), Class::Success);
        assert_eq!(m.method(), METHOD_BINDING);
        assert_eq!(m.transaction_id(), [9u8; 12]);
        assert_eq!(m.xor_mapped_address(), Some(remote));
        // Responses are authenticated with the local password (RFC 8445
        // §7.3) and must not echo USERNAME (RFC 5389 §10.1.2).
        assert!(m.verify_message_integrity(b"localpassword"));
        assert!(m.fingerprint_valid());
        assert!(m.get(attr::USERNAME).is_none());
        assert_eq!(m.software(), Some(SOFTWARE_NAME));
        assert_eq!(a.selected_pair(), None);
        assert_eq!(a.pair_count(), 1);
    }

    #[test]
    fn nomination_flow_end_to_end() {
        let mut a = agent();
        let remote = v4(5000);
        let now = Instant::now();

        // Plain check: answered, no nomination yet.
        let req = check_request("srv", "cli", "localpassword", false, 1);
        let (resp, event) = run(&mut a, &req, remote, now);
        assert!(resp.is_some());
        assert_eq!(event, None);
        assert_eq!(a.selected_pair(), None);

        // Nomination: answered and reported once.
        let nom = check_request("srv", "cli", "localpassword", true, 1);
        let (resp, event) = run(&mut a, &nom, remote, now);
        assert!(resp.is_some());
        assert_eq!(event, Some(IceEvent::Nominated(remote)));
        assert_eq!(a.selected_pair(), Some(remote));

        // Retransmitted nomination: still answered, no duplicate event.
        let (resp2, event2) = run(&mut a, &nom, remote, now);
        assert!(resp2.is_some());
        assert_eq!(event2, None);
        assert_eq!(a.stats.nominations, 1);

        // The peer re-nominates a different pair: reported again.
        let remote2 = v4(6000);
        let nom2 = check_request("srv", "cli", "localpassword", true, 2);
        let (resp3, event3) = run(&mut a, &nom2, remote2, now);
        assert!(resp3.is_some());
        assert_eq!(event3, Some(IceEvent::Nominated(remote2)));
        assert_eq!(a.selected_pair(), Some(remote2));
    }

    #[test]
    fn retransmitted_check_produces_identical_response() {
        let mut a = agent();
        let remote = v4(5000);
        let req = check_request("srv", "cli", "localpassword", false, 1);
        let now = Instant::now();
        let (r1, _) = run(&mut a, &req, remote, now);
        let (r2, _) = run(&mut a, &req, remote, now);
        assert_eq!(r1, r2);
    }

    #[test]
    fn wrong_username_rejected() {
        let mut a = agent();
        let req = check_request("srv", "someoneelse", "localpassword", false, 1);
        let (resp, event) = run(&mut a, &req, v4(5000), Instant::now());
        assert_eq!(event, None);
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.class(), Class::Error);
        assert_eq!(m.error_code().map(|e| e.0), Some(401));
        // Auth-failure responses carry no MESSAGE-INTEGRITY (RFC 5389
        // §10.1.2).
        assert!(m.get(attr::MESSAGE_INTEGRITY).is_none());
        // Also: entirely foreign local ufrag.
        let req = check_request("other", "cli", "localpassword", false, 1);
        let (resp, _) = run(&mut a, &req, v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(401));
    }

    #[test]
    fn bad_integrity_rejected() {
        let mut a = agent();
        // Well-formed request signed with the wrong password.
        let req = check_request("srv", "cli", "not-the-password", false, 1);
        let (resp, event) = run(&mut a, &req, v4(5000), Instant::now());
        assert_eq!(event, None);
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(401));
        assert!(m.get(attr::MESSAGE_INTEGRITY).is_none());
        assert_eq!(a.pair_count(), 0);
    }

    #[test]
    fn missing_credentials_get_400() {
        let mut a = agent();
        let tid = [4u8; 12];
        for with_username in [true, false] {
            let mut buf = [0u8; 128];
            let n = {
                let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
                if with_username {
                    b.username("srv:cli").unwrap();
                }
                // no MESSAGE-INTEGRITY either way
                b.fingerprint().unwrap();
                b.finish().unwrap()
            };
            let (resp, _) = run(&mut a, &buf[..n], v4(5000), Instant::now());
            let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
            assert_eq!(m.error_code().map(|e| e.0), Some(400));
        }
        // USERNAME missing but MI present is still a 400.
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.message_integrity(b"localpassword").unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, _) = run(&mut a, &buf[..n], v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(400));
    }

    #[test]
    fn role_conflict_gets_487() {
        let mut a = agent();
        let tid = [5u8; 12];
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username("srv:cli").unwrap();
            b.ice_controlled(0xfeed).unwrap(); // peer claims our role
            b.message_integrity(b"localpassword").unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, event) = run(&mut a, &buf[..n], v4(5000), Instant::now());
        assert_eq!(event, None);
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(487));
        // Post-auth error responses are signed.
        assert!(m.verify_message_integrity(b"localpassword"));
        // We remain controlled; nothing was recorded.
        assert_eq!(a.pair_count(), 0);
        assert_eq!(a.selected_pair(), None);
    }

    #[test]
    fn missing_role_gets_400() {
        let mut a = agent();
        let tid = [6u8; 12];
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username("srv:cli").unwrap();
            b.message_integrity(b"localpassword").unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, _) = run(&mut a, &buf[..n], v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(400));
        assert!(m.verify_message_integrity(b"localpassword"));
    }

    #[test]
    fn unknown_attributes_420_and_optional_skipped() {
        let mut a = agent();
        let tid = [8u8; 12];

        // Unknown comprehension-required (0x0002) -> 420 + list.
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username("srv:cli").unwrap();
            b.ice_controlling(1).unwrap();
            b.attr(0x0002, &[1, 2, 3, 4]).unwrap(); // RESPONSE-ADDRESS era relic
            b.message_integrity(b"localpassword").unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, event) = run(&mut a, &buf[..n], v4(5000), Instant::now());
        assert_eq!(event, None);
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(420));
        let unknown: Vec<u16> = m.unknown_attributes().collect();
        assert_eq!(unknown, [0x0002]);
        assert!(m.verify_message_integrity(b"localpassword"));

        // Unknown comprehension-optional (e.g. NETWORK-COST 0xc057) is
        // skipped, not an error.
        let mut buf = [0u8; 128];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_REQUEST, &tid).unwrap();
            b.username("srv:cli").unwrap();
            b.ice_controlling(1).unwrap();
            b.attr(0xc057, &[0, 0, 0, 5]).unwrap();
            b.use_candidate().unwrap();
            b.message_integrity(b"localpassword").unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, event) = run(&mut a, &buf[..n], v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.class(), Class::Success);
        assert_eq!(event, Some(IceEvent::Nominated(v4(5000))));
    }

    #[test]
    fn non_stun_and_non_binding_ignored() {
        let mut a = agent();
        let remote = v4(5000);
        let now = Instant::now();
        // RTP packet.
        let (resp, event) = run(&mut a, &[0x80u8; 40], remote, now);
        assert!(resp.is_none() && event.is_none());
        // Binding indication is never answered.
        let tid = [3u8; 12];
        let mut buf = [0u8; 64];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_INDICATION, &tid).unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let (resp, event) = run(&mut a, &buf[..n], remote, now);
        assert!(resp.is_none() && event.is_none());
        // A TURN Allocate request (method 0x003) is not ours to answer.
        let mut buf = [0u8; 64];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, 0x0003, &tid).unwrap();
            b.finish().unwrap()
        };
        let (resp, event) = run(&mut a, &buf[..n], remote, now);
        assert!(resp.is_none() && event.is_none());
        // A Binding success response (we sent no request) is ignored.
        let (resp, event) = run(&mut a, SAMPLE_IPV4_RESPONSE, remote, now);
        assert!(resp.is_none() && event.is_none());
        assert!(a.stats.non_stun >= 1);
    }

    #[test]
    fn keepalive_refreshes_pair_and_timeout_purges() {
        let mut a = agent();
        let remote = v4(5000);
        let t0 = Instant::now();

        // A validated check creates a pair with a deadline.
        let req = check_request("srv", "cli", "localpassword", false, 1);
        run(&mut a, &req, remote, t0);
        assert_eq!(a.poll_timeout(), Some(t0 + PAIR_TTL));

        // An unauthenticated keepalive refreshes the existing pair.
        let tid = [2u8; 12];
        let mut buf = [0u8; 64];
        let n = {
            let mut b = MessageBuilder::new(&mut buf, BINDING_INDICATION, &tid).unwrap();
            b.fingerprint().unwrap();
            b.finish().unwrap()
        };
        let t1 = t0 + Duration::from_secs(10);
        let (resp, _) = run(&mut a, &buf[..n], remote, t1);
        assert!(resp.is_none());
        assert_eq!(a.poll_timeout(), Some(t1 + PAIR_TTL));

        // A keepalive from an unknown address creates nothing.
        let (resp, _) = run(&mut a, &buf[..n], v4(9999), t1);
        assert!(resp.is_none());
        assert_eq!(a.pair_count(), 1);

        // Within TTL the entry survives; past it, it is purged.
        a.handle_timeout(t1 + PAIR_TTL);
        assert_eq!(a.pair_count(), 1);
        a.handle_timeout(t1 + PAIR_TTL + Duration::from_secs(1));
        assert_eq!(a.pair_count(), 0);
        assert_eq!(a.poll_timeout(), None);
    }

    #[test]
    fn selected_pair_is_not_expired() {
        let mut a = agent();
        let remote = v4(5000);
        let t0 = Instant::now();
        let nom = check_request("srv", "cli", "localpassword", true, 1);
        run(&mut a, &nom, remote, t0);
        assert_eq!(a.selected_pair(), Some(remote));
        // No expiry is scheduled for the selected pair.
        assert_eq!(a.poll_timeout(), None);
        a.handle_timeout(t0 + Duration::from_secs(3600));
        assert_eq!(a.selected_pair(), Some(remote));
    }

    #[test]
    fn ice_restart_flushes_state() {
        let mut a = agent();
        let remote = v4(5000);
        let nom = check_request("srv", "cli", "localpassword", true, 1);
        run(&mut a, &nom, remote, Instant::now());
        assert_eq!(a.selected_pair(), Some(remote));

        a.set_remote_ufrag("cli2");
        assert_eq!(a.selected_pair(), None);
        assert_eq!(a.pair_count(), 0);

        // Old ufrag now fails; the new one works.
        let (resp, event) = run(&mut a, &nom, remote, Instant::now());
        assert_eq!(event, None);
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(401));

        let nom2 = check_request("srv", "cli2", "localpassword", true, 1);
        let (_, event) = run(&mut a, &nom2, remote, Instant::now());
        assert_eq!(event, Some(IceEvent::Nominated(remote)));
    }

    #[test]
    fn checks_before_answer_use_local_ufrag_only() {
        // Remote ufrag not yet signaled: any remote half is accepted.
        let mut a = IceLiteAgent::new("srv", "localpassword", None);
        let req = check_request("srv", "whatever", "localpassword", false, 1);
        let (resp, _) = run(&mut a, &req, v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.class(), Class::Success);

        // Once the answer arrives the ufrag is enforced.
        a.set_remote_ufrag("cli");
        let (resp, _) = run(&mut a, &req, v4(5000), Instant::now());
        let resp = resp.unwrap();
        let m = Message::parse(&resp).unwrap();
        assert_eq!(m.error_code().map(|e| e.0), Some(401));
    }

    #[test]
    fn pair_table_is_bounded() {
        let mut a = agent();
        let req = check_request("srv", "cli", "localpassword", false, 1);
        let now = Instant::now();
        // More distinct remote addresses than the table can hold.
        for i in 0..(MAX_PAIRS + 40) {
            let addr = v4(10_000 + i as u16);
            let (resp, _) = run(&mut a, &req, addr, now);
            assert!(resp.is_some());
        }
        assert_eq!(a.pair_count(), MAX_PAIRS);
    }

    #[test]
    fn tiny_output_buffer_never_panics() {
        let mut a = agent();
        let req = check_request("srv", "cli", "localpassword", false, 1);
        for out_len in [0, 10, 20, 40, 60] {
            let mut out = vec![0u8; out_len];
            let o = a.handle_datagram(&req, v4(5000), Instant::now(), &mut out);
            assert!(o.response.is_none() || o.response.unwrap() <= out_len);
        }
    }
}
