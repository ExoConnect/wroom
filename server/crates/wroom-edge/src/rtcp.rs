//! RTCP packet handling for the edge: RFC 3550 sender/receiver reports and
//! the feedback messages the SFU forwards or generates — generic NACK
//! (RFC 4585), PLI/FIR (RFC 5104), and transport-wide congestion-control
//! feedback (draft-holmer-rmcat-transport-wide-cc-extensions).
//!
//! Wire format recap: every RTCP block opens with a 4-byte header
//! (`V=2 | P | RC-or-FMT`, packet type, length in 32-bit words minus one,
//! header included). On the wire, several blocks are concatenated into a
//! single compound datagram; [`packets`] walks them one at a time.
//!
//! Everything is zero-copy and allocation-free: parsed packets borrow the
//! datagram and builders render into caller-provided scratch buffers. No
//! function in this module panics on malformed input.

use thiserror::Error;
use tracing::trace;

/// Length of the RTCP common header, before the body.
pub const HEADER_LEN: usize = 4;

/// Length of the shared feedback header (sender SSRC + media SSRC) that
/// every RTPFB/PSFB packet carries between the common header and the FCI.
pub const FEEDBACK_HEADER_LEN: usize = 8;

/// RTCP packet types and the feedback sub-message FMT values.
pub mod pt {
    /// Sender Report.
    pub const SR: u8 = 200;
    /// Receiver Report.
    pub const RR: u8 = 201;
    /// Source Description.
    pub const SDES: u8 = 202;
    /// Goodbye.
    pub const BYE: u8 = 203;
    /// Application-defined.
    pub const APP: u8 = 204;
    /// Transport-layer feedback (RFC 4585).
    pub const RTPFB: u8 = 205;
    /// Payload-specific feedback (RFC 4585).
    pub const PSFB: u8 = 206;

    /// RTPFB FMT for generic NACK.
    pub const FMT_NACK: u8 = 1;
    /// RTPFB FMT for transport-wide congestion-control feedback.
    pub const FMT_TWCC: u8 = 15;
    /// PSFB FMT for Picture Loss Indication.
    pub const FMT_PLI: u8 = 1;
    /// PSFB FMT for Full Intra Request (RFC 5104).
    pub const FMT_FIR: u8 = 4;
    /// PSFB FMT for application-layer feedback (REMB lives here).
    pub const FMT_AFB: u8 = 15;
}

/// Errors returned when parsing or building an RTCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RtcpError {
    /// Fewer bytes than the 4-byte common header.
    #[error("datagram shorter than the 4-byte RTCP header")]
    TooShort,
    /// The version field was not 2.
    #[error("unsupported RTCP version {0}")]
    BadVersion(u8),
    /// The length field makes the block overrun the datagram.
    #[error("RTCP length field inconsistent with the datagram")]
    BadLength,
    /// Padding bit set but the padding count byte is missing or invalid.
    #[error("invalid RTCP padding")]
    BadPadding,
    /// The block body is too small for what its packet type requires.
    #[error("RTCP block too small for its packet type")]
    Truncated,
    /// The scratch buffer is too small for the packet being built. `needed`
    /// is the exact size required, so the caller can resize and retry.
    #[error("output buffer too small: need {needed} bytes, have {have}")]
    BufferTooSmall { needed: usize, have: usize },
    /// A count field cannot express `have` entries (maximum `max`).
    #[error("field count {have} exceeds the maximum {max}")]
    CountOverflow { have: usize, max: usize },
    /// A field value is outside the range the wire format can express.
    #[error("invalid field value: {0}")]
    Invalid(&'static str),
}

/// One reception report block (RFC 3550 §6.4.1); shared by SR and RR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportBlock {
    /// The SSRC of the source being reported on.
    pub ssrc: u32,
    /// Fraction of packets lost since the previous report (8-bit fixed
    /// point with the binary point at the field's left edge).
    pub fraction_lost: u8,
    /// Cumulative packets lost, sign-extended from its 24-bit wire form;
    /// may be negative when duplicates arrive.
    pub cumulative_lost: i32,
    /// Extended highest sequence number received (cycles << 16 | seq).
    pub highest_seq: u32,
    /// Interarrival jitter estimate in timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP time of the last SR received.
    pub lsr: u32,
    /// Delay since the last SR, in 1/65536 seconds.
    pub dlsr: u32,
}

const REPORT_BLOCK_LEN: usize = 24;

impl ReportBlock {
    /// Caller guarantees `b.len() >= REPORT_BLOCK_LEN`.
    fn parse(b: &[u8]) -> Self {
        let cumulative_lost =
            (u32::from_be_bytes([0, b[5], b[6], b[7]]) as i32) << 8 >> 8;
        Self {
            ssrc: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            fraction_lost: b[4],
            cumulative_lost,
            highest_seq: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            jitter: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            lsr: u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
            dlsr: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
        }
    }

    /// Caller guarantees `out.len() >= REPORT_BLOCK_LEN`.
    fn write(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        out[4] = self.fraction_lost;
        // Keep the low 24 bits of the signed value.
        out[5..8].copy_from_slice(&(self.cumulative_lost & 0xFF_FFFF).to_be_bytes()[1..]);
        out[8..12].copy_from_slice(&self.highest_seq.to_be_bytes());
        out[12..16].copy_from_slice(&self.jitter.to_be_bytes());
        out[16..20].copy_from_slice(&self.lsr.to_be_bytes());
        out[20..24].copy_from_slice(&self.dlsr.to_be_bytes());
    }
}

/// A generic NACK feedback control information entry: packet identifier
/// plus a bitmask of the following 16 packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackEntry {
    /// Sequence number of a lost packet.
    pub pid: u16,
    /// Bitmask of following losses: bit `i` set means `pid + i + 1` is lost.
    pub blp: u16,
}

impl NackEntry {
    /// Every lost sequence number this entry encodes: `pid`, then `pid+i`
    /// for each set BLP bit.
    pub fn lost(self) -> impl Iterator<Item = u16> {
        (0..=16u16).filter_map(move |i| {
            if i == 0 {
                Some(self.pid)
            } else if self.blp & (1 << (i - 1)) != 0 {
                Some(self.pid.wrapping_add(i))
            } else {
                None
            }
        })
    }
}

/// A Full Intra Request FCI entry (RFC 5104 §4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirEntry {
    /// The media source that should produce a keyframe.
    pub ssrc: u32,
    /// Command sequence number; the sender repeats the request with a new
    /// value only for a genuinely new request.
    pub seq: u8,
}

/// Receive status of one packet covered by a TWCC feedback message.
///
/// Carries the same meaning when parsed (a packet's arrival offset) and
/// when building (what to encode on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwccStatus {
    /// The packet was not received.
    NotReceived,
    /// The packet was received; value is the arrival-time delta relative
    /// to the reference time, in 250 µs units.
    Received(i32),
}

/// One SDES chunk: a source SSRC and the raw item list that follows it.
/// The edge only needs the SSRC to skip chunks reliably; `items` is exposed
/// unparsed (`type, len, value…` terminated by a null item).
#[derive(Debug, Clone, Copy)]
pub struct SdesChunk<'a> {
    /// The SSRC/CSRC this chunk describes.
    pub ssrc: u32,
    /// Raw SDES item bytes between the SSRC and the null terminator.
    pub items: &'a [u8],
}

/// The dissected common header + body of one RTCP block in a datagram.
#[derive(Debug, Clone, Copy)]
struct Block<'a> {
    /// The RC field — or the FMT sub-message number for feedback types.
    count: u8,
    packet_type: u8,
    /// Total bytes this block occupies, header and padding included.
    block_len: usize,
    /// Body between the header and any padding bytes.
    payload: &'a [u8],
    /// The entire block, header included.
    raw: &'a [u8],
}

impl<'a> Block<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self, RtcpError> {
        if buf.len() < HEADER_LEN {
            return Err(RtcpError::TooShort);
        }
        let version = buf[0] >> 6;
        if version != 2 {
            return Err(RtcpError::BadVersion(version));
        }
        let count = buf[0] & 0x1f;
        let packet_type = buf[1];
        let words = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let block_len = (words + 1) * 4;
        if block_len > buf.len() {
            return Err(RtcpError::BadLength);
        }
        let raw = &buf[..block_len];
        let mut payload = &raw[HEADER_LEN..];
        if buf[0] & 0x20 != 0 {
            // P set: the last byte of the block is the padding count.
            let n = payload.last().copied().unwrap_or(0) as usize;
            if n == 0 || n > payload.len() {
                return Err(RtcpError::BadPadding);
            }
            payload = &payload[..payload.len() - n];
        }
        Ok(Self {
            count,
            packet_type,
            block_len,
            payload,
            raw,
        })
    }

    /// The feedback-header body, when the block is a feedback type. Gives
    /// `FCI` = payload minus the shared sender/media SSRC header.
    fn feedback(&self) -> Result<(&'a [u8], &'a [u8]), RtcpError> {
        self.payload
            .get(..FEEDBACK_HEADER_LEN)
            .zip(self.payload.get(FEEDBACK_HEADER_LEN..))
            .ok_or(RtcpError::Truncated)
    }
}

/// A parsed RTCP block: a zero-copy view over one block of a datagram.
#[derive(Debug, Clone, Copy)]
pub struct RtcpPacket<'a> {
    block: Block<'a>,
    kind: RtcpKind<'a>,
}

/// Which kind of block an [`RtcpPacket`] carries. Variants are borrowed
/// views into the datagram; `Other` covers APP packets, unknown types, and
/// feedback sub-messages this module does not model.
#[derive(Debug, Clone, Copy)]
pub enum RtcpKind<'a> {
    /// Sender Report (PT 200).
    SenderReport(SenderReport<'a>),
    /// Receiver Report (PT 201).
    ReceiverReport(ReceiverReport<'a>),
    /// Source Description (PT 202); parsed far enough to walk chunks.
    Sdes(Sdes<'a>),
    /// Goodbye (PT 203).
    Bye(Bye<'a>),
    /// Generic NACK transport feedback (RTPFB FMT 1).
    Nack(Nack<'a>),
    /// Picture Loss Indication (PSFB FMT 1).
    Pli(Pli<'a>),
    /// Full Intra Request (PSFB FMT 4).
    Fir(Fir<'a>),
    /// Transport-wide congestion-control feedback (RTPFB FMT 15).
    Twcc(Twcc<'a>),
    /// REMB bandwidth estimate (PSFB FMT 15, "REMB" FCI).
    Remb(Remb<'a>),
    /// Any other block — APP, unknown packet types, unmodeled feedback
    /// sub-messages. Carried so compound walking never fails on them.
    Other(Other<'a>),
}

impl<'a> RtcpPacket<'a> {
    /// Parses the first block of `buf`. Trailing blocks of a compound
    /// datagram are ignored; use [`packets`] to walk them all.
    pub fn parse(buf: &'a [u8]) -> Result<Self, RtcpError> {
        Self::from_block(Block::parse(buf)?)
    }

    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        let kind = match (b.packet_type, b.count) {
            (pt::SR, _) => RtcpKind::SenderReport(SenderReport::from_block(b)?),
            (pt::RR, _) => RtcpKind::ReceiverReport(ReceiverReport::from_block(b)?),
            (pt::SDES, _) => RtcpKind::Sdes(Sdes { block: b }),
            (pt::BYE, _) => RtcpKind::Bye(Bye::from_block(b)?),
            (pt::RTPFB, pt::FMT_NACK) => RtcpKind::Nack(Nack::from_block(b)?),
            (pt::RTPFB, pt::FMT_TWCC) => RtcpKind::Twcc(Twcc::from_block(b)?),
            (pt::PSFB, pt::FMT_PLI) => RtcpKind::Pli(Pli::from_block(b)?),
            (pt::PSFB, pt::FMT_FIR) => RtcpKind::Fir(Fir::from_block(b)?),
            (pt::PSFB, pt::FMT_AFB) => {
                // FMT 15 multiplexes application-defined feedback; only
                // REMB is modeled. A "REMB" magic that doesn't fit its
                // layout is an error, not a different message.
                if Remb::is_remb(&b) {
                    RtcpKind::Remb(Remb::from_block(b)?)
                } else {
                    RtcpKind::Other(Other { block: b })
                }
            }
            _ => RtcpKind::Other(Other { block: b }),
        };
        Ok(Self { block: b, kind })
    }

    /// Which kind of block this is.
    pub fn kind(&self) -> RtcpKind<'a> {
        self.kind
    }

    /// The block's packet type field.
    pub fn packet_type(&self) -> u8 {
        self.block.packet_type
    }

    /// The RC field — reception report count for SR/RR, source count for
    /// SDES/BYE, FMT sub-message number for feedback packets.
    pub fn count(&self) -> u8 {
        self.block.count
    }

    /// Total bytes the block occupies in the datagram, header and padding
    /// included.
    pub fn block_len(&self) -> usize {
        self.block.block_len
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }
}

/// Iterates the individual blocks of a compound RTCP datagram.
///
/// Yields `Ok` per successfully parsed block. On malformed input it yields
/// the error once and then ends — a compound datagram cannot be resynced
/// mid-stream because each block's length locates the next.
///
/// RFC 3550 additionally requires the first block of a compound to be an
/// SR or RR with the padding bit clear; the walker is lenient on purpose —
/// the forwarding path only needs the blocks it understands.
pub fn packets(datagram: &[u8]) -> PacketIter<'_> {
    PacketIter {
        rest: datagram,
        done: false,
    }
}

/// See [`packets`].
#[derive(Debug, Clone)]
pub struct PacketIter<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Result<RtcpPacket<'a>, RtcpError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        let b = match Block::parse(self.rest) {
            Ok(b) => b,
            Err(e) => {
                self.done = true;
                trace!(error = %e, "malformed RTCP block, dropping rest of datagram");
                return Some(Err(e));
            }
        };
        self.rest = &self.rest[b.block_len..];
        match RtcpPacket::from_block(b) {
            Ok(p) => Some(Ok(p)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Length of the SR sender-info section (sender SSRC, NTP + RTP
/// timestamps, packet/octet counters) between the header and the report
/// blocks.
const SENDER_INFO_LEN: usize = 24;

/// Sender Report view (PT 200).
#[derive(Debug, Clone, Copy)]
pub struct SenderReport<'a> {
    block: Block<'a>,
}

impl<'a> SenderReport<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        let need = SENDER_INFO_LEN + REPORT_BLOCK_LEN * b.count as usize;
        if b.payload.len() < need {
            return Err(RtcpError::Truncated);
        }
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the sender generating this report.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// The sender's wallclock when the report was sent, as a 64-bit NTP
    /// timestamp (seconds in the high word, fraction in the low word).
    pub fn ntp_timestamp(&self) -> u64 {
        u64::from_be_bytes(self.block.payload[4..12].try_into().unwrap_or_default())
    }

    /// The middle 32 bits of [`Self::ntp_timestamp`], the value receivers
    /// echo in report-block LSR fields.
    pub fn ntp_middle(&self) -> u32 {
        (self.ntp_timestamp() >> 16) as u32
    }

    /// RTP timestamp corresponding to the NTP time, for clock mapping.
    pub fn rtp_timestamp(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[12..16].try_into().unwrap_or_default())
    }

    /// Cumulative packets sent by the source.
    pub fn packet_count(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[16..20].try_into().unwrap_or_default())
    }

    /// Cumulative payload octets sent by the source.
    pub fn octet_count(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[20..24].try_into().unwrap_or_default())
    }

    /// The reception report blocks.
    pub fn reports(&self) -> impl Iterator<Item = ReportBlock> + '_ {
        let n = REPORT_BLOCK_LEN * self.block.count as usize;
        self.block.payload[SENDER_INFO_LEN..SENDER_INFO_LEN + n]
            .chunks_exact(REPORT_BLOCK_LEN)
            .map(ReportBlock::parse)
    }

    /// Builds a Sender Report into `out`; returns the block length.
    ///
    /// `ntp` is the 64-bit NTP send time. At most 31 report blocks fit the
    /// 5-bit RC field; more returns [`RtcpError::CountOverflow`].
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        ntp: u64,
        rtp_timestamp: u32,
        packet_count: u32,
        octet_count: u32,
        reports: &[ReportBlock],
    ) -> Result<usize, RtcpError> {
        if reports.len() > 31 {
            return Err(RtcpError::CountOverflow {
                have: reports.len(),
                max: 31,
            });
        }
        let total = HEADER_LEN + SENDER_INFO_LEN + REPORT_BLOCK_LEN * reports.len();
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, reports.len() as u8, pt::SR, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        out[8..16].copy_from_slice(&ntp.to_be_bytes());
        out[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
        out[20..24].copy_from_slice(&packet_count.to_be_bytes());
        out[24..28].copy_from_slice(&octet_count.to_be_bytes());
        let mut w = 28;
        for r in reports {
            r.write(&mut out[w..w + REPORT_BLOCK_LEN]);
            w += REPORT_BLOCK_LEN;
        }
        Ok(total)
    }
}

/// Receiver Report view (PT 201).
#[derive(Debug, Clone, Copy)]
pub struct ReceiverReport<'a> {
    block: Block<'a>,
}

impl<'a> ReceiverReport<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        let need = 4 + REPORT_BLOCK_LEN * b.count as usize;
        if b.payload.len() < need {
            return Err(RtcpError::Truncated);
        }
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the receiver generating this report.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// The reception report blocks.
    pub fn reports(&self) -> impl Iterator<Item = ReportBlock> + '_ {
        let n = REPORT_BLOCK_LEN * self.block.count as usize;
        self.block.payload[4..4 + n]
            .chunks_exact(REPORT_BLOCK_LEN)
            .map(ReportBlock::parse)
    }

    /// Builds a Receiver Report into `out`; returns the block length.
    /// At most 31 report blocks fit the RC field.
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        reports: &[ReportBlock],
    ) -> Result<usize, RtcpError> {
        if reports.len() > 31 {
            return Err(RtcpError::CountOverflow {
                have: reports.len(),
                max: 31,
            });
        }
        let total = HEADER_LEN + 4 + REPORT_BLOCK_LEN * reports.len();
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, reports.len() as u8, pt::RR, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        let mut w = 8;
        for r in reports {
            r.write(&mut out[w..w + REPORT_BLOCK_LEN]);
            w += REPORT_BLOCK_LEN;
        }
        Ok(total)
    }
}

/// Source Description view (PT 202). Parsed only far enough to attribute
/// chunks to their SSRC and to skip the block inside compounds.
#[derive(Debug, Clone, Copy)]
pub struct Sdes<'a> {
    block: Block<'a>,
}

impl<'a> Sdes<'a> {
    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// The declared chunk count (RC field).
    pub fn chunk_count(&self) -> u8 {
        self.block.count
    }

    /// Builds a one-chunk SDES block whose only item is a CNAME; returns
    /// the block length. Chunk padding to the 32-bit boundary is zeros.
    pub fn build_cname(
        out: &mut [u8],
        ssrc: u32,
        cname: &[u8],
    ) -> Result<usize, RtcpError> {
        if cname.len() > u8::MAX as usize {
            return Err(RtcpError::Invalid("SDES CNAME exceeds 255 bytes"));
        }
        // ssrc + item header + value + null terminator.
        let chunk = 4 + 2 + cname.len() + 1;
        let total = HEADER_LEN + chunk.div_ceil(4) * 4;
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, 1, pt::SDES, total)?;
        out[4..8].copy_from_slice(&ssrc.to_be_bytes());
        out[8] = 1; // CNAME item type
        out[9] = cname.len() as u8;
        out[10..10 + cname.len()].copy_from_slice(cname);
        out[10 + cname.len()..total].fill(0);
        Ok(total)
    }

    /// Iterates the chunks, yielding each source's SSRC and raw item list.
    /// Stops early on malformed content or when `chunk_count` is exhausted.
    pub fn chunks(&self) -> SdesChunks<'a> {
        SdesChunks {
            payload: self.block.payload,
            pos: 0,
            remaining: self.block.count,
        }
    }
}

/// See [`Sdes::chunks`].
#[derive(Debug, Clone)]
pub struct SdesChunks<'a> {
    payload: &'a [u8],
    pos: usize,
    remaining: u8,
}

impl<'a> Iterator for SdesChunks<'a> {
    type Item = SdesChunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.pos + 4 > self.payload.len() {
            return None;
        }
        let start = self.pos;
        let ssrc = u32::from_be_bytes(
            self.payload[start..start + 4].try_into().unwrap_or_default(),
        );
        // Scan the item list: (type, len, value)* then a null type byte.
        // Any truncation aborts the whole iteration.
        let mut p = start + 4;
        let items_end = loop {
            let t = *self.payload.get(p)?;
            p += 1;
            if t == 0 {
                break p - 1;
            }
            let l = *self.payload.get(p)? as usize;
            p += 1;
            if p + l > self.payload.len() {
                return None;
            }
            p += l;
        };
        // Chunks are 32-bit aligned relative to their start.
        self.remaining -= 1;
        self.pos = start + (p - start).div_ceil(4) * 4;
        Some(SdesChunk {
            ssrc,
            items: &self.payload[start + 4..items_end],
        })
    }
}

/// Goodbye view (PT 203).
#[derive(Debug, Clone, Copy)]
pub struct Bye<'a> {
    block: Block<'a>,
}

impl<'a> Bye<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        if b.payload.len() < 4 * b.count as usize {
            return Err(RtcpError::Truncated);
        }
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// The departing sources.
    pub fn ssrcs(&self) -> impl Iterator<Item = u32> + '_ {
        self.block.payload[..4 * self.block.count as usize]
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap_or_default()))
    }

    /// The optional human-readable reason, when present and well-formed.
    pub fn reason(&self) -> Option<&'a [u8]> {
        let rest = &self.block.payload[4 * self.block.count as usize..];
        let (&n, text) = rest.split_first()?;
        text.get(..n as usize)
    }
}

/// Generic NACK view (RTPFB FMT 1, RFC 4585 §6.2.1).
#[derive(Debug, Clone, Copy)]
pub struct Nack<'a> {
    block: Block<'a>,
}

impl<'a> Nack<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        b.feedback()?;
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the participant sending the feedback.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// SSRC of the media source the feedback applies to.
    pub fn media_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[4..8].try_into().unwrap_or_default())
    }

    /// The raw PID/BLP entries.
    pub fn entries(&self) -> impl Iterator<Item = NackEntry> + '_ {
        self.block.payload[FEEDBACK_HEADER_LEN..]
            .chunks_exact(4)
            .map(|c| NackEntry {
                pid: u16::from_be_bytes([c[0], c[1]]),
                blp: u16::from_be_bytes([c[2], c[3]]),
            })
    }

    /// Every lost sequence number, expanded from the PID/BLP pairs.
    pub fn lost_packets(&self) -> impl Iterator<Item = u16> + '_ {
        self.entries().flat_map(NackEntry::lost)
    }

    /// Builds a generic NACK into `out`; returns the block length.
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        media_ssrc: u32,
        entries: &[NackEntry],
    ) -> Result<usize, RtcpError> {
        let total = HEADER_LEN + FEEDBACK_HEADER_LEN + 4 * entries.len();
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, pt::FMT_NACK, pt::RTPFB, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
        let mut w = 12;
        for e in entries {
            out[w..w + 2].copy_from_slice(&e.pid.to_be_bytes());
            out[w + 2..w + 4].copy_from_slice(&e.blp.to_be_bytes());
            w += 4;
        }
        Ok(total)
    }
}

/// Picture Loss Indication view (PSFB FMT 1, RFC 4585 §6.3.1).
#[derive(Debug, Clone, Copy)]
pub struct Pli<'a> {
    block: Block<'a>,
}

impl<'a> Pli<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        b.feedback()?;
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the participant sending the request.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// SSRC of the media source asked for a keyframe.
    pub fn media_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[4..8].try_into().unwrap_or_default())
    }

    /// Builds a PLI into `out`; returns the block length.
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        media_ssrc: u32,
    ) -> Result<usize, RtcpError> {
        let total = HEADER_LEN + FEEDBACK_HEADER_LEN;
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, pt::FMT_PLI, pt::PSFB, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
        Ok(total)
    }
}

/// Full Intra Request view (PSFB FMT 4, RFC 5104 §4.3.1).
#[derive(Debug, Clone, Copy)]
pub struct Fir<'a> {
    block: Block<'a>,
}

impl<'a> Fir<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        b.feedback()?;
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the participant sending the request.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// The feedback header's media SSRC; RFC 5104 sets this to 0 and
    /// carries the target inside each FCI entry.
    pub fn media_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[4..8].try_into().unwrap_or_default())
    }

    /// The FIR command entries: target source + sequence number.
    pub fn entries(&self) -> impl Iterator<Item = FirEntry> + '_ {
        self.block.payload[FEEDBACK_HEADER_LEN..]
            .chunks_exact(8)
            .map(|c| FirEntry {
                ssrc: u32::from_be_bytes(c[0..4].try_into().unwrap_or_default()),
                seq: c[4],
            })
    }

    /// Builds a FIR into `out`; returns the block length. Per RFC 5104 the
    /// common-header media SSRC is unused — callers conventionally pass 0
    /// and put the target in `entries`.
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        media_ssrc: u32,
        entries: &[FirEntry],
    ) -> Result<usize, RtcpError> {
        let total = HEADER_LEN + FEEDBACK_HEADER_LEN + 8 * entries.len();
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, pt::FMT_FIR, pt::PSFB, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
        let mut w = 12;
        for e in entries {
            out[w..w + 4].copy_from_slice(&e.ssrc.to_be_bytes());
            out[w + 4] = e.seq;
            // w + 5..w + 8 stay zero (reserved).
            w += 8;
        }
        Ok(total)
    }
}

/// Bit 15 set marks a status-vector chunk (clear = run length).
const TWCC_VECTOR: u16 = 0x8000;
/// Bit 14 of a vector chunk selects 2-bit symbols (clear = 1-bit).
const TWCC_VEC_WIDE: u16 = 0x4000;
/// The run-length field of a run chunk.
const TWCC_RUN_MASK: u16 = 0x1FFF;

/// The 2-bit wire symbol for a status: 0 = not received, 1 = small delta,
/// 2 = large/negative delta.
fn twcc_symbol(s: TwccStatus) -> u16 {
    match s {
        TwccStatus::NotReceived => 0,
        TwccStatus::Received(d) if (0..=255).contains(&d) => 1,
        TwccStatus::Received(_) => 2,
    }
}

/// How many delta bytes a wire symbol consumes (small = 1, large = 2).
fn twcc_delta_bytes(sym: u16) -> usize {
    usize::from(sym == 1) + 2 * usize::from(sym == 2)
}

/// Transport-wide congestion-control feedback view (RTPFB FMT 15,
/// draft-holmer-rmcat-transport-wide-cc-extensions).
#[derive(Debug, Clone, Copy)]
pub struct Twcc<'a> {
    block: Block<'a>,
    /// The packet-chunk region of the FCI.
    chunks: &'a [u8],
    /// The recv-delta region: exactly the bytes the status symbols
    /// reference, not including any trailing padding.
    deltas: &'a [u8],
}

impl<'a> Twcc<'a> {
    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        let (_, fci) = b.feedback()?;
        if fci.len() < 8 {
            return Err(RtcpError::Truncated);
        }
        let status_count = u16::from_be_bytes([fci[2], fci[3]]) as usize;
        // Scan chunks until `status_count` symbols are accounted for,
        // counting the delta bytes the received symbols will need. A chunk
        // may encode more symbols than the count — the tail is ignored.
        let mut off = 8usize;
        let mut decoded = 0usize;
        let mut delta_bytes = 0usize;
        while decoded < status_count {
            if off + 2 > fci.len() {
                return Err(RtcpError::Truncated);
            }
            let chunk = u16::from_be_bytes([fci[off], fci[off + 1]]);
            off += 2;
            let left = status_count - decoded;
            if chunk & TWCC_VECTOR == 0 {
                let sym = (chunk >> 13) & 3;
                let take = ((chunk & TWCC_RUN_MASK) as usize).min(left);
                decoded += take;
                delta_bytes += take * twcc_delta_bytes(sym);
            } else {
                let wide = chunk & TWCC_VEC_WIDE != 0;
                let take = (if wide { 7 } else { 14 }).min(left);
                for i in 0..take {
                    let s = if wide {
                        (chunk >> (12 - 2 * i)) & 3
                    } else {
                        (chunk >> (13 - i)) & 1
                    };
                    delta_bytes += twcc_delta_bytes(s);
                }
                decoded += take;
            }
            // A zero-progress chunk (run length 0) would loop forever;
            // bail out instead of spinning on malformed input.
            if (chunk & TWCC_VECTOR == 0) && (chunk & TWCC_RUN_MASK == 0) {
                return Err(RtcpError::Truncated);
            }
        }
        if fci.len() - off < delta_bytes {
            return Err(RtcpError::Truncated);
        }
        Ok(Self {
            block: b,
            chunks: &fci[8..off],
            deltas: &fci[off..off + delta_bytes],
        })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the participant sending the feedback.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// SSRC of the media source the feedback applies to.
    pub fn media_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[4..8].try_into().unwrap_or_default())
    }

    /// The transport-wide sequence number of the first packet covered.
    pub fn base_seq(&self) -> u16 {
        let fci = &self.block.payload[FEEDBACK_HEADER_LEN..];
        u16::from_be_bytes([fci[0], fci[1]])
    }

    /// How many packet statuses the message encodes.
    pub fn status_count(&self) -> u16 {
        let fci = &self.block.payload[FEEDBACK_HEADER_LEN..];
        u16::from_be_bytes([fci[2], fci[3]])
    }

    /// The reference time the deltas are relative to, in 64 ms units
    /// (24-bit wire field).
    pub fn reference_time(&self) -> u32 {
        let fci = &self.block.payload[FEEDBACK_HEADER_LEN..];
        (u32::from(fci[4]) << 16) | (u32::from(fci[5]) << 8) | u32::from(fci[6])
    }

    /// The sender's feedback-packet counter; receivers use it to detect
    /// lost feedback.
    pub fn feedback_packet_count(&self) -> u8 {
        self.block.payload[FEEDBACK_HEADER_LEN + 7]
    }

    /// Iterates `(sequence number, status)` for each of the
    /// `status_count` covered packets, in order.
    pub fn packets(&self) -> TwccPackets<'a> {
        TwccPackets {
            chunks: self.chunks,
            chunk_off: 0,
            deltas: self.deltas,
            delta_off: 0,
            remaining: self.status_count() as usize,
            seq: self.base_seq(),
            chunk: 0,
            syms_left: 0,
            is_vec: false,
            vec_wide: false,
        }
    }

    /// Builds a TWCC feedback packet into `out`; returns the block length,
    /// including zero padding to the 32-bit boundary.
    ///
    /// `statuses[i]` describes `base_seq + i`; `ref_time` is in 64 ms
    /// units and must fit 24 bits; received deltas are encoded as small
    /// (one byte) when in `0..=255` and large (two bytes, signed)
    /// otherwise — anything outside `i16` range fails with
    /// [`RtcpError::Invalid`].
    ///
    /// Chunks are emitted as status vectors only — 1-bit symbols when the
    /// next window holds no large deltas, 2-bit otherwise. Run-length
    /// coding of long loss streaks is a possible future optimization; the
    /// format produced here is always legal.
    pub fn build(
        out: &mut [u8],
        sender_ssrc: u32,
        media_ssrc: u32,
        base_seq: u16,
        ref_time: u32,
        fb_count: u8,
        statuses: &[TwccStatus],
    ) -> Result<usize, RtcpError> {
        if statuses.len() > u16::MAX as usize {
            return Err(RtcpError::CountOverflow {
                have: statuses.len(),
                max: u16::MAX as usize,
            });
        }
        if ref_time > 0xFF_FFFF {
            return Err(RtcpError::Invalid(
                "TWCC reference time exceeds 24 bits",
            ));
        }
        // Size pass: delta bytes + validation of the delta range.
        let mut delta_bytes = 0usize;
        for &s in statuses {
            match s {
                TwccStatus::NotReceived => {}
                TwccStatus::Received(d) if (0..=255).contains(&d) => delta_bytes += 1,
                TwccStatus::Received(d) if i16::try_from(d).is_ok() => delta_bytes += 2,
                TwccStatus::Received(_) => {
                    return Err(RtcpError::Invalid("TWCC receive delta out of range"));
                }
            }
        }
        let body = HEADER_LEN + FEEDBACK_HEADER_LEN + 8
            + 2 * Self::chunk_count(statuses)
            + delta_bytes;
        // The FCI is zero-padded to the 32-bit boundary; the length field
        // covers it, no P bit needed.
        let total = body.div_ceil(4) * 4;
        if out.len() < total {
            return Err(RtcpError::BufferTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        write_header(out, pt::FMT_TWCC, pt::RTPFB, total)?;
        out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
        out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
        out[12..14].copy_from_slice(&base_seq.to_be_bytes());
        out[14..16].copy_from_slice(&(statuses.len() as u16).to_be_bytes());
        out[16..19].copy_from_slice(&ref_time.to_be_bytes()[1..]);
        out[19] = fb_count;
        let mut w = 20;
        let mut i = 0;
        while i < statuses.len() {
            let (take, mut chunk) = Self::chunk_at(statuses, i);
            for (k, &s) in statuses[i..i + take].iter().enumerate() {
                let sym = twcc_symbol(s);
                if chunk & TWCC_VEC_WIDE != 0 {
                    chunk |= sym << (12 - 2 * k);
                } else {
                    chunk |= sym << (13 - k);
                }
            }
            out[w..w + 2].copy_from_slice(&chunk.to_be_bytes());
            w += 2;
            i += take;
        }
        for &s in statuses {
            if let TwccStatus::Received(d) = s {
                if (0..=255).contains(&d) {
                    out[w] = d as u8;
                    w += 1;
                } else {
                    out[w..w + 2].copy_from_slice(&(d as i16).to_be_bytes());
                    w += 2;
                }
            }
        }
        out[w..total].fill(0);
        Ok(total)
    }
}

impl Twcc<'_> {
    /// How many packet statuses the chunk starting at `i` encodes, and the
    /// chunk's base bits (vector flag + width). Greedy: a 1-bit vector of
    /// up to 14 when no large delta is in the window, else a 2-bit vector
    /// of up to 7.
    fn chunk_at(statuses: &[TwccStatus], i: usize) -> (usize, u16) {
        let narrow_end = statuses.len().min(i + 14);
        let has_large = statuses[i..narrow_end]
            .iter()
            .any(|&s| twcc_symbol(s) == 2);
        if has_large {
            (
                statuses.len().min(i + 7) - i,
                TWCC_VECTOR | TWCC_VEC_WIDE,
            )
        } else {
            (narrow_end - i, TWCC_VECTOR)
        }
    }

    fn chunk_count(statuses: &[TwccStatus]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < statuses.len() {
            i += Self::chunk_at(statuses, i).0;
            n += 1;
        }
        n
    }
}

/// See [`Twcc::packets`].
#[derive(Debug, Clone)]
pub struct TwccPackets<'a> {
    chunks: &'a [u8],
    chunk_off: usize,
    deltas: &'a [u8],
    delta_off: usize,
    /// Statuses still to emit (the wire `status_count`).
    remaining: usize,
    seq: u16,
    /// The chunk being peeled: `syms_left` symbols remain, each taken from
    /// the top of the chunk's symbol field.
    chunk: u16,
    syms_left: u16,
    is_vec: bool,
    vec_wide: bool,
}

impl TwccPackets<'_> {
    /// The next 2-bit status symbol, loading a fresh chunk when the
    /// current one is exhausted. `None` means the chunk bytes ran out —
    /// impossible for a parsed [`Twcc`], defensive against it anyway.
    fn next_symbol(&mut self) -> Option<u16> {
        while self.syms_left == 0 {
            self.chunk = u16::from_be_bytes([
                *self.chunks.get(self.chunk_off)?,
                *self.chunks.get(self.chunk_off + 1)?,
            ]);
            self.chunk_off += 2;
            if self.chunk & TWCC_VECTOR == 0 {
                self.is_vec = false;
                self.syms_left = self.chunk & TWCC_RUN_MASK;
            } else {
                self.is_vec = true;
                self.vec_wide = self.chunk & TWCC_VEC_WIDE != 0;
                self.syms_left = if self.vec_wide { 7 } else { 14 };
            }
            // A run chunk of length 0 simply skips to the next chunk.
        }
        self.syms_left -= 1;
        if !self.is_vec {
            return Some((self.chunk >> 13) & 3);
        }
        // Symbols are packed MSB-first: index 0 sits at bit 13 (1-bit) or
        // bits 13..12 (2-bit).
        let total = if self.vec_wide { 7 } else { 14 };
        let idx = total - 1 - self.syms_left;
        if self.vec_wide {
            Some((self.chunk >> (12 - 2 * idx)) & 3)
        } else {
            Some((self.chunk >> (13 - idx)) & 1)
        }
    }
}

impl Iterator for TwccPackets<'_> {
    type Item = (u16, TwccStatus);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let sym = self.next_symbol()?;
        self.remaining -= 1;
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let status = match sym {
            1 => {
                let d = *self.deltas.get(self.delta_off)?;
                self.delta_off += 1;
                TwccStatus::Received(i32::from(d))
            }
            2 => {
                let hi = *self.deltas.get(self.delta_off)?;
                let lo = *self.deltas.get(self.delta_off + 1)?;
                self.delta_off += 2;
                TwccStatus::Received(i32::from(i16::from_be_bytes([hi, lo])))
            }
            // 0 = not received, 3 = reserved (treated as not received).
            _ => TwccStatus::NotReceived,
        };
        Some((seq, status))
    }
}

/// REMB bandwidth estimate view (PSFB FMT 15 with the "REMB" FCI,
/// draft-alvestrand-rmcat-remb).
#[derive(Debug, Clone, Copy)]
pub struct Remb<'a> {
    block: Block<'a>,
}

impl<'a> Remb<'a> {
    /// True when the block is a PSFB FMT-15 whose FCI starts with "REMB".
    fn is_remb(b: &Block<'a>) -> bool {
        b.payload
            .get(FEEDBACK_HEADER_LEN..FEEDBACK_HEADER_LEN + 4)
            == Some(b"REMB".as_slice())
    }

    fn from_block(b: Block<'a>) -> Result<Self, RtcpError> {
        let (_, fci) = b.feedback()?;
        // Magic (4) + num-SSRC (1) + bitrate exp/mantissa (3).
        if fci.len() < 8 || fci.len() < 8 + 4 * fci[4] as usize {
            return Err(RtcpError::Truncated);
        }
        Ok(Self { block: b })
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }

    /// SSRC of the participant sending the estimate.
    pub fn sender_ssrc(&self) -> u32 {
        u32::from_be_bytes(self.block.payload[0..4].try_into().unwrap_or_default())
    }

    /// The estimated bitrate in bits per second (mantissa << exponent,
    /// saturating at `u64::MAX`).
    pub fn bitrate(&self) -> u64 {
        let fci = &self.block.payload[FEEDBACK_HEADER_LEN..];
        let exp = u32::from(fci[5] >> 2);
        let mantissa = u128::from(u32::from_be_bytes([0, fci[5] & 3, fci[6], fci[7]]));
        (mantissa << exp).min(u128::from(u64::MAX)) as u64
    }

    /// The media SSRCs the estimate applies to.
    pub fn ssrcs(&self) -> impl Iterator<Item = u32> + '_ {
        let fci = &self.block.payload[FEEDBACK_HEADER_LEN..];
        let n = fci[4] as usize;
        fci[8..8 + 4 * n]
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap_or_default()))
    }
}

/// Any RTCP block this module does not model: APP packets, unknown packet
/// types, and feedback sub-messages without a dedicated view.
#[derive(Debug, Clone, Copy)]
pub struct Other<'a> {
    block: Block<'a>,
}

impl<'a> Other<'a> {
    /// The packet type field.
    pub fn packet_type(&self) -> u8 {
        self.block.packet_type
    }

    /// The RC / FMT field.
    pub fn count(&self) -> u8 {
        self.block.count
    }

    /// The block body between header and padding.
    pub fn payload(&self) -> &'a [u8] {
        self.block.payload
    }

    /// The block's raw bytes, header included.
    pub fn raw(&self) -> &'a [u8] {
        self.block.raw
    }
}

/// Writes the common header for a block of `total` bytes. `total` must be
/// a multiple of 4 (every builder pads to the boundary); the only
/// reachable failure is a block over 256 KiB, which the count field
/// cannot express.
fn write_header(
    out: &mut [u8],
    count: u8,
    packet_type: u8,
    total: usize,
) -> Result<(), RtcpError> {
    debug_assert!(total >= HEADER_LEN && total.is_multiple_of(4));
    let words = total / 4 - 1;
    if words > u16::MAX as usize {
        return Err(RtcpError::CountOverflow {
            have: total,
            max: 4 * (u16::MAX as usize + 1),
        });
    }
    out[0] = 0x80 | count;
    out[1] = packet_type;
    out[2..4].copy_from_slice(&(words as u16).to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_blocks() -> [ReportBlock; 2] {
        [
            ReportBlock {
                ssrc: 0x01020304,
                fraction_lost: 0x20,
                cumulative_lost: 0x010203,
                highest_seq: 0x0004_0007,
                jitter: 512,
                lsr: 0xA1B2C3D4,
                dlsr: 0x00010000,
            },
            ReportBlock {
                ssrc: 0x05060708,
                fraction_lost: 0,
                cumulative_lost: -5, // duplicates can push this negative
                highest_seq: 9,
                jitter: 0,
                lsr: 0,
                dlsr: 0,
            },
        ]
    }

    fn parse_first(buf: &[u8]) -> RtcpPacket<'_> {
        packets(buf).next().unwrap().unwrap()
    }

    #[test]
    fn sr_round_trip() {
        let reports = report_blocks();
        let mut out = [0u8; 256];
        let n = SenderReport::build(
            &mut out,
            0xDEADBEEF,
            0x11223344_55667788,
            0x01020304,
            1234,
            98765,
            &reports,
        )
        .unwrap();
        assert_eq!(n, 4 + 24 + 48);
        let RtcpKind::SenderReport(sr) = parse_first(&out[..n]).kind() else {
            panic!("expected SR");
        };
        assert_eq!(sr.packet_count(), 1234);
        assert_eq!(sr.octet_count(), 98765);
        assert_eq!(sr.sender_ssrc(), 0xDEADBEEF);
        assert_eq!(sr.ntp_timestamp(), 0x11223344_55667788);
        assert_eq!(sr.ntp_middle(), 0x3344_5566);
        assert_eq!(sr.rtp_timestamp(), 0x01020304);
        let got: Vec<ReportBlock> = sr.reports().collect();
        assert_eq!(got, reports);
        let pkt = parse_first(&out[..n]);
        assert_eq!(pkt.packet_type(), pt::SR);
        assert_eq!(pkt.count(), 2);
        assert_eq!(pkt.block_len(), n);
        assert_eq!(pkt.raw(), &out[..n]);
    }

    #[test]
    fn rr_round_trip_empty_and_full() {
        let mut out = [0u8; 256];
        let n = ReceiverReport::build(&mut out, 0x0BADC0DE, &[]).unwrap();
        assert_eq!(n, 8);
        let RtcpKind::ReceiverReport(rr) = parse_first(&out[..n]).kind() else {
            panic!("expected RR");
        };
        assert_eq!(rr.sender_ssrc(), 0x0BADC0DE);
        assert_eq!(rr.reports().count(), 0);

        let reports = report_blocks();
        let n = ReceiverReport::build(&mut out, 7, &reports).unwrap();
        let RtcpKind::ReceiverReport(rr) = parse_first(&out[..n]).kind() else {
            panic!("expected RR");
        };
        let got: Vec<ReportBlock> = rr.reports().collect();
        assert_eq!(got, reports);
    }

    #[test]
    fn report_overflow_rejected() {
        let blocks = [ReportBlock {
            ssrc: 0,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_seq: 0,
            jitter: 0,
            lsr: 0,
            dlsr: 0,
        }; 32];
        let mut out = [0u8; 4096];
        assert_eq!(
            ReceiverReport::build(&mut out, 1, &blocks).unwrap_err(),
            RtcpError::CountOverflow { have: 32, max: 31 }
        );
    }

    #[test]
    fn nack_round_trip_and_expansion() {
        let entries = [
            NackEntry {
                pid: 100,
                blp: 0b0010_0000_0000_0101,
            },
            NackEntry { pid: 65000, blp: 0 },
        ];
        let mut out = [0u8; 256];
        let n = Nack::build(&mut out, 1, 0xABCDEF01, &entries).unwrap();
        assert_eq!(n, 4 + 8 + 8);
        let pkt = parse_first(&out[..n]);
        assert_eq!(pkt.packet_type(), pt::RTPFB);
        assert_eq!(pkt.count(), pt::FMT_NACK);
        let RtcpKind::Nack(nack) = pkt.kind() else {
            panic!("expected NACK");
        };
        assert_eq!(nack.sender_ssrc(), 1);
        assert_eq!(nack.media_ssrc(), 0xABCDEF01);
        let got: Vec<NackEntry> = nack.entries().collect();
        assert_eq!(got, entries);
        // pid 100; BLP bits 0,2,13 -> 101, 103, 114. Second entry: 65000.
        let lost: Vec<u16> = nack.lost_packets().collect();
        assert_eq!(lost, [100, 101, 103, 114, 65000]);
    }

    #[test]
    fn nack_blp_wraps_sequence_numbers() {
        let entries = [NackEntry {
            pid: 0xFFFE,
            blp: 0b11,
        }];
        let mut out = [0u8; 64];
        let n = Nack::build(&mut out, 1, 2, &entries).unwrap();
        let RtcpKind::Nack(nack) = parse_first(&out[..n]).kind() else {
            panic!("expected NACK");
        };
        let lost: Vec<u16> = nack.lost_packets().collect();
        assert_eq!(lost, [0xFFFE, 0xFFFF, 0x0000]);
    }

    #[test]
    fn pli_round_trip() {
        let mut out = [0u8; 64];
        let n = Pli::build(&mut out, 0x11111111, 0x22222222).unwrap();
        assert_eq!(n, 12);
        let pkt = parse_first(&out[..n]);
        assert_eq!(pkt.packet_type(), pt::PSFB);
        assert_eq!(pkt.count(), pt::FMT_PLI);
        let RtcpKind::Pli(pli) = pkt.kind() else {
            panic!("expected PLI");
        };
        assert_eq!(pli.sender_ssrc(), 0x11111111);
        assert_eq!(pli.media_ssrc(), 0x22222222);
    }

    #[test]
    fn fir_round_trip() {
        let entries = [
            FirEntry {
                ssrc: 0x99887766,
                seq: 42,
            },
            FirEntry {
                ssrc: 0x11223344,
                seq: 7,
            },
        ];
        let mut out = [0u8; 128];
        let n = Fir::build(&mut out, 0x5555, 0, &entries).unwrap();
        assert_eq!(n, 4 + 8 + 16);
        let RtcpKind::Fir(fir) = parse_first(&out[..n]).kind() else {
            panic!("expected FIR");
        };
        assert_eq!(fir.sender_ssrc(), 0x5555);
        assert_eq!(fir.media_ssrc(), 0);
        let got: Vec<FirEntry> = fir.entries().collect();
        assert_eq!(got, entries);
    }

    #[test]
    fn twcc_round_trip_all_status_kinds() {
        // Mix of not-received, small, large, and negative deltas — enough
        // packets to span several chunks of both vector widths.
        let statuses: Vec<TwccStatus> = (0..30u16)
            .map(|i| match i % 7 {
                0 => TwccStatus::NotReceived,
                1 => TwccStatus::Received(3),
                2 => TwccStatus::Received(255),
                3 => TwccStatus::Received(300), // large
                4 => TwccStatus::Received(-10), // large negative
                5 => TwccStatus::Received(0),
                _ => TwccStatus::NotReceived,
            })
            .collect();
        let mut out = [0u8; 512];
        let n = Twcc::build(&mut out, 0xAAAA, 0xBBBB, 1000, 0x123456, 9, &statuses).unwrap();
        assert_eq!(n % 4, 0);
        let pkt = parse_first(&out[..n]);
        assert_eq!(pkt.packet_type(), pt::RTPFB);
        assert_eq!(pkt.count(), pt::FMT_TWCC);
        let RtcpKind::Twcc(twcc) = pkt.kind() else {
            panic!("expected TWCC");
        };
        assert_eq!(twcc.sender_ssrc(), 0xAAAA);
        assert_eq!(twcc.media_ssrc(), 0xBBBB);
        assert_eq!(twcc.base_seq(), 1000);
        assert_eq!(twcc.status_count() as usize, statuses.len());
        assert_eq!(twcc.reference_time(), 0x123456);
        assert_eq!(twcc.feedback_packet_count(), 9);
        let got: Vec<(u16, TwccStatus)> = twcc.packets().collect();
        let want: Vec<(u16, TwccStatus)> = statuses
            .iter()
            .enumerate()
            .map(|(i, &s)| (1000 + i as u16, s))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn twcc_round_trip_empty() {
        let mut out = [0u8; 64];
        let n = Twcc::build(&mut out, 1, 2, 5, 0, 0, &[]).unwrap();
        assert_eq!(n, 4 + 8 + 8);
        let RtcpKind::Twcc(twcc) = parse_first(&out[..n]).kind() else {
            panic!("expected TWCC");
        };
        assert_eq!(twcc.status_count(), 0);
        assert_eq!(twcc.packets().count(), 0);
    }

    #[test]
    fn twcc_parses_run_length_chunks() {
        // Hand-crafted: base 200, count 20, ref 0x010203, fb 4.
        // Chunk 1: run of 16 x small-delta (T=0, S=1, run=16) = 0x2010.
        // Chunk 2: run of 4 x not-received (T=0, S=0, run=4) = 0x0004.
        // Then 16 one-byte deltas.
        let mut p = vec![0x8F, pt::RTPFB, 0x00, 0x09];
        p.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // sender
        p.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]); // media
        p.extend_from_slice(&200u16.to_be_bytes());
        p.extend_from_slice(&20u16.to_be_bytes());
        p.extend_from_slice(&[0x01, 0x02, 0x03, 4]);
        p.extend_from_slice(&0x2010u16.to_be_bytes());
        p.extend_from_slice(&0x0004u16.to_be_bytes());
        p.extend_from_slice(&[7u8; 16]);
        assert_eq!(p.len(), 4 * 10);
        let RtcpKind::Twcc(twcc) = parse_first(&p).kind() else {
            panic!("expected TWCC");
        };
        assert_eq!(twcc.base_seq(), 200);
        let got: Vec<(u16, TwccStatus)> = twcc.packets().collect();
        assert_eq!(got.len(), 20);
        for (i, &(seq, s)) in got.iter().enumerate() {
            assert_eq!(seq, 200 + i as u16);
            if i < 16 {
                assert_eq!(s, TwccStatus::Received(7));
            } else {
                assert_eq!(s, TwccStatus::NotReceived);
            }
        }
    }

    #[test]
    fn twcc_parses_one_bit_vectors_and_tail_padding() {
        // 16 statuses via a 14-wide 1-bit vector (T=1,S=0) plus a tail
        // vector whose extra symbols sit past the status count.
        // Chunk 1: alternating received/lost starting with received.
        // Chunk 2: two real "received" symbols then ignored pad bits.
        let mut p = vec![0x8F, pt::RTPFB, 0x00, 0x08];
        p.extend_from_slice(&[0, 0, 0, 1]); // sender
        p.extend_from_slice(&[0, 0, 0, 2]); // media
        p.extend_from_slice(&50u16.to_be_bytes());
        p.extend_from_slice(&16u16.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        let chunk1: u16 = 0x8000 | 0b10_1010_1010_1010;
        p.extend_from_slice(&chunk1.to_be_bytes());
        let chunk2: u16 = 0x8000 | 0b11_0000_0000_0000;
        p.extend_from_slice(&chunk2.to_be_bytes());
        // Received: even positions 0,2,4,6,8,10,12 (7) + tail 14,15 = 9.
        p.extend_from_slice(&[1u8; 9]);
        p.extend_from_slice(&[0, 0, 0]); // FCI zero-pad to 4 bytes
        let RtcpKind::Twcc(twcc) = parse_first(&p).kind() else {
            panic!("expected TWCC");
        };
        let got: Vec<(u16, TwccStatus)> = twcc.packets().collect();
        assert_eq!(got.len(), 16);
        for (i, &(_, s)) in got.iter().enumerate() {
            if i % 2 == 0 || i >= 14 {
                assert_eq!(s, TwccStatus::Received(1), "index {i}");
            } else {
                assert_eq!(s, TwccStatus::NotReceived, "index {i}");
            }
        }
    }

    #[test]
    fn twcc_rejects_invalid_inputs() {
        let mut out = [0u8; 256];
        // ref_time wider than 24 bits.
        assert_eq!(
            Twcc::build(&mut out, 1, 2, 0, 0x1_000_000, 0, &[]).unwrap_err(),
            RtcpError::Invalid("TWCC reference time exceeds 24 bits")
        );
        // Delta beyond the signed 16-bit wire range.
        assert_eq!(
            Twcc::build(&mut out, 1, 2, 0, 0, 0, &[TwccStatus::Received(40_000)])
                .unwrap_err(),
            RtcpError::Invalid("TWCC receive delta out of range")
        );
    }

    #[test]
    fn remb_parses_bitrate_and_ssrcs() {
        // PSFB FMT 15, FCI = "REMB" | num=2 | exp<<2|mantissa | ssrcs.
        // exp = 6, mantissa = 1500 -> 1500 << 6 = 96000 bit/s.
        let mut p = vec![0x8F, pt::PSFB, 0x00, 0x06];
        p.extend_from_slice(&[0, 0, 0, 9]); // sender
        p.extend_from_slice(&[0, 0, 0, 0]); // media (unused)
        p.extend_from_slice(b"REMB");
        p.push(2);
        p.extend_from_slice(&[6 << 2, (1500 >> 8) as u8, (1500 & 0xFF) as u8]);
        p.extend_from_slice(&0xAAAAu32.to_be_bytes());
        p.extend_from_slice(&0xBBBBu32.to_be_bytes());
        let RtcpKind::Remb(remb) = parse_first(&p).kind() else {
            panic!("expected REMB");
        };
        assert_eq!(remb.sender_ssrc(), 9);
        assert_eq!(remb.bitrate(), 96000);
        let ssrcs: Vec<u32> = remb.ssrcs().collect();
        assert_eq!(ssrcs, [0xAAAA, 0xBBBB]);
    }

    #[test]
    fn sdes_and_bye_parse() {
        // SDES with two chunks: ssrc A + CNAME item, ssrc B + empty list.
        let mut sdes = vec![0x82, pt::SDES, 0x00, 0x00];
        sdes.extend_from_slice(&0xAAAAu32.to_be_bytes());
        sdes.extend_from_slice(&[1, 4, b'n', b'a', b'm', b'e']); // CNAME
        sdes.push(0); // null
        while (sdes.len() - 8) % 4 != 0 {
            sdes.push(0); // pad chunk to 32-bit boundary
        }
        sdes.extend_from_slice(&0xBBBBu32.to_be_bytes());
        sdes.extend_from_slice(&[0, 0, 0, 0]); // null + pad chunk to 4
        let words = (sdes.len() / 4 - 1) as u16;
        sdes[2..4].copy_from_slice(&words.to_be_bytes());
        let RtcpKind::Sdes(s) = parse_first(&sdes).kind() else {
            panic!("expected SDES");
        };
        assert_eq!(s.chunk_count(), 2);
        let chunks: Vec<SdesChunk<'_>> = s.chunks().collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].ssrc, 0xAAAA);
        assert_eq!(chunks[0].items, &[1, 4, b'n', b'a', b'm', b'e']);
        assert_eq!(chunks[1].ssrc, 0xBBBB);
        assert_eq!(chunks[1].items, &[][..]);

        // BYE with two SSRCs and a reason.
        let mut bye = vec![0x82, pt::BYE, 0x00, 0x00];
        bye.extend_from_slice(&0x1111u32.to_be_bytes());
        bye.extend_from_slice(&0x2222u32.to_be_bytes());
        bye.push(4);
        bye.extend_from_slice(b"gone");
        bye.extend_from_slice(&[0, 0, 0]); // reason pad to 4
        let words = (bye.len() / 4 - 1) as u16;
        bye[2..4].copy_from_slice(&words.to_be_bytes());
        let RtcpKind::Bye(b) = parse_first(&bye).kind() else {
            panic!("expected BYE");
        };
        let ssrcs: Vec<u32> = b.ssrcs().collect();
        assert_eq!(ssrcs, [0x1111, 0x2222]);
        assert_eq!(b.reason(), Some(b"gone".as_slice()));
    }

    #[test]
    fn sdes_build_cname_round_trip() {
        let mut out = [0u8; 64];
        let n = Sdes::build_cname(&mut out, 0xABCDEF, b"wroomd").unwrap();
        // 4 (hdr) + align4(4 + 2 + 6 + 1) = 4 + 16.
        assert_eq!(n, 20);
        let RtcpKind::Sdes(s) = parse_first(&out[..n]).kind() else {
            panic!("expected SDES");
        };
        assert_eq!(s.chunk_count(), 1);
        let chunks: Vec<SdesChunk<'_>> = s.chunks().collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].ssrc, 0xABCDEF);
        let mut want = vec![1u8, 6];
        want.extend_from_slice(b"wroomd");
        assert_eq!(chunks[0].items, &want[..]);

        // Odd-length CNAME pads to the boundary; oversized ones are rejected.
        let n = Sdes::build_cname(&mut out, 7, b"abc").unwrap();
        assert_eq!(n, 16);
        assert_eq!(
            Sdes::build_cname(&mut out, 7, &[0u8; 300]).unwrap_err(),
            RtcpError::Invalid("SDES CNAME exceeds 255 bytes")
        );
    }

    #[test]
    fn compound_datagram_walks_all_blocks() {
        // RR (empty) + SDES (skipped) + NACK + PLI in one datagram.
        let mut dgram = Vec::new();
        let mut scratch = [0u8; 256];
        let n = ReceiverReport::build(&mut scratch, 0x1234, &[]).unwrap();
        dgram.extend_from_slice(&scratch[..n]);
        // Minimal well-formed SDES: one chunk, empty item list.
        let sdes = [0x81, pt::SDES, 0x00, 0x01, 0, 0, 0, 7];
        dgram.extend_from_slice(&sdes);
        let n = Nack::build(
            &mut scratch,
            0x1234,
            0xBEEF,
            &[NackEntry { pid: 5, blp: 1 }],
        )
        .unwrap();
        dgram.extend_from_slice(&scratch[..n]);
        let n = Pli::build(&mut scratch, 0x1234, 0xBEEF).unwrap();
        dgram.extend_from_slice(&scratch[..n]);

        let kinds: Vec<u8> = packets(&dgram)
            .map(|r| r.unwrap().packet_type())
            .collect();
        assert_eq!(kinds, [pt::RR, pt::SDES, pt::RTPFB, pt::PSFB]);
        // And the NACK inside is intact.
        let third = packets(&dgram).nth(2).unwrap().unwrap();
        let RtcpKind::Nack(nack) = third.kind() else {
            panic!("expected NACK");
        };
        let lost: Vec<u16> = nack.lost_packets().collect();
        assert_eq!(lost, [5, 6]);
    }

    #[test]
    fn compound_with_unknown_blocks_still_walks() {
        // APP (204) and an unmodeled RTPFB FMT 3 ride along fine.
        let app = [0x80, pt::APP, 0x00, 0x01, 0, 0, 0, 0];
        let fb3 = [0x83, pt::RTPFB, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2];
        let mut dgram = Vec::new();
        dgram.extend_from_slice(&app);
        dgram.extend_from_slice(&fb3);
        let mut scratch = [0u8; 64];
        let n = Pli::build(&mut scratch, 1, 2).unwrap();
        dgram.extend_from_slice(&scratch[..n]);
        let blocks: Vec<RtcpPacket<'_>> =
            packets(&dgram).collect::<Result<_, _>>().unwrap();
        assert!(matches!(blocks[0].kind(), RtcpKind::Other(_)));
        assert!(matches!(blocks[1].kind(), RtcpKind::Other(_)));
        assert!(matches!(blocks[2].kind(), RtcpKind::Pli(_)));
        let RtcpKind::Other(o) = blocks[0].kind() else {
            panic!("expected Other");
        };
        assert_eq!(o.packet_type(), pt::APP);
        assert_eq!(o.count(), 0);
        assert_eq!(o.payload(), &[0, 0, 0, 0]);
    }

    #[test]
    fn rejects_malformed_blocks() {
        // Empty / short.
        assert_eq!(RtcpPacket::parse(&[]).unwrap_err(), RtcpError::TooShort);
        assert_eq!(
            RtcpPacket::parse(&[0x80; 3]).unwrap_err(),
            RtcpError::TooShort
        );
        // Bad version.
        let mut v = [0u8; 8];
        v[0] = 0x40;
        assert_eq!(
            RtcpPacket::parse(&v).unwrap_err(),
            RtcpError::BadVersion(1)
        );
        // Length field overruns the datagram.
        let l = [0x80, pt::RR, 0x00, 0x05, 0, 0, 0, 0];
        assert_eq!(RtcpPacket::parse(&l).unwrap_err(), RtcpError::BadLength);
        // P set with zero padding or a count beyond the block.
        let p0 = [0xA0, pt::RR, 0x00, 0x01, 0, 0, 0, 0];
        assert_eq!(
            RtcpPacket::parse(&p0).unwrap_err(),
            RtcpError::BadPadding
        );
        let p1 = [0xA0, pt::RR, 0x00, 0x01, 0, 0, 0, 9];
        assert_eq!(
            RtcpPacket::parse(&p1).unwrap_err(),
            RtcpError::BadPadding
        );
        // SR body too small for the sender info.
        let sr = [0x80, pt::SR, 0x00, 0x01, 0, 0, 0, 0];
        assert_eq!(RtcpPacket::parse(&sr).unwrap_err(), RtcpError::Truncated);
        // RR body too small for declared report blocks.
        let rr = [0x81, pt::RR, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(RtcpPacket::parse(&rr).unwrap_err(), RtcpError::Truncated);
        // NACK without the feedback header.
        let nack = [0x81, pt::RTPFB, 0x00, 0x00];
        assert_eq!(RtcpPacket::parse(&nack).unwrap_err(), RtcpError::Truncated);
        // BYE payload too small for the SSRC count.
        let bye = [0x82, pt::BYE, 0x00, 0x01, 0, 0, 0, 1];
        assert_eq!(RtcpPacket::parse(&bye).unwrap_err(), RtcpError::Truncated);
    }

    #[test]
    fn twcc_truncations_do_not_panic() {
        // FCI header too short.
        let short = [0x8F, pt::RTPFB, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(
            RtcpPacket::parse(&short).unwrap_err(),
            RtcpError::Truncated
        );
        // status_count = 5 but no chunks at all.
        let mut p = vec![0x8F, pt::RTPFB, 0x00, 0x04];
        p.extend_from_slice(&[0; 8]); // feedback header
        p.extend_from_slice(&[0, 0, 0, 5]); // base 0, count 5
        p.extend_from_slice(&[0, 0, 0, 0]); // ref + fb count, no chunks
        assert_eq!(
            RtcpPacket::parse(&p).unwrap_err(),
            RtcpError::Truncated
        );
        // A chunk promises two 2-byte deltas (symbols 0,1 both 2) that
        // aren't there.
        let mut q = vec![0x8F, pt::RTPFB, 0x00, 0x05];
        q.extend_from_slice(&[0; 8]);
        q.extend_from_slice(&[0, 0, 0, 2]); // base 0, count 2
        q.extend_from_slice(&[0, 0, 0, 0]);
        q.extend_from_slice(&0xE800u16.to_be_bytes()); // wide vec, syms 2,2
        q.extend_from_slice(&[0, 0]); // 2 pad bytes, half the promised deltas
        assert_eq!(
            RtcpPacket::parse(&q).unwrap_err(),
            RtcpError::Truncated
        );
        // A run chunk of length 0 cannot satisfy the count; must not loop.
        let mut r = vec![0x8F, pt::RTPFB, 0x00, 0x05];
        r.extend_from_slice(&[0; 8]);
        r.extend_from_slice(&[0, 0, 0, 1]);
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(&0x0000u16.to_be_bytes()); // run of 0
        r.extend_from_slice(&[0, 0]);
        assert_eq!(
            RtcpPacket::parse(&r).unwrap_err(),
            RtcpError::Truncated
        );
    }

    #[test]
    fn compound_error_terminates_iteration() {
        let mut scratch = [0u8; 64];
        let n = Pli::build(&mut scratch, 1, 2).unwrap();
        let mut dgram = scratch[..n].to_vec();
        dgram.extend_from_slice(&[0x80, pt::RR]); // truncated second block
        let mut it = packets(&dgram);
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next().unwrap().unwrap_err(), RtcpError::TooShort);
        assert!(it.next().is_none());
    }

    #[test]
    fn buffer_too_small_reports_needed() {
        let mut out = [0u8; 8];
        let err = Pli::build(&mut out, 1, 2).unwrap_err();
        assert_eq!(
            err,
            RtcpError::BufferTooSmall {
                needed: 12,
                have: 8
            }
        );
        let reports = report_blocks();
        let err = SenderReport::build(&mut out, 1, 0, 0, 0, 0, &reports).unwrap_err();
        assert_eq!(
            err,
            RtcpError::BufferTooSmall {
                needed: 76,
                have: 8
            }
        );
    }

    #[test]
    fn trailing_garbage_is_an_error_not_a_panic() {
        let mut scratch = [0u8; 64];
        let n = Pli::build(&mut scratch, 1, 2).unwrap();
        let mut dgram = scratch[..n].to_vec();
        dgram.extend_from_slice(&[0xFF, 0xEE]); // 2 leftover bytes
        let results: Vec<_> = packets(&dgram).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[1].as_ref().unwrap_err(), &RtcpError::TooShort);
    }
}
