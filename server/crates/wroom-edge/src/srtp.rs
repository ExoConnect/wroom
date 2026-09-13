//! SRTP and SRTCP packet protection for one peer connection — RFC 3711
//! packet processing with the AES-GCM AEAD transforms of RFC 7714 and
//! the AES-CM/HMAC-SHA1-80 baseline of RFC 3711 (the profiles WebRTC
//! negotiates over DTLS-SRTP).
//!
//! [`Srtp`] is the per-peer state that sits between the DTLS handshake
//! and the media plane. When `dimpl` finishes it yields DTLS-SRTP keying
//! material (RFC 5764 §4.2), which [`Srtp::from_keying_material`] splits
//! into a decrypt context for inbound media and an encrypt context for
//! outbound media, deriving the session keys and salts through the
//! RFC 3711 §4.3 AES-CM PRF.
//!
//! Everything on the packet path runs in place on caller-owned buffers:
//! no allocation, no IO, no locks, no unbounded work. Per-SSRC state
//! (rollover counter tracking and a 64-bit replay window) lives in a
//! fixed-size table.
//!
//! # Wire layout produced/consumed
//!
//! GCM profiles:
//!
//! SRTP:  `RTP header ‖ AES-GCM ciphertext(payload) ‖ 16-octet tag`
//! — the RTP header is the AEAD associated data.
//!
//! SRTCP: `RTCP header(8) ‖ AES-GCM ciphertext(body) ‖ tag ‖ E‖index`
//! — associated data is the 8-octet header plus the E/index word.
//!
//! `AES128_CM_SHA1_80`:
//!
//! SRTP:  `RTP header ‖ AES-CM ciphertext(payload) ‖ 10-octet HMAC tag`
//! — the tag is HMAC-SHA1 over the packet concatenated with the ROC,
//! truncated to 80 bits (RFC 3711 §4.2).
//!
//! SRTCP: `RTCP header(8) ‖ AES-CM ciphertext(body) ‖ E‖index ‖ tag`
//! — note the E/index word precedes the tag here (it follows the tag
//! under GCM), and the tag covers the packet including that word
//! (RFC 3711 §3.4).
//!
//! When a peer sends an unencrypted (E=0) SRTCP packet the "ciphertext"
//! is the plaintext body; `decrypt_rtcp` authenticates and accepts those
//! too, per RFC 7714 §9.3 and RFC 3711 §3.4.
//!
//! # Boundaries
//!
//! * The supported profiles are `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`,
//!   and `AES128_CM_SHA1_80` — the RFC 8827 mandatory baseline, which
//!   browsers' `use_srtp` leads with and dimpl's client-first server
//!   therefore selects.
//! * MKI is not supported. A peer using MKI is not possible under
//!   DTLS-SRTP negotiation, and a packet carrying one fails
//!   authentication and is dropped.
//! * key_derivation_rate is 0, per RFC 5764 — session keys are derived
//!   once at context creation.
//! * Reordered *sends* are tolerated within the 64-index window, but the
//!   caller must never repeat a `(SSRC, ROC, SEQ)` triple: GCM IV reuse
//!   destroys authentication, and CM keystream reuse is a two-time pad.
//!   The send path enforces this and returns [`SrtpError::IndexReuse`]
//!   rather than emit a packet with a spent IV.

use std::fmt;

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ctr::Ctr128BE;
use ctr::cipher::StreamCipher;
use dimpl::SrtpProfile;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use tracing::{debug, trace};

/// Maximum bytes [`Srtp::encrypt_rtp`] appends to an RTP packet: the
/// 128-bit GCM authentication tag mandated by RFC 7714 §10. The CM
/// profile appends only [`CM_TAG_LEN`]; callers size buffers with this
/// constant as the upper bound.
pub const SRTP_TAG_LEN: usize = 16;

/// Maximum bytes [`Srtp::encrypt_rtcp`] appends to an RTCP packet: the
/// tag plus the 4-octet E-flag/SRTCP-index word. The CM profile appends
/// [`CM_SRTCP_TRAILER_LEN`].
pub const SRTCP_TRAILER_LEN: usize = SRTP_TAG_LEN + 4;

/// Maximum distinct SSRCs tracked per direction per connection.
///
/// A *publisher* leg carries a dozen at most — audio + a few simulcast
/// layers with RTX. A *subscriber* leg is an SFU aggregate: it must carry
/// every publisher's SSRCs, so the bound is sized to the room cap —
/// 512 members × ~4 SSRCs each (audio + video + RTX + one layer) ≈ 2048.
/// When the table is full, packets for new SSRCs are rejected rather than
/// evicting live replay state — eviction would let an attacker flush a
/// window and replay old packets.
const MAX_STREAMS: usize = 2048;

/// Width in bits of the sliding replay window (RFC 3711 §3.3.2 requires
/// at least 64).
const REPLAY_WINDOW: u64 = 64;

/// Salt length for the GCM transforms (RFC 7714 §12).
const GCM_SALT_LEN: usize = 12;

/// Salt length for the AES-CM transform (RFC 3711 §4.1.1); also the
/// width of [`SessionCipher::salt`], the largest of the transforms.
const CM_SALT_LEN: usize = 14;

/// HMAC-SHA1 tag length the `AES128_CM_SHA1_80` profile appends to an
/// RTP packet (RFC 3711 §4.2.1, n_tag = 80 bits).
const CM_TAG_LEN: usize = 10;

/// Bytes the CM profile appends to an RTCP packet: the 4-octet
/// E-flag/SRTCP-index word followed by the tag — the opposite order of
/// the GCM trailer.
const CM_SRTCP_TRAILER_LEN: usize = 4 + CM_TAG_LEN;

/// Key-derivation labels, RFC 3711 §4.3.1/§4.3.2. The authentication-key
/// labels (0x01/0x04) are used only by the AES-CM profile; GCM needs no
/// separate auth key.
const LABEL_RTP_KEY: u8 = 0x00;
const LABEL_RTP_AUTH: u8 = 0x01;
const LABEL_RTP_SALT: u8 = 0x02;
const LABEL_RTCP_KEY: u8 = 0x03;
const LABEL_RTCP_AUTH: u8 = 0x04;
const LABEL_RTCP_SALT: u8 = 0x05;

/// The E-flag bit inside the SRTCP index word.
const SRTCP_E_BIT: u32 = 0x8000_0000;

/// First value past the valid 31-bit SRTCP index range; used as the
/// exhausted sentinel on the send side.
const SRTCP_INDEX_EXHAUSTED: u32 = 0x8000_0000;

/// Errors from SRTP/SRTCP processing.
///
/// All decrypt-side errors are non-fatal for the context: the packet is
/// dropped and the state is left untouched (authentication failures do
/// not advance the replay window or ROC estimates).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SrtpError {
    /// The negotiated profile is not one of the supported transforms
    /// (RFC 7714 GCM or RFC 3711 AES-CM/HMAC-SHA1-80).
    #[error("unsupported SRTP profile {0}")]
    UnsupportedProfile(SrtpProfile),

    /// The exported keying material length does not match the profile's
    /// `2 * (key + salt)` layout.
    #[error("keying material length {0} does not match negotiated profile")]
    BadKeyingMaterialLen(usize),

    /// Input shorter than the protocol minimum for the operation.
    #[error("packet too short")]
    TooShort,

    /// Header fields are inconsistent (bad version, claimed CSRC/extension
    /// lengths running past the packet, ...).
    #[error("malformed packet header")]
    Malformed,

    /// The caller's buffer has no room for the tag/trailer on encrypt.
    #[error("output buffer too small for authentication tag")]
    BufferTooSmall,

    /// Authentication tag verification failed: corrupted or forged
    /// packet (GCM tag or truncated HMAC-SHA1, per profile).
    #[error("authentication failed")]
    AuthFailed,

    /// The packet index is already in the replay window or too far
    /// behind it.
    #[error("packet replayed or outside replay window")]
    Replayed,

    /// Per-SSRC state table is full (see [`MAX_STREAMS`] rationale).
    #[error("too many SSRCs on this transport")]
    TooManyStreams,

    /// Sending this packet would reuse a `(SSRC, ROC, SEQ)` triple —
    /// refused because GCM IV reuse destroys authentication and CM
    /// keystream reuse is a two-time pad (RFC 7714 §8.4, RFC 3711
    /// §4.1.1).
    #[error("packet index reuse prevented")]
    IndexReuse,

    /// The 48-bit SRTP or 31-bit SRTCP index space is exhausted; the
    /// session must be rekeyed before further packets.
    #[error("packet index exhausted, rekey required")]
    IndexExhausted,

    /// The cipher primitive itself failed (AEAD length-limit violation,
    /// or a packet path dispatched against the wrong transform —
    /// unreachable for legal packets and profiles, kept for
    /// completeness).
    #[error("cipher operation failed")]
    Cipher,
}

/// Which DTLS role the local endpoint played when the keying material
/// was exported. RFC 5764 §4.2 fixes the exporter layout to
/// `client_key ‖ server_key ‖ client_salt ‖ server_salt`, so the role
/// decides which half decrypts inbound media.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The DTLS server — every production caller (browsers are always
    /// the clients). rx is the client-write half, tx the server-write.
    Server,
    /// The DTLS client — headless peers in tests and any future
    /// client-mode use. The halves swap: rx is the server-write half.
    Client,
}

/// SRTP/SRTCP protection state for one peer connection.
///
/// Obtained from [`Srtp::from_keying_material`] once DTLS reports the
/// negotiated profile and exported keying material. Internally holds two
/// independent contexts: inbound (decrypt, keyed with the client's write
/// keys — we are always the DTLS server) and outbound (encrypt, keyed
/// with the server's write keys).
///
/// Each operation mutates per-SSRC stream state, so all methods take
/// `&mut self`. Nothing here allocates or blocks.
pub struct Srtp {
    profile: SrtpProfile,
    /// Inbound context: decrypts packets the peer sends us.
    rx: Dir,
    /// Outbound context: encrypts packets we send the peer.
    tx: Dir,
}

impl Srtp {
    /// Build the context pair from DTLS-SRTP keying material.
    ///
    /// `material` is the exporter output `dimpl` reports via
    /// `Output::KeyingMaterial` (a [`dimpl::KeyingMaterial`] derefs to
    /// `&[u8]`), laid out per RFC 5764 §4.2 as
    /// `client_key ‖ server_key ‖ client_salt ‖ server_salt`. Equivalent
    /// to [`Srtp::from_keying_material_as`] with [`Role::Server`]: we are
    /// the DTLS server, so the client half keys the decrypt side and the
    /// server half keys the encrypt side.
    ///
    /// Returns [`SrtpError::UnsupportedProfile`] for anything but the
    /// supported profiles, and [`SrtpError::BadKeyingMaterialLen`] when
    /// the material length doesn't match the profile.
    pub fn from_keying_material(profile: SrtpProfile, material: &[u8]) -> Result<Self, SrtpError> {
        Self::from_keying_material_as(profile, material, Role::Server)
    }

    /// [`from_keying_material`](Self::from_keying_material) with the local
    /// endpoint's DTLS [`Role`] made explicit. For [`Role::Client`] the
    /// halves swap: rx decrypts with the server-write half and tx encrypts
    /// with the client-write half. The server default stays the primary
    /// entry point because every production caller is the DTLS server;
    /// the client role exists for in-process test peers that drive the
    /// real handshake.
    pub fn from_keying_material_as(
        profile: SrtpProfile,
        material: &[u8],
        role: Role,
    ) -> Result<Self, SrtpError> {
        // Master key/salt lengths per profile: RFC 5764 §4.2 /
        // RFC 3711 §5 (CM uses a 14-octet salt; GCM uses 12).
        let (key_len, salt_len) = match profile {
            SrtpProfile::AEAD_AES_128_GCM => (16, GCM_SALT_LEN),
            SrtpProfile::AEAD_AES_256_GCM => (32, GCM_SALT_LEN),
            SrtpProfile::AES128_CM_SHA1_80 => (16, CM_SALT_LEN),
            other => return Err(SrtpError::UnsupportedProfile(other)),
        };
        let want = 2 * (key_len + salt_len);
        if material.len() != want {
            return Err(SrtpError::BadKeyingMaterialLen(material.len()));
        }
        let (keys, salts) = material.split_at(2 * key_len);
        let (client_key, server_key) = keys.split_at(key_len);
        let (client_salt, server_salt) = salts.split_at(salt_len);
        let (rx_key, rx_salt, tx_key, tx_salt) = match role {
            Role::Server => (client_key, client_salt, server_key, server_salt),
            Role::Client => (server_key, server_salt, client_key, client_salt),
        };
        debug!(%profile, ?role, "SRTP contexts created");
        Ok(Self {
            profile,
            rx: Dir::new(profile, rx_key, rx_salt)?,
            tx: Dir::new(profile, tx_key, tx_salt)?,
        })
    }

    /// The negotiated protection profile.
    pub fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Decrypt and authenticate one inbound SRTP packet, in place.
    ///
    /// `buf` holds exactly one packet including the trailing tag (16
    /// octets for GCM, 10 for AES-CM). On success returns the plaintext
    /// packet length: the RTP packet then occupies `buf[..ret]` and the
    /// tag region beyond it is scratch. Replay state for the packet's
    /// SSRC is updated only after authentication succeeds; on error no
    /// state changes and the buffer's content is unspecified.
    pub fn decrypt_rtp(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        match self.profile {
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM => {
                self.decrypt_rtp_gcm(buf)
            }
            SrtpProfile::AES128_CM_SHA1_80 => self.decrypt_rtp_cm(buf),
            other => Err(SrtpError::UnsupportedProfile(other)),
        }
    }

    /// [`decrypt_rtp`](Self::decrypt_rtp) for the RFC 7714 AEAD-GCM
    /// transforms: a single AEAD open authenticates and decrypts.
    fn decrypt_rtp_gcm(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        let len = buf.len();
        if len < 12 + SRTP_TAG_LEN {
            return Err(SrtpError::TooShort);
        }
        let (header_len, seq, ssrc) = rtp_header(&buf[..len])?;
        // The tag must sit after the full RTP header; a header length
        // reaching into the tag region means the header lied.
        if header_len > len - SRTP_TAG_LEN {
            return Err(SrtpError::Malformed);
        }

        let index = match self.rx.streams.get(ssrc) {
            Some(s) => {
                let index = s.rtp.guess(seq);
                if !s.rtp.check(index) {
                    trace!(ssrc, seq, "SRTP packet dropped: replayed");
                    return Err(SrtpError::Replayed);
                }
                index
            }
            // First packet for this SSRC: s_l initialises to its SEQ
            // with ROC 0 (RFC 3711 §3.3.1).
            None => seq as u64,
        };

        let roc = (index >> 16) as u32;
        let iv = rtp_iv(self.rx.rtp.salt(), ssrc, roc, seq);
        let (head, rest) = buf.split_at_mut(header_len);
        let (body, tag) = rest.split_at_mut(rest.len() - SRTP_TAG_LEN);
        self.rx.rtp.decrypt(&iv, head, body, tag)?;

        // Authenticated: commit the index to the replay window.
        self.rx.streams.get_mut_or_insert(ssrc)?.rtp.record(index);
        Ok(len - SRTP_TAG_LEN)
    }

    /// [`decrypt_rtp`](Self::decrypt_rtp) for AES-CM/HMAC-SHA1-80:
    /// authenticate, replay-check, then CTR-decrypt the payload.
    /// Nothing commits to stream state until the tag verifies.
    fn decrypt_rtp_cm(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        let len = buf.len();
        if len < 12 + CM_TAG_LEN {
            return Err(SrtpError::TooShort);
        }
        let (header_len, seq, ssrc) = rtp_header(&buf[..len])?;
        if header_len > len - CM_TAG_LEN {
            return Err(SrtpError::Malformed);
        }

        // The index estimate supplies both the ROC the tag is computed
        // over and the CTR IV's index field.
        let index = match self.rx.streams.get(ssrc) {
            Some(s) => s.rtp.guess(seq),
            // First packet for this SSRC: s_l initialises to its SEQ
            // with ROC 0 (RFC 3711 §3.3.1).
            None => seq as u64,
        };
        let roc = (index >> 16) as u32;

        // Authenticate first: tag = HMAC-SHA1(auth, packet ‖ ROC)
        // truncated to 80 bits (RFC 3711 §4.2.1). `verify_truncated_left`
        // compares in constant time.
        let cm = self.rx.rtp.cm()?;
        let mut mac = cm.auth();
        mac.update(&buf[..len - CM_TAG_LEN]);
        mac.update(&roc.to_be_bytes());
        mac.verify_truncated_left(&buf[len - CM_TAG_LEN..])
            .map_err(|_| SrtpError::AuthFailed)?;

        if let Some(s) = self.rx.streams.get(ssrc)
            && !s.rtp.check(index)
        {
            trace!(ssrc, seq, "SRTP packet dropped: replayed");
            return Err(SrtpError::Replayed);
        }

        // CTR-decrypt the payload in place; encryption and decryption
        // are the same keystream XOR.
        let iv = cm_rtp_iv(self.rx.rtp.salt(), ssrc, index);
        cm.keystream(&iv, &mut buf[header_len..len - CM_TAG_LEN]);

        // Authenticated: commit the index to the replay window.
        self.rx.streams.get_mut_or_insert(ssrc)?.rtp.record(index);
        Ok(len - CM_TAG_LEN)
    }

    /// Encrypt one outbound RTP packet, in place.
    ///
    /// `buf[..len]` holds the plaintext RTP packet; `buf` must have room
    /// for the tag past `len` — [`SRTP_TAG_LEN`] bytes is always enough
    /// (the CM profile appends only [`CM_TAG_LEN`]). On success the
    /// secured packet occupies `buf[..ret]`.
    ///
    /// A `(SSRC, ROC, SEQ)` triple must never repeat under one key —
    /// for GCM, IV reuse destroys authentication (RFC 7714 §8.4); for
    /// CM, keystream reuse is a two-time pad (RFC 3711 §4.1.1). If the
    /// presented sequence number would do so — e.g. an exact duplicate,
    /// or a send so old the 64-packet history can't disprove reuse —
    /// the packet is refused with [`SrtpError::IndexReuse`].
    pub fn encrypt_rtp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        match self.profile {
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM => {
                self.encrypt_rtp_gcm(buf, len)
            }
            SrtpProfile::AES128_CM_SHA1_80 => self.encrypt_rtp_cm(buf, len),
            other => Err(SrtpError::UnsupportedProfile(other)),
        }
    }

    /// [`encrypt_rtp`](Self::encrypt_rtp) for the RFC 7714 AEAD-GCM
    /// transforms.
    fn encrypt_rtp_gcm(&mut self, buf: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        if buf.len() < len + SRTP_TAG_LEN {
            return Err(SrtpError::BufferTooSmall);
        }
        let (header_len, seq, ssrc) = rtp_header(&buf[..len])?;
        let index = {
            let stream = self.tx.streams.get_mut_or_insert(ssrc)?;
            let index = stream.rtp.send_index(seq)?;
            if !stream.rtp.check(index) {
                trace!(ssrc, seq, "SRTP send refused: IV reuse");
                return Err(SrtpError::IndexReuse);
            }
            index
        };

        let roc = (index >> 16) as u32;
        let iv = rtp_iv(self.tx.rtp.salt(), ssrc, roc, seq);
        let (head, rest) = buf.split_at_mut(header_len);
        let tag = self
            .tx
            .rtp
            .encrypt(&iv, head, &mut rest[..len - header_len])?;
        buf[len..len + SRTP_TAG_LEN].copy_from_slice(&tag);

        self.tx.streams.get_mut_or_insert(ssrc)?.rtp.record(index);
        Ok(len + SRTP_TAG_LEN)
    }

    /// [`encrypt_rtp`](Self::encrypt_rtp) for AES-CM/HMAC-SHA1-80:
    /// CTR-encrypt the payload, then append the 80-bit HMAC-SHA1 tag
    /// computed over the packet concatenated with the ROC.
    fn encrypt_rtp_cm(&mut self, buf: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        if buf.len() < len + CM_TAG_LEN {
            return Err(SrtpError::BufferTooSmall);
        }
        let (header_len, seq, ssrc) = rtp_header(&buf[..len])?;
        let index = {
            let stream = self.tx.streams.get_mut_or_insert(ssrc)?;
            let index = stream.rtp.send_index(seq)?;
            if !stream.rtp.check(index) {
                trace!(ssrc, seq, "SRTP send refused: IV reuse");
                return Err(SrtpError::IndexReuse);
            }
            index
        };
        let roc = (index >> 16) as u32;

        let cm = self.tx.rtp.cm()?;
        let iv = cm_rtp_iv(self.tx.rtp.salt(), ssrc, index);
        cm.keystream(&iv, &mut buf[header_len..len]);

        // tag = HMAC-SHA1(auth, packet ‖ ROC) truncated to 80 bits
        // (RFC 3711 §4.2, §4.2.1).
        let mut mac = cm.auth();
        mac.update(&buf[..len]);
        mac.update(&roc.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        buf[len..len + CM_TAG_LEN].copy_from_slice(&tag[..CM_TAG_LEN]);

        self.tx.streams.get_mut_or_insert(ssrc)?.rtp.record(index);
        Ok(len + CM_TAG_LEN)
    }

    /// Decrypt and authenticate one inbound SRTCP packet, in place.
    ///
    /// `buf` holds one packet including the trailing tag and E/index
    /// word (the tag/word order differs per profile — see the module
    /// docs). Handles both E=1 (body encrypted) and E=0 (authenticated
    /// only) forms per RFC 7714 §9.2/§9.3 and RFC 3711 §3.4. On success
    /// returns the plaintext length: the RTCP compound packet is
    /// `buf[..ret]`, the stripped trailer is scratch. On error no state
    /// changes and the buffer's content is unspecified.
    pub fn decrypt_rtcp(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        match self.profile {
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM => {
                self.decrypt_rtcp_gcm(buf)
            }
            SrtpProfile::AES128_CM_SHA1_80 => self.decrypt_rtcp_cm(buf),
            other => Err(SrtpError::UnsupportedProfile(other)),
        }
    }

    /// [`decrypt_rtcp`](Self::decrypt_rtcp) for the RFC 7714 AEAD-GCM
    /// transforms; the wire layout is `packet ‖ tag ‖ E‖index`.
    fn decrypt_rtcp_gcm(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        let len = buf.len();
        // Minimum: 8-octet RTCP header + 16-octet tag + 4-octet trailer.
        if len < 8 + SRTCP_TRAILER_LEN {
            return Err(SrtpError::TooShort);
        }
        if buf[0] >> 6 != 2 {
            return Err(SrtpError::Malformed);
        }
        let ssrc = u32::from_be_bytes(buf[4..8].try_into().expect("slice len checked"));
        let esrtcp = u32::from_be_bytes(buf[len - 4..].try_into().expect("slice len checked"));
        let encrypted = esrtcp & SRTCP_E_BIT != 0;
        let index = (esrtcp & !SRTCP_E_BIT) as u64;
        let tag_at = len - SRTCP_TRAILER_LEN;

        if let Some(s) = self.rx.streams.get(ssrc)
            && !s.rtcp.check(index)
        {
            trace!(ssrc, index, "SRTCP packet dropped: replayed");
            return Err(SrtpError::Replayed);
        }

        let iv = rtcp_iv(self.rx.rtcp.salt(), ssrc, esrtcp & !SRTCP_E_BIT);
        if encrypted {
            // AAD = first 8 octets ‖ E/index word (non-contiguous — a
            // 12-byte staging copy keeps it allocation-free).
            let mut aad = [0u8; 12];
            aad[..8].copy_from_slice(&buf[..8]);
            aad[8..].copy_from_slice(&esrtcp.to_be_bytes());
            let (body, tail) = buf[8..].split_at_mut(tag_at - 8);
            self.rx
                .rtcp
                .decrypt(&iv, &aad, body, &tail[..SRTP_TAG_LEN])?;
        } else {
            // AAD = whole RTCP packet ‖ E/index word. Slide the index
            // word into the tag slot so the AAD is one contiguous slice;
            // the tag itself is small enough to keep on the stack.
            let mut tag = [0u8; SRTP_TAG_LEN];
            tag.copy_from_slice(&buf[tag_at..tag_at + SRTP_TAG_LEN]);
            buf[tag_at..tag_at + 4].copy_from_slice(&esrtcp.to_be_bytes());
            self.rx
                .rtcp
                .decrypt(&iv, &buf[..len - SRTP_TAG_LEN], &mut [], &tag)?;
        }

        self.rx.streams.get_mut_or_insert(ssrc)?.rtcp.record(index);
        Ok(tag_at)
    }

    /// [`decrypt_rtcp`](Self::decrypt_rtcp) for AES-CM/HMAC-SHA1-80;
    /// the wire layout is `packet ‖ E‖index ‖ tag` — the index word
    /// precedes the tag and is inside the authenticated region
    /// (RFC 3711 §3.4).
    fn decrypt_rtcp_cm(&mut self, buf: &mut [u8]) -> Result<usize, SrtpError> {
        let len = buf.len();
        // Minimum: 8-octet RTCP header + 4-octet E/index + 10-octet tag.
        if len < 8 + CM_SRTCP_TRAILER_LEN {
            return Err(SrtpError::TooShort);
        }
        if buf[0] >> 6 != 2 {
            return Err(SrtpError::Malformed);
        }
        let ssrc = u32::from_be_bytes(buf[4..8].try_into().expect("slice len checked"));
        let tag_at = len - CM_TAG_LEN;
        let esrtcp =
            u32::from_be_bytes(buf[tag_at - 4..tag_at].try_into().expect("slice len checked"));
        let encrypted = esrtcp & SRTCP_E_BIT != 0;
        let index = (esrtcp & !SRTCP_E_BIT) as u64;

        // Authenticate first: the tag covers the packet including the
        // E/index word — everything before the tag.
        let cm = self.rx.rtcp.cm()?;
        let mut mac = cm.auth();
        mac.update(&buf[..tag_at]);
        mac.verify_truncated_left(&buf[tag_at..])
            .map_err(|_| SrtpError::AuthFailed)?;

        // Then the replay check on the 31-bit index (RFC 3711 §3.4).
        if let Some(s) = self.rx.streams.get(ssrc)
            && !s.rtcp.check(index)
        {
            trace!(ssrc, index, "SRTCP packet dropped: replayed");
            return Err(SrtpError::Replayed);
        }

        // E=0 leaves the body unmodified (RFC 3711 §3.4).
        if encrypted {
            let iv = cm_rtcp_iv(self.rx.rtcp.salt(), ssrc, esrtcp & !SRTCP_E_BIT);
            cm.keystream(&iv, &mut buf[8..tag_at - 4]);
        }

        self.rx.streams.get_mut_or_insert(ssrc)?.rtcp.record(index);
        Ok(tag_at - 4)
    }

    /// Encrypt and authenticate one outbound RTCP packet, in place.
    ///
    /// `buf[..len]` holds the plaintext RTCP compound packet; `buf` must
    /// have room for [`SRTCP_TRAILER_LEN`] more bytes (always enough —
    /// the CM profile appends [`CM_SRTCP_TRAILER_LEN`]). The E bit is
    /// set (we always encrypt SRTCP bodies, matching browser
    /// behaviour). The per-SSRC SRTCP index is managed internally per
    /// RFC 3711 §3.4; wrapping it past 2³¹ returns
    /// [`SrtpError::IndexExhausted`].
    pub fn encrypt_rtcp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        match self.profile {
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM => {
                self.seal_rtcp_gcm(buf, len, true)
            }
            SrtpProfile::AES128_CM_SHA1_80 => self.seal_rtcp_cm(buf, len, true),
            other => Err(SrtpError::UnsupportedProfile(other)),
        }
    }

    /// Shared SRTCP seal for the GCM profile; `encrypt_body` selects
    /// E=1 vs E=0 form. The public surface only encrypts
    /// (`encrypt_rtcp`); the E=0 path is kept internal and exercised by
    /// tests and [`decrypt_rtcp`](Self::decrypt_rtcp).
    fn seal_rtcp_gcm(
        &mut self,
        buf: &mut [u8],
        len: usize,
        encrypt_body: bool,
    ) -> Result<usize, SrtpError> {
        if buf.len() < len + SRTCP_TRAILER_LEN {
            return Err(SrtpError::BufferTooSmall);
        }
        if len < 8 {
            return Err(SrtpError::TooShort);
        }
        if buf[0] >> 6 != 2 {
            return Err(SrtpError::Malformed);
        }
        let ssrc = u32::from_be_bytes(buf[4..8].try_into().expect("slice len checked"));
        let index = {
            let stream = self.tx.streams.get_mut_or_insert(ssrc)?;
            if stream.rtcp_next == SRTCP_INDEX_EXHAUSTED {
                return Err(SrtpError::IndexExhausted);
            }
            let index = stream.rtcp_next;
            stream.rtcp_next += 1;
            index
        };
        let esrtcp = if encrypt_body {
            index | SRTCP_E_BIT
        } else {
            index
        };
        let iv = rtcp_iv(self.tx.rtcp.salt(), ssrc, index);

        if encrypt_body {
            let mut aad = [0u8; 12];
            aad[..8].copy_from_slice(&buf[..8]);
            aad[8..].copy_from_slice(&esrtcp.to_be_bytes());
            let tag = self.tx.rtcp.encrypt(&iv, &aad, &mut buf[8..len])?;
            buf[len..len + SRTP_TAG_LEN].copy_from_slice(&tag);
            buf[len + SRTP_TAG_LEN..len + SRTCP_TRAILER_LEN].copy_from_slice(&esrtcp.to_be_bytes());
        } else {
            // Stage the index word immediately after the packet so the
            // AAD (packet ‖ index) is one contiguous slice, then
            // overwrite it with tag ‖ index.
            buf[len..len + 4].copy_from_slice(&esrtcp.to_be_bytes());
            let tag = self.tx.rtcp.encrypt(&iv, &buf[..len + 4], &mut [])?;
            buf[len + SRTP_TAG_LEN..len + SRTCP_TRAILER_LEN].copy_from_slice(&esrtcp.to_be_bytes());
            buf[len..len + SRTP_TAG_LEN].copy_from_slice(&tag);
        }
        Ok(len + SRTCP_TRAILER_LEN)
    }

    /// [`seal_rtcp_gcm`](Self::seal_rtcp_gcm) for AES-CM/HMAC-SHA1-80:
    /// CTR-encrypt the body (E=1) or not (E=0), append the E/index word,
    /// then the truncated HMAC-SHA1 tag covering the packet including
    /// that word (RFC 3711 §3.4).
    fn seal_rtcp_cm(
        &mut self,
        buf: &mut [u8],
        len: usize,
        encrypt_body: bool,
    ) -> Result<usize, SrtpError> {
        if buf.len() < len + CM_SRTCP_TRAILER_LEN {
            return Err(SrtpError::BufferTooSmall);
        }
        if len < 8 {
            return Err(SrtpError::TooShort);
        }
        if buf[0] >> 6 != 2 {
            return Err(SrtpError::Malformed);
        }
        let ssrc = u32::from_be_bytes(buf[4..8].try_into().expect("slice len checked"));
        let index = {
            let stream = self.tx.streams.get_mut_or_insert(ssrc)?;
            if stream.rtcp_next == SRTCP_INDEX_EXHAUSTED {
                return Err(SrtpError::IndexExhausted);
            }
            let index = stream.rtcp_next;
            stream.rtcp_next += 1;
            index
        };
        let esrtcp = if encrypt_body {
            index | SRTCP_E_BIT
        } else {
            index
        };

        let cm = self.tx.rtcp.cm()?;
        if encrypt_body {
            let iv = cm_rtcp_iv(self.tx.rtcp.salt(), ssrc, index);
            cm.keystream(&iv, &mut buf[8..len]);
        }

        // The E/index word precedes the tag; the tag's input is the
        // packet including that word (RFC 3711 §3.4).
        buf[len..len + 4].copy_from_slice(&esrtcp.to_be_bytes());
        let mut mac = cm.auth();
        mac.update(&buf[..len + 4]);
        let tag = mac.finalize().into_bytes();
        buf[len + 4..len + CM_SRTCP_TRAILER_LEN].copy_from_slice(&tag[..CM_TAG_LEN]);
        Ok(len + CM_SRTCP_TRAILER_LEN)
    }
}

impl fmt::Debug for Srtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("Srtp")
            .field("profile", &self.profile)
            .field("rx_streams", &self.rx.streams.len())
            .field("tx_streams", &self.tx.streams.len())
            .finish()
    }
}

/// One direction's cryptographic state: the SRTP and SRTCP session
/// ciphers (each the derived session key material + session salt) plus
/// the bounded per-SSRC table.
struct Dir {
    rtp: SessionCipher,
    rtcp: SessionCipher,
    streams: Streams,
}

impl Dir {
    /// Derive session keys and salts from a master key/salt pair via the
    /// RFC 3711 §4.3.3 AES-CM PRF (kdr = 0, so derivation happens once).
    /// The PRF cipher width follows the master key: AES-128 for
    /// AEAD_AES_128_GCM and AES128_CM_SHA1_80, AES-256 for
    /// AEAD_AES_256_GCM (RFC 7714 §11, RFC 6188).
    fn new(
        profile: SrtpProfile,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<Self, SrtpError> {
        debug_assert!(matches!(master_salt.len(), GCM_SALT_LEN | CM_SALT_LEN));
        Ok(Self {
            rtp: SessionCipher::derive(
                profile,
                master_key,
                master_salt,
                LABEL_RTP_KEY,
                LABEL_RTP_AUTH,
                LABEL_RTP_SALT,
            )?,
            rtcp: SessionCipher::derive(
                profile,
                master_key,
                master_salt,
                LABEL_RTCP_KEY,
                LABEL_RTCP_AUTH,
                LABEL_RTCP_SALT,
            )?,
            streams: Streams::new(),
        })
    }
}

/// A derived session cipher: the transform's key material plus the
/// session salt used in per-packet IV formation. `salt` is padded to
/// [`CM_SALT_LEN`]; [`SessionCipher::salt`] trims it to the transform's
/// width.
struct SessionCipher {
    cipher: Cipher,
    salt: [u8; CM_SALT_LEN],
}

// ~1 KB inline per variant — per-connection state, so the size is
// bounded and cheap; boxing would put a pointer dereference on every
// packet for no benefit on the hot path.
#[allow(clippy::large_enum_variant)]
enum Cipher {
    Gcm128(Aes128Gcm),
    Gcm256(Aes256Gcm),
    /// RFC 3711 AES-128 Counter Mode + HMAC-SHA1-80.
    Cm(CmSha1),
}

/// The AES-128-CM + HMAC-SHA1-80 transform's session state for one
/// direction (RFC 3711 §4.1.1, §4.2.1). Unlike the AEAD ciphers the
/// keystream and authentication are separate primitives: a CTR-mode
/// keystream XOR plus an 80-bit truncated HMAC-SHA1 tag.
struct CmSha1 {
    /// The 16-octet session encryption key. `Ctr128BE` is rebuilt per
    /// packet (it owns no reusable IV state), so the raw key is kept —
    /// AES-128 key expansion is a bounded, stack-only cost.
    enc: [u8; 16],
    /// The session authentication key, pre-keyed into an HMAC-SHA1:
    /// cloning it per packet skips re-deriving the pads.
    mac: Hmac<Sha1>,
}

impl CmSha1 {
    /// XOR `buf` with the AES-CM keystream seeded at `iv`. Encryption
    /// and decryption are the same operation.
    fn keystream(&self, iv: &[u8; 16], buf: &mut [u8]) {
        let mut ctr = Ctr128BE::<Aes128>::new(
            GenericArray::from_slice(&self.enc),
            GenericArray::from_slice(iv),
        );
        ctr.apply_keystream(buf);
    }

    /// A fresh HMAC-SHA1 instance under the session authentication key.
    fn auth(&self) -> Hmac<Sha1> {
        self.mac.clone()
    }
}

impl SessionCipher {
    fn derive(
        profile: SrtpProfile,
        master_key: &[u8],
        master_salt: &[u8],
        key_label: u8,
        auth_label: u8,
        salt_label: u8,
    ) -> Result<Self, SrtpError> {
        let mut salt = [0u8; CM_SALT_LEN];
        let cipher = match profile {
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM => {
                let key_len = match profile {
                    SrtpProfile::AEAD_AES_128_GCM => 16,
                    _ => 32,
                };
                let mut key = [0u8; 32];
                aes_cm_prf(master_key, master_salt, key_label, &mut key[..key_len]);
                aes_cm_prf(master_key, master_salt, salt_label, &mut salt[..GCM_SALT_LEN]);
                if key_len == 16 {
                    Cipher::Gcm128(Aes128Gcm::new(GenericArray::from_slice(&key[..16])))
                } else {
                    Cipher::Gcm256(Aes256Gcm::new(GenericArray::from_slice(&key[..32])))
                }
            }
            SrtpProfile::AES128_CM_SHA1_80 => {
                // Session sizes per RFC 3711 §5 defaults: 16-octet
                // encryption key, 20-octet HMAC-SHA1 auth key, 14-octet
                // salt.
                let mut enc = [0u8; 16];
                aes_cm_prf(master_key, master_salt, key_label, &mut enc);
                let mut auth = [0u8; 20];
                aes_cm_prf(master_key, master_salt, auth_label, &mut auth);
                aes_cm_prf(master_key, master_salt, salt_label, &mut salt);
                let mac = <Hmac<Sha1> as Mac>::new_from_slice(&auth)
                    .expect("HMAC accepts keys of any length");
                Cipher::Cm(CmSha1 { enc, mac })
            }
            // Rejected in `from_keying_material_as` before this runs.
            other => return Err(SrtpError::UnsupportedProfile(other)),
        };
        Ok(Self { cipher, salt })
    }

    /// The session salt at the transform's width: 12 octets for GCM
    /// (RFC 7714 §12), 14 for AES-CM (RFC 3711 §4.1.1).
    fn salt(&self) -> &[u8] {
        match &self.cipher {
            Cipher::Gcm128(_) | Cipher::Gcm256(_) => &self.salt[..GCM_SALT_LEN],
            Cipher::Cm(_) => &self.salt[..],
        }
    }

    /// The CM transform state. Only reached from the CM packet paths,
    /// which dispatch on the same profile [`derive`] built this cipher
    /// for — a GCM cipher here is a construction bug, reported as
    /// [`SrtpError::Cipher`] rather than a panic.
    fn cm(&self) -> Result<&CmSha1, SrtpError> {
        match &self.cipher {
            Cipher::Cm(c) => Ok(c),
            _ => Err(SrtpError::Cipher),
        }
    }

    /// AEAD-encrypt `buf` in place, returning the detached 16-octet tag.
    fn encrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; SRTP_TAG_LEN], SrtpError> {
        let nonce = GenericArray::from_slice(iv);
        let tag = match &self.cipher {
            Cipher::Gcm128(c) => c.encrypt_in_place_detached(nonce, aad, buf),
            Cipher::Gcm256(c) => c.encrypt_in_place_detached(nonce, aad, buf),
            // GCM packet paths never carry a CM cipher — see `Self::cm`.
            Cipher::Cm(_) => return Err(SrtpError::Cipher),
        }
        .map_err(|_| SrtpError::Cipher)?;
        let mut out = [0u8; SRTP_TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// AEAD-decrypt `buf` in place; `tag` is the detached 16-octet tag.
    /// Any verification failure maps to [`SrtpError::AuthFailed`].
    fn decrypt(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SrtpError> {
        debug_assert_eq!(tag.len(), SRTP_TAG_LEN);
        let nonce = GenericArray::from_slice(iv);
        let tag = GenericArray::from_slice(tag);
        match &self.cipher {
            Cipher::Gcm128(c) => c.decrypt_in_place_detached(nonce, aad, buf, tag),
            Cipher::Gcm256(c) => c.decrypt_in_place_detached(nonce, aad, buf, tag),
            // GCM packet paths never carry a CM cipher — see `Self::cm`.
            Cipher::Cm(_) => return Err(SrtpError::Cipher),
        }
        .map_err(|_| SrtpError::AuthFailed)
    }
}

/// RFC 3711 §4.3.3 AES-CM PRF with kdr = 0.
///
/// The PRF input block is the master salt (left-aligned, zero-padded to
/// 14 octets — the GCM transform's 12-octet master salt is padded on the
/// right, matching libsrtp and the interoperable implementations) XORed
/// with `label ‖ r`, where `r = index DIV kdr` is zero here, so the
/// label lands on input octet 7. Output blocks are `E(master_key, input
/// + i)` — the low 16 bits of the input are the block counter, per the
/// `IV = x·2¹⁶` definition.
fn aes_cm_prf(master_key: &[u8], master_salt: &[u8], label: u8, out: &mut [u8]) {
    debug_assert!(master_salt.len() <= 14);
    debug_assert!(matches!(master_key.len(), 16 | 32));
    let mut input = [0u8; 16];
    input[..master_salt.len()].copy_from_slice(master_salt);
    input[7] ^= label;

    macro_rules! run {
        ($cipher:expr) => {{
            let cipher = $cipher;
            for (i, chunk) in out.chunks_mut(16).enumerate() {
                input[14] = (i >> 8) as u8;
                input[15] = i as u8;
                let mut block = input;
                cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }};
    }
    match master_key.len() {
        16 => run!(Aes128::new(GenericArray::from_slice(master_key))),
        // AES_256_CM_PRF per RFC 6188: same construction, AES-256.
        _ => run!(Aes256::new(GenericArray::from_slice(master_key))),
    }
}

/// SRTP IV formation for AES-GCM (RFC 7714 §8.1, Figure 1):
/// `(00 00 ‖ SSRC ‖ ROC ‖ SEQ) XOR session_salt`.
fn rtp_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
    debug_assert_eq!(salt.len(), GCM_SALT_LEN);
    let mut iv = [0u8; 12];
    iv[..salt.len()].copy_from_slice(salt);
    xor(&mut iv[2..6], &ssrc.to_be_bytes());
    xor(&mut iv[6..10], &roc.to_be_bytes());
    xor(&mut iv[10..12], &seq.to_be_bytes());
    iv
}

/// SRTCP IV formation for AES-GCM (RFC 7714 §9.1, Figure 4):
/// `(00 00 ‖ SSRC ‖ 00 00 ‖ 0 ‖ 31-bit index) XOR session_salt`.
fn rtcp_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 12] {
    debug_assert_eq!(index & SRTCP_E_BIT, 0);
    debug_assert_eq!(salt.len(), GCM_SALT_LEN);
    let mut iv = [0u8; 12];
    iv[..salt.len()].copy_from_slice(salt);
    xor(&mut iv[2..6], &ssrc.to_be_bytes());
    xor(&mut iv[8..12], &index.to_be_bytes());
    iv
}

/// SRTP IV formation for AES-CM (RFC 3711 §4.1.1):
/// `(k_s·2¹⁶) ⊕ (SSRC·2⁶⁴) ⊕ (i·2¹⁶)` — i.e. the 14-octet salt followed
/// by two zero octets, XORed with `SSRC` at octets 4..8 and the 48-bit
/// `ROC‖SEQ` packet index at octets 8..14. The low 16 bits stay zero:
/// they are the keystream block counter.
fn cm_rtp_iv(salt: &[u8], ssrc: u32, index: u64) -> [u8; 16] {
    debug_assert_eq!(salt.len(), CM_SALT_LEN);
    let mut iv = [0u8; 16];
    iv[..salt.len()].copy_from_slice(salt);
    xor(&mut iv[4..8], &ssrc.to_be_bytes());
    xor(&mut iv[8..14], &index.to_be_bytes()[2..]);
    iv
}

/// SRTCP IV formation for AES-CM (RFC 3711 §4.1.1 with §3.4): the same
/// construction with the 31-bit SRTCP index as `i` — landing in octets
/// 10..14.
fn cm_rtcp_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 16] {
    debug_assert_eq!(index & SRTCP_E_BIT, 0);
    debug_assert_eq!(salt.len(), CM_SALT_LEN);
    let mut iv = [0u8; 16];
    iv[..salt.len()].copy_from_slice(salt);
    xor(&mut iv[4..8], &ssrc.to_be_bytes());
    xor(&mut iv[10..14], &index.to_be_bytes());
    iv
}

fn xor(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// Parse the fields SRTP needs out of an RTP packet header:
/// `(header_len, seq, ssrc)` where `header_len` covers the fixed header,
/// CSRC list, and the extension block if the X bit is set — i.e. the
/// AEAD associated-data region. Payload/padding semantics are left to
/// the RTP layer; here they are just bytes to encrypt.
fn rtp_header(buf: &[u8]) -> Result<(usize, u16, u32), SrtpError> {
    if buf.len() < 12 {
        return Err(SrtpError::TooShort);
    }
    if buf[0] >> 6 != 2 {
        return Err(SrtpError::Malformed);
    }
    let csrc = (buf[0] & 0x0f) as usize;
    let mut header_len = 12 + 4 * csrc;
    if buf.len() < header_len {
        return Err(SrtpError::Malformed);
    }
    if buf[0] & 0x10 != 0 {
        if buf.len() < header_len + 4 {
            return Err(SrtpError::Malformed);
        }
        let words = u16::from_be_bytes([buf[header_len + 2], buf[header_len + 3]]) as usize;
        header_len += 4 + 4 * words;
        if buf.len() < header_len {
            return Err(SrtpError::Malformed);
        }
    }
    let seq = u16::from_be_bytes([buf[2], buf[3]]);
    let ssrc = u32::from_be_bytes(buf[8..12].try_into().expect("slice len checked"));
    Ok((header_len, seq, ssrc))
}

/// Per-SSRC stream state. `rtp`/`rtcp` are index windows (see
/// [`IndexWindow`]); `rtcp_next` is the outbound SRTCP counter used on
/// the encrypt side only.
#[derive(Clone, Copy, Default)]
struct Stream {
    ssrc: u32,
    /// SRTP packet-index state: replay window + ROC estimate on the
    /// decrypt side, sent-index guard on the encrypt side.
    rtp: IndexWindow,
    /// SRTCP index state: replay window on the decrypt side. Unused on
    /// the encrypt side (SRTCP indices are counted, not estimated).
    rtcp: IndexWindow,
    /// Next outbound SRTCP index; [`SRTCP_INDEX_EXHAUSTED`] once spent.
    rtcp_next: u32,
}

/// The sliding 64-index window that serves both replay protection
/// (decrypt) and IV-reuse prevention (encrypt).
///
/// `highest` is the largest packet index authenticated (or sent) so far;
/// bit `i` of `bits` records whether index `highest - i` has been seen.
/// For SRTP the same `highest` doubles as the RFC 3711 Appendix-A state:
/// its high 32 bits are the ROC and its low 16 bits are `s_l`, since the
/// update rules there reduce to "keep the largest authenticated index".
#[derive(Clone, Copy, Default)]
struct IndexWindow {
    highest: Option<u64>,
    bits: u64,
}

impl IndexWindow {
    /// Receiver-side index estimate, RFC 3711 Appendix A: pick
    /// `v ∈ {ROC-1, ROC, ROC+1}` so the index stays closest to the last
    /// authenticated one.
    fn guess(&self, seq: u16) -> u64 {
        let Some(h) = self.highest else {
            // First observed packet: s_l initialises to its SEQ (§3.3.1).
            return seq as u64;
        };
        let roc = (h >> 16) as u32;
        let s_l = (h & 0xffff) as i32;
        let seq = seq as i32;
        let v = if s_l < 0x8000 {
            if seq - s_l > 0x8000 {
                roc.wrapping_sub(1)
            } else {
                roc
            }
        } else if s_l - 0x8000 > seq {
            roc.wrapping_add(1)
        } else {
            roc
        };
        ((v as u64) << 16) | (seq as u16) as u64
    }

    /// Sender-side index: the sender's own index is `ROC‖SEQ`, where ROC
    /// increments when the 16-bit sequence wraps. A SEQ far below the
    /// last-sent one means wraparound, never a step back — matching what
    /// the receiver's `guess` concludes for the same pair.
    fn send_index(&self, seq: u16) -> Result<u64, SrtpError> {
        match self.highest {
            None => Ok(seq as u64),
            Some(h) => {
                let roc = (h >> 16) as u32;
                let s_l = (h & 0xffff) as u16;
                let v = if seq < s_l && (s_l - seq) > 0x8000 {
                    roc.checked_add(1).ok_or(SrtpError::IndexExhausted)?
                } else {
                    roc
                };
                Ok(((v as u64) << 16) | seq as u64)
            }
        }
    }

    /// True if `index` is plausibly new: ahead of the window, or inside
    /// it and not yet marked.
    fn check(&self, index: u64) -> bool {
        match self.highest {
            None => true,
            Some(h) => {
                if index > h {
                    true
                } else {
                    let d = h - index;
                    d < REPLAY_WINDOW && self.bits & (1 << d) == 0
                }
            }
        }
    }

    /// Mark `index` as seen; call only after it authenticated (rx) or
    /// was actually emitted (tx).
    fn record(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.bits = 1;
            }
            Some(h) => {
                if index > h {
                    let shift = index - h;
                    self.bits = if shift >= REPLAY_WINDOW {
                        1
                    } else {
                        (self.bits << shift) | 1
                    };
                    self.highest = Some(index);
                } else {
                    let d = h - index;
                    if d < REPLAY_WINDOW {
                        self.bits |= 1 << d;
                    }
                }
            }
        }
    }
}

/// Fixed-capacity SSRC → [`Stream`] table; linear scan over a bounded
/// array, no allocation.
struct Streams {
    /// Sparse, grows with use — a 2048-entry fixed table would cost
    /// ~64KB per direction per transport even for one stream.
    slots: Vec<Option<Stream>>,
    /// Last-hit hint: within a fan-out pass every target sees the same
    /// SSRC, so the previous slot is overwhelmingly the one asked for.
    last: Option<u32>,
}

impl Streams {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            last: None,
        }
    }

    fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Slot index holding `ssrc`, checking the last-hit hint first.
    fn find(&self, ssrc: u32) -> Option<usize> {
        if let Some(i) = self.last
            && self
                .slots
                .get(i as usize)
                .and_then(|s| s.as_ref())
                .is_some_and(|st| st.ssrc == ssrc)
        {
            return Some(i as usize);
        }
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|st| st.ssrc == ssrc))
    }

    fn get(&self, ssrc: u32) -> Option<&Stream> {
        self.find(ssrc).and_then(|i| self.slots[i].as_ref())
    }

    /// Existing entry or a fresh one; [`SrtpError::TooManyStreams`] when
    /// the table is full (new SSRCs are refused rather than evicting
    /// live replay state).
    fn get_mut_or_insert(&mut self, ssrc: u32) -> Result<&mut Stream, SrtpError> {
        if let Some(i) = self.find(ssrc) {
            self.last = Some(i as u32);
            return Ok(self.slots[i].as_mut().expect("occupied slot"));
        }
        if self.slots.iter().filter(|s| s.is_some()).count() >= MAX_STREAMS {
            return Err(SrtpError::TooManyStreams);
        }
        // First empty slot, else grow.
        let i = match self.slots.iter().position(|s| s.is_none()) {
            Some(i) => i,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        self.slots[i] = Some(Stream {
            ssrc,
            ..Stream::default()
        });
        self.last = Some(i as u32);
        Ok(self.slots[i].as_mut().expect("just inserted"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(clean.len().is_multiple_of(2), "odd hex length");
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7714 §16/§17 session material: the vectors drive the packet
    /// layer with the session key/salt directly (no KDF step).
    const RFC_KEY_128: &str = "000102030405060708090a0b0c0d0e0f";
    const RFC_KEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const RFC_SALT: &str = "517569642070726f2071756f"; // "Quid pro quo"

    /// The RTP packet all RFC 7714 §16 vectors share.
    const RFC_RTP: &str = "8040f17b 8041f8d3 5501a0b2 47616c6c
                           69612065 7374206f 6d6e6973 20646976
                           69736120 696e2070 61727465 73207472
                           6573";

    /// The RTCP packet all RFC 7714 §17 vectors share.
    const RFC_RTCP: &str = "81c8000d 4d617273 4e545031 4e545032
                            52545020 0000042a 0000e930 4c756e61
                            deadbeef deadbeef deadbeef deadbeef
                            deadbeef";

    fn session_cipher(profile: SrtpProfile, key: &[u8], salt: &[u8]) -> SessionCipher {
        let mut session_salt = [0u8; CM_SALT_LEN];
        session_salt[..salt.len()].copy_from_slice(salt);
        let cipher = match profile {
            SrtpProfile::AEAD_AES_128_GCM => {
                Cipher::Gcm128(Aes128Gcm::new(GenericArray::from_slice(key)))
            }
            _ => Cipher::Gcm256(Aes256Gcm::new(GenericArray::from_slice(key))),
        };
        SessionCipher {
            cipher,
            salt: session_salt,
        }
    }

    /// An `Srtp` whose *session* keys are given directly — the shape the
    /// RFC 7714 vectors assume. Both directions share the same material
    /// so encrypt → decrypt round-trips work.
    fn session_srtp(profile: SrtpProfile, key: &[u8], salt: &[u8]) -> Srtp {
        Srtp {
            profile,
            rx: Dir {
                rtp: session_cipher(profile, key, salt),
                rtcp: session_cipher(profile, key, salt),
                streams: Streams::new(),
            },
            tx: Dir {
                rtp: session_cipher(profile, key, salt),
                rtcp: session_cipher(profile, key, salt),
                streams: Streams::new(),
            },
        }
    }

    fn gcm128() -> Srtp {
        session_srtp(
            SrtpProfile::AEAD_AES_128_GCM,
            &hex(RFC_KEY_128),
            &hex(RFC_SALT),
        )
    }

    fn gcm256() -> Srtp {
        session_srtp(
            SrtpProfile::AEAD_AES_256_GCM,
            &hex(RFC_KEY_256),
            &hex(RFC_SALT),
        )
    }

    /// Set the outbound SRTCP index for `ssrc` (test-only knob — the RFC
    /// vectors use a mid-session index).
    fn set_tx_rtcp_index(s: &mut Srtp, ssrc: u32, index: u32) {
        s.tx.streams.get_mut_or_insert(ssrc).unwrap().rtcp_next = index;
    }

    // ---------------------------------------------------------------
    // AES-CM helpers
    // ---------------------------------------------------------------

    /// The master material that RFC 3711 Appendix B.3 and libsrtp's
    /// `srtp_validate` self-test share.
    const CM_MASTER_KEY: &str = "E1F97A0D3E018BE0D64FA32C06DE4139";
    const CM_MASTER_SALT: &str = "0EC675AD498AFEEBB6960B3AABE6";

    /// An `Srtp` on `AES128_CM_SHA1_80` built through the real KDF path
    /// (`Dir::new`), with the same master key/salt in both directions so
    /// encrypt → decrypt round-trips work.
    fn cm_srtp() -> Srtp {
        let key = hex(CM_MASTER_KEY);
        let salt = hex(CM_MASTER_SALT);
        Srtp {
            profile: SrtpProfile::AES128_CM_SHA1_80,
            rx: Dir::new(SrtpProfile::AES128_CM_SHA1_80, &key, &salt).unwrap(),
            tx: Dir::new(SrtpProfile::AES128_CM_SHA1_80, &key, &salt).unwrap(),
        }
    }

    // ---------------------------------------------------------------
    // KDF
    // ---------------------------------------------------------------

    /// RFC 3711 Appendix B.3: AES-128 PRF, 14-octet master salt.
    #[test]
    fn kdf_rfc3711_b3() {
        let key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
        let salt = hex("0EC675AD498AFEEBB6960B3AABE6");

        let mut out = [0u8; 94];
        aes_cm_prf(&key, &salt, 0x00, &mut out[..16]);
        assert_eq!(&out[..16], &hex("C61E7A93744F39EE10734AFE3FF7A087")[..]);

        aes_cm_prf(&key, &salt, 0x02, &mut out[..14]);
        assert_eq!(&out[..14], &hex("30CBBC08863D8C85D49DB34A9AE1")[..]);

        // 94-octet auth key exercises the multi-block counter.
        aes_cm_prf(&key, &salt, 0x01, &mut out);
        assert_eq!(
            &out[..],
            &hex(
                "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCE
                  E049646C43D9327AD175578EF72270986371C10C9A369AC2F94A8C5FBCDDDC25
                  6D6E919A48B610EF17C2041E474035766B68642C59BBFC2F34DB60DBDFB2"
            )[..]
        );
    }

    /// RFC 6188 §7.2: AES-256 PRF, 14-octet master salt (vector via
    /// rtc-srtp's test suite, which reproduces the RFC).
    #[test]
    fn kdf_rfc6188_aes256() {
        let key = hex("F0F04914B513F2763A1B1FA130F10E2998F6F6E43E4309D1E622A0E332B9F1B6");
        let salt = hex("3B04803DE51EE7C96423AB5B78D2");

        let mut out = [0u8; 32];
        aes_cm_prf(&key, &salt, 0x00, &mut out);
        assert_eq!(
            &out[..],
            &hex("5BA1064E30EC51613CAD926C5A28EF731EC7FB397F70A960653CAF06554CD8C4")[..]
        );

        let mut salt_out = [0u8; 14];
        aes_cm_prf(&key, &salt, 0x02, &mut salt_out);
        assert_eq!(&salt_out[..], &hex("FA31791685CA444A9E07C6C64E93")[..]);
    }

    /// GCM master-salt case: 12-octet salt right-padded to 14. Expected
    /// values computed with `openssl enc -aes-*-ctr` on the libsrtp GCM
    /// test material (`test_key_gcm`): master key 0001.., salt a0a1..ab.
    #[test]
    fn kdf_gcm_master_salt() {
        let key128 = hex(RFC_KEY_128);
        let key256 = hex(RFC_KEY_256);
        let salt = hex("a0a1a2a3a4a5a6a7a8a9aaab");

        let mut out = [0u8; 32];

        aes_cm_prf(&key128, &salt, LABEL_RTP_KEY, &mut out[..16]);
        assert_eq!(&out[..16], &hex("077c6143cb221bc355ff23d5f984a16e")[..]);
        aes_cm_prf(&key128, &salt, LABEL_RTP_SALT, &mut out[..12]);
        assert_eq!(&out[..12], &hex("9af3e95364ebac9c99c5a7c4")[..]);
        aes_cm_prf(&key128, &salt, LABEL_RTCP_KEY, &mut out[..16]);
        assert_eq!(&out[..16], &hex("615dcd9042600666f6fd4d9e4fe4519f")[..]);
        aes_cm_prf(&key128, &salt, LABEL_RTCP_SALT, &mut out[..12]);
        assert_eq!(&out[..12], &hex("fcca937b9112a500dac72269")[..]);

        aes_cm_prf(&key256, &salt, LABEL_RTP_KEY, &mut out);
        assert_eq!(
            &out[..],
            &hex("b7a435ce454463b760dc82c838468a115c699625af4b93a0f8220a2a6119c5d0")[..]
        );
        aes_cm_prf(&key256, &salt, LABEL_RTCP_KEY, &mut out);
        assert_eq!(
            &out[..],
            &hex("3c90f52a0a13ff8a853397cadc245b9eac76b36edb4a6062bf624aa1174eebf2")[..]
        );
        aes_cm_prf(&key256, &salt, LABEL_RTP_SALT, &mut out[..12]);
        assert_eq!(&out[..12], &hex("944bd21c268a962cd09c674a")[..]);
        aes_cm_prf(&key256, &salt, LABEL_RTCP_SALT, &mut out[..12]);
        assert_eq!(&out[..12], &hex("258c540cf38ddd40848ceaed")[..]);
    }

    /// End-to-end material split + derivation: feed libsrtp's GCM test
    /// material as the client half and confirm the rx session key/salt.
    #[test]
    fn keying_material_split_and_derive() {
        // client_key ‖ server_key ‖ client_salt ‖ server_salt
        let mut material = Vec::new();
        material.extend_from_slice(&hex(RFC_KEY_128)); // client key
        material.extend_from_slice(&hex("202122232425262728292a2b2c2d2e2f")); // server key
        material.extend_from_slice(&hex("a0a1a2a3a4a5a6a7a8a9aaab")); // client salt
        material.extend_from_slice(&hex("b0b1b2b3b4b5b6b7b8b9babb")); // server salt

        let s = Srtp::from_keying_material(SrtpProfile::AEAD_AES_128_GCM, &material)
            .expect("material is well-formed");
        // rx (client-write half) must have derived the openssl-computed
        // session salt for label 0x02 on that master salt.
        assert_eq!(s.rx.rtp.salt(), &hex("9af3e95364ebac9c99c5a7c4")[..]);
        assert_eq!(s.rx.rtcp.salt(), &hex("fcca937b9112a500dac72269")[..]);
        // tx derives from the *server* half — must differ.
        assert_ne!(s.tx.rtp.salt(), s.rx.rtp.salt());
    }

    #[test]
    fn from_keying_material_validation() {
        // All three profiles accepted at their RFC 5764 lengths.
        assert!(Srtp::from_keying_material(SrtpProfile::AES128_CM_SHA1_80, &[0u8; 60]).is_ok());
        assert!(Srtp::from_keying_material(SrtpProfile::AEAD_AES_128_GCM, &[0u8; 56]).is_ok());
        assert!(Srtp::from_keying_material(SrtpProfile::AEAD_AES_256_GCM, &[0u8; 88]).is_ok());
        // Lengths off by the per-profile `2 * (key + salt)` split fail.
        assert!(matches!(
            Srtp::from_keying_material(SrtpProfile::AEAD_AES_128_GCM, &[0u8; 55]),
            Err(SrtpError::BadKeyingMaterialLen(55))
        ));
        // GCM material length presented as CM (and vice versa) fails.
        assert!(matches!(
            Srtp::from_keying_material(SrtpProfile::AES128_CM_SHA1_80, &[0u8; 56]),
            Err(SrtpError::BadKeyingMaterialLen(56))
        ));
        assert!(matches!(
            Srtp::from_keying_material(SrtpProfile::AEAD_AES_128_GCM, &[0u8; 60]),
            Err(SrtpError::BadKeyingMaterialLen(60))
        ));
    }

    // ---------------------------------------------------------------
    // RFC 7714 packet vectors
    // ---------------------------------------------------------------

    /// §16.1.1/§16.1.2: AEAD_AES_128_GCM encrypt + decrypt.
    #[test]
    fn rfc7714_rtp_128() {
        let want = hex("8040f17b 8041f8d3 5501a0b2 f24de3a3
             fb34de6c acba861c 9d7e4bca be633bd5
             0d294e6f 42a5f47a 51c7d19b 36de3adf
             8833899d 7f27beb1 6a9152cf 765ee439
             0cce");
        let plain = hex(RFC_RTP);

        let mut enc = gcm128();
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = enc.encrypt_rtp(&mut buf, plain.len()).unwrap();
        assert_eq!(&buf[..n], &want[..]);

        let mut dec = gcm128();
        let mut wire = want.clone();
        let n = dec.decrypt_rtp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);

        // Second decrypt of the identical packet → replay rejection.
        let mut wire = want;
        assert!(matches!(
            dec.decrypt_rtp(&mut wire),
            Err(SrtpError::Replayed)
        ));
    }

    /// §16.2.1/§16.2.2: AEAD_AES_256_GCM encrypt + decrypt.
    #[test]
    fn rfc7714_rtp_256() {
        let want = hex("8040f17b 8041f8d3 5501a0b2 32b1de78
             a822fe12 ef9f78fa 332e33aa b1801238
             9a58e2f3 b50b2a02 76ffae0f 1ba63799
             b87b7aa3 db36dfff d6b0f9bb 7878d7a7
             6c13");
        let plain = hex(RFC_RTP);

        let mut enc = gcm256();
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = enc.encrypt_rtp(&mut buf, plain.len()).unwrap();
        assert_eq!(&buf[..n], &want[..]);

        let mut dec = gcm256();
        let mut wire = want;
        let n = dec.decrypt_rtp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);
    }

    /// §17.1: SRTCP AEAD_AES_128_GCM encryption (E-flag set).
    #[test]
    fn rfc7714_srtcp_128_encrypt() {
        let want = hex("81c8000d 4d617273 63e94885 dcdab67c
             a727d766 2f6b7e99 7ff5c0f7 6c06f32d
             c676a5f1 730d6fda 4ce09b46 86303ded
             0bb9275b c84aa458 96cf4d2f c5abf872
             45d9eade 800005d4");
        let plain = hex(RFC_RTCP);
        let ssrc = 0x4d617273;

        let mut s = gcm128();
        set_tx_rtcp_index(&mut s, ssrc, 0x5d4);
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = s.encrypt_rtcp(&mut buf, plain.len()).unwrap();
        assert_eq!(&buf[..n], &want[..]);
    }

    /// §17.2: SRTCP AEAD_AES_256_GCM verification + decryption.
    #[test]
    fn rfc7714_srtcp_256_decrypt() {
        let wire = hex("81c8000d 4d617273 d50ae4d1 f5ce5d30
             4ba297e4 7d470c28 2c3ece5d bffe0a50
             a2eaa5c1 110555be 8415f658 c61de047
             6f1b6fad 1d1eb30c 4446839f 57ff6f6c
             b26ac3be 800005d4");
        let mut s = gcm256();
        let mut buf = wire;
        let n = s.decrypt_rtcp(&mut buf).unwrap();
        assert_eq!(&buf[..n], &hex(RFC_RTCP)[..]);
    }

    /// §17.3: SRTCP AEAD_AES_128_GCM tag-only (E-flag clear).
    #[test]
    fn rfc7714_srtcp_128_tag_only() {
        let want = hex("81c8000d 4d617273 4e545031 4e545032
             52545020 0000042a 0000e930 4c756e61
             deadbeef deadbeef deadbeef deadbeef
             deadbeef 841dd968 3dd78ec9 2ae58790
             125f62b3 000005d4");
        let plain = hex(RFC_RTCP);
        let ssrc = 0x4d617273;

        let mut s = gcm128();
        set_tx_rtcp_index(&mut s, ssrc, 0x5d4);
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = s.seal_rtcp_gcm(&mut buf, plain.len(), false).unwrap();
        assert_eq!(&buf[..n], &want[..]);

        // ...and the same packet verifies on the receive side.
        let mut rx = gcm128();
        let n = rx.decrypt_rtcp(&mut buf[..n]).unwrap();
        assert_eq!(&buf[..n], &plain[..]);
    }

    /// §17.4: SRTCP AEAD_AES_256_GCM tag-only verification.
    #[test]
    fn rfc7714_srtcp_256_tag_only_decrypt() {
        let wire = hex("81c8000d 4d617273 4e545031 4e545032
             52545020 0000042a 0000e930 4c756e61
             deadbeef deadbeef deadbeef deadbeef
             deadbeef 91db4afb feee5a97 8fab4393
             ed2615fe 000005d4");
        let mut s = gcm256();
        let mut buf = wire;
        let n = s.decrypt_rtcp(&mut buf).unwrap();
        assert_eq!(&buf[..n], &hex(RFC_RTCP)[..]);
    }

    // ---------------------------------------------------------------
    // RFC 3711 AES-CM vectors
    // ---------------------------------------------------------------

    /// Appendix B.2: AES-CM keystream for session key
    /// 2B7E…/salt F0F1…FCFD with SSRC = 0 and index = 0 — the IV is then
    /// just the shifted salt `salt‖0000`, and the ciphertext of a zero
    /// payload is the keystream itself.
    #[test]
    fn cm_keystream_rfc3711_b2() {
        let cm = CmSha1 {
            enc: hex("2B7E151628AED2A6ABF7158809CF4F3C")
                .try_into()
                .unwrap(),
            // The keystream doesn't touch the auth key.
            mac: <Hmac<Sha1> as Mac>::new_from_slice(&[0u8; 20]).unwrap(),
        };
        let salt = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");
        let iv = cm_rtp_iv(&salt, 0, 0);
        // SSRC and index are zero, so the IV is the shifted salt.
        assert_eq!(&iv[..], &hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000")[..]);

        // First three keystream blocks of the RFC's table.
        let mut buf = vec![0u8; 48];
        cm.keystream(&iv, &mut buf);
        assert_eq!(
            &buf[..],
            &hex("E03EAD0935C95E80E166B16DD92B4EB4
                  D23513162B02D0F72A43A2FE4A5F97AB
                  41E95B3BB0A2E8DD477901E4FCA894C0")[..]
        );

        // The segment's tail — blocks 0xFEFF/0xFF00/0xFF01, which the
        // RFC notes coincide with the RFC 3686 F.5.1 AES-CTR vectors.
        let mut seg = vec![0u8; 65282 * 16];
        cm.keystream(&iv, &mut seg);
        assert_eq!(
            &seg[0xFEFF * 16..0xFF00 * 16],
            &hex("EC8CDF7398607CB0F2D21675EA9EA1E4")[..]
        );
        assert_eq!(
            &seg[0xFF00 * 16..0xFF01 * 16],
            &hex("362B7C3C6773516318A077D7FC5073AE")[..]
        );
        assert_eq!(
            &seg[0xFF01 * 16..],
            &hex("6A2CC3787889374FBEB4C81B17BA6C44")[..]
        );
    }

    /// libsrtp `srtp_validate` self-test: SRTP AES_CM_SHA1_80, SSRC
    /// 0xcafebabe, SEQ 0x1234, ROC 0. End-to-end known-answer through
    /// the real KDF — encrypted payload plus truncated HMAC-SHA1 tag.
    #[test]
    fn cm_rtp_libsrtp_vector() {
        let plain = hex("800f1234 decafbad cafebabe abababab abababab abababab abababab");
        let want = hex("800f1234 decafbad cafebabe 4e55dc4c e79978d8
                        8ca4d215 949d2402 b78d6acc 99ea179b 8dbb");

        let mut tx = cm_srtp();
        let mut buf = [0u8; 128];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = tx.encrypt_rtp(&mut buf, plain.len()).unwrap();
        assert_eq!(n, plain.len() + CM_TAG_LEN);
        assert_eq!(&buf[..n], &want[..]);

        let mut rx = cm_srtp();
        let mut wire = want.clone();
        let n = rx.decrypt_rtp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);

        // Replayed → rejected.
        let mut wire = want;
        assert!(matches!(
            rx.decrypt_rtp(&mut wire),
            Err(SrtpError::Replayed)
        ));
    }

    /// libsrtp `srtp_validate` self-test: SRTCP AES_CM_SHA1_80 — the
    /// E/index word precedes the 10-octet tag. (libsrtp's first
    /// protected SRTCP packet carries index 1.)
    #[test]
    fn cm_rtcp_libsrtp_vector() {
        let plain = hex("81c8000b cafebabe abababab abababab abababab abababab");
        let want = hex("81c8000b cafebabe 7128035b e487b9bd bef89041
                        f977a5a8 80000001 993e08cd 54d6c123 0798");
        let ssrc = 0xcafebabe;

        let mut tx = cm_srtp();
        set_tx_rtcp_index(&mut tx, ssrc, 1);
        let mut buf = [0u8; 128];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = tx.encrypt_rtcp(&mut buf, plain.len()).unwrap();
        assert_eq!(n, plain.len() + CM_SRTCP_TRAILER_LEN);
        assert_eq!(&buf[..n], &want[..]);

        let mut rx = cm_srtp();
        let mut wire = want;
        let n = rx.decrypt_rtcp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);
    }

    /// Pin the CM IV layout for a nonzero SSRC and ROC (the fields the
    /// keystream mixes in): `iv = (salt‖00 00) ⊕ (00*4 ‖ SSRC ‖ i ‖
    /// 00 00)`, computed field-by-field rather than as a magic constant.
    #[test]
    fn cm_iv_formation() {
        let salt = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");

        // SRTP: 48-bit index (ROC‖SEQ) lands in octets 8..14.
        let iv = cm_rtp_iv(&salt, 0x11223344, 0x0000_0005_0007);
        let mut mask = [0u8; 16];
        mask[4..8].copy_from_slice(&0x11223344u32.to_be_bytes());
        mask[8..14].copy_from_slice(&0x0000_0005_0007u64.to_be_bytes()[2..]);
        let mut expect = [0u8; 16];
        expect[..14].copy_from_slice(&salt);
        xor(&mut expect, &mask);
        assert_eq!(iv, expect);

        // SRTCP: the 31-bit index lands in octets 10..14.
        let iv = cm_rtcp_iv(&salt, 0x11223344, 0x0badf00d);
        let mut mask = [0u8; 16];
        mask[4..8].copy_from_slice(&0x11223344u32.to_be_bytes());
        mask[10..14].copy_from_slice(&0x0badf00du32.to_be_bytes());
        let mut expect = [0u8; 16];
        expect[..14].copy_from_slice(&salt);
        xor(&mut expect, &mask);
        assert_eq!(iv, expect);
    }

    /// Minimal RTP packet builder: fixed 12-byte header + payload byte.
    fn rtp_packet(seq: u16, ssrc: u32, payload: u8) -> [u8; 13] {
        let mut p = [0u8; 13];
        p[0] = 0x80;
        p[1] = 96;
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p[8..12].copy_from_slice(&ssrc.to_be_bytes());
        p[12] = payload;
        p
    }

    fn encrypt(s: &mut Srtp, seq: u16, ssrc: u32, payload: u8) -> Vec<u8> {
        let pkt = rtp_packet(seq, ssrc, payload);
        let mut buf = [0u8; 64];
        buf[..13].copy_from_slice(&pkt);
        let n = s.encrypt_rtp(&mut buf, 13).unwrap();
        buf[..n].to_vec()
    }

    /// Sequence wrap 65535 → 0 advances the ROC on both sides.
    #[test]
    fn roc_rollover() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        let ssrc = 0x12345678;

        let mut last_plain = None;
        for seq in [65534u16, 65535, 0, 1, 2] {
            let wire = encrypt(&mut tx, seq, ssrc, seq as u8);
            let mut buf = wire;
            let n = rx.decrypt_rtp(&mut buf).unwrap();
            assert_eq!(&buf[..n], &rtp_packet(seq, ssrc, seq as u8)[..]);
            last_plain = Some(n);
        }
        let _ = last_plain;

        // After the wrap both sides sit on ROC 1.
        let rx_state = rx.rx.streams.get(ssrc).unwrap();
        assert_eq!(rx_state.rtp.highest, Some((1 << 16) | 2));
        let tx_state = tx.tx.streams.get(ssrc).unwrap();
        assert_eq!(tx_state.rtp.highest, Some((1 << 16) | 2));
    }

    /// A packet straddling the wrap boundary that arrives reordered
    /// (65535 after 0) still authenticates via the ROC-1 estimate.
    #[test]
    fn roc_rollover_reordered() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        let ssrc = 0x11111111;

        // Wire order on the sender: 65533, 65534, 65535, 0, 1.
        let sent: Vec<(Vec<u8>, u16, u8)> = [
            (65533u16, 0x11u8),
            (65534, 0x22),
            (65535, 0x33),
            (0, 0x44),
            (1, 0x55),
        ]
        .iter()
        .map(|&(seq, p)| (encrypt(&mut tx, seq, ssrc, p), seq, p))
        .collect();

        // Deliver 65535, 0, 1 (the wrap), then stragglers 65534 and
        // 65533 from the previous cycle — each must be estimated at
        // ROC-1 and still authenticate.
        for i in [2usize, 3, 4, 1, 0] {
            let (wire, seq, payload) = &sent[i];
            let mut buf = wire.clone();
            let n = rx.decrypt_rtp(&mut buf).unwrap();
            assert_eq!(&buf[..n], &rtp_packet(*seq, ssrc, *payload)[..]);
        }
        assert_eq!(
            rx.rx.streams.get(ssrc).unwrap().rtp.highest,
            Some((1 << 16) | 1)
        );
    }

    /// Duplicate and too-old packets are rejected; in-window reordering
    /// is accepted.
    #[test]
    fn replay_protection() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        let ssrc = 0x42;

        let wires: Vec<Vec<u8>> = (0u16..70)
            .map(|s| encrypt(&mut tx, s, ssrc, s as u8))
            .collect();

        // Deliver 0..69 to rx.
        for w in &wires {
            let mut b = w.clone();
            rx.decrypt_rtp(&mut b).unwrap();
        }
        // Duplicate of the most recent → replayed.
        let mut dup = wires[69].clone();
        assert!(matches!(rx.decrypt_rtp(&mut dup), Err(SrtpError::Replayed)));
        // seq 0 is now 69 behind the window (>64) → replayed/too old.
        let mut old = wires[0].clone();
        assert!(matches!(rx.decrypt_rtp(&mut old), Err(SrtpError::Replayed)));

        // In-window reorder: fresh pair, deliver 5 then 3.
        let mut tx = gcm128();
        let mut rx = gcm128();
        let w3 = encrypt(&mut tx, 3, ssrc, 0);
        let w5 = encrypt(&mut tx, 5, ssrc, 0);
        let mut b5 = w5;
        rx.decrypt_rtp(&mut b5).unwrap();
        let mut b3 = w3.clone();
        rx.decrypt_rtp(&mut b3).unwrap();
        // …but again → replayed.
        let mut b3_again = w3;
        assert!(matches!(
            rx.decrypt_rtp(&mut b3_again),
            Err(SrtpError::Replayed)
        ));
    }

    /// SRTCP indices are counted per SSRC: second send on the same SSRC
    /// gets index+1; a replayed SRTCP packet is rejected.
    #[test]
    fn srtcp_index_and_replay() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        let ssrc = 0x4d617273;
        set_tx_rtcp_index(&mut tx, ssrc, 0x5d4);

        let plain = hex(RFC_RTCP);
        let mut wires = Vec::new();
        for _ in 0..3 {
            let mut buf = [0u8; 512];
            buf[..plain.len()].copy_from_slice(&plain);
            let n = tx.encrypt_rtcp(&mut buf, plain.len()).unwrap();
            wires.push(buf[..n].to_vec());
        }
        // Indices must be consecutive.
        for (i, w) in wires.iter().enumerate() {
            let idx = u32::from_be_bytes(w[w.len() - 4..].try_into().unwrap()) & !SRTCP_E_BIT;
            assert_eq!(idx, 0x5d4 + i as u32);
        }
        for w in &wires {
            let mut b = w.clone();
            let n = rx.decrypt_rtcp(&mut b).unwrap();
            assert_eq!(&b[..n], &plain[..]);
        }
        let mut dup = wires[0].clone();
        assert!(matches!(
            rx.decrypt_rtcp(&mut dup),
            Err(SrtpError::Replayed)
        ));
    }

    // ---------------------------------------------------------------
    // Round-trips and failure modes
    // ---------------------------------------------------------------

    /// Full round-trip through `from_keying_material`: a client view
    /// (swapped halves) must interoperate with the server view.
    #[test]
    fn keying_material_roundtrip() {
        let mut material = Vec::new();
        material.extend_from_slice(&hex(RFC_KEY_128)); // client key
        material.extend_from_slice(&hex("202122232425262728292a2b2c2d2e2f")); // server key
        material.extend_from_slice(&hex("a0a1a2a3a4a5a6a7a8a9aaab")); // client salt
        material.extend_from_slice(&hex("b0b1b2b3b4b5b6b7b8b9babb")); // server salt

        let mut server =
            Srtp::from_keying_material(SrtpProfile::AEAD_AES_128_GCM, &material).unwrap();
        // Client view: the mirror — it decrypts with the server-write
        // half and encrypts with its own client-write half.
        let mut client =
            Srtp::from_keying_material_as(SrtpProfile::AEAD_AES_128_GCM, &material, Role::Client)
                .unwrap();

        let ssrc = 0xabcd;
        let wire = encrypt(&mut client, 7, ssrc, 0x99);
        let mut b = wire;
        let n = server.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(7, ssrc, 0x99)[..]);

        let wire = encrypt(&mut server, 9, ssrc, 0x77);
        let mut b = wire;
        let n = client.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(9, ssrc, 0x77)[..]);
    }

    /// Send-side IV reuse guard: the same SEQ under one SSRC is refused.
    #[test]
    fn send_index_reuse_refused() {
        let mut tx = gcm128();
        let ssrc = 0x5;
        let _w = encrypt(&mut tx, 100, ssrc, 0);
        assert!(matches!(
            {
                let pkt = rtp_packet(100, ssrc, 0);
                let mut buf = [0u8; 64];
                buf[..13].copy_from_slice(&pkt);
                tx.encrypt_rtp(&mut buf, 13)
            },
            Err(SrtpError::IndexReuse)
        ));
    }

    /// Bit-flipped packets fail authentication and do not poison the
    /// replay state: the next legitimate packet still decrypts.
    #[test]
    fn tampered_packet_rejected() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        let ssrc = 0x7777;

        let good = encrypt(&mut tx, 1, ssrc, 0x01);
        let next = encrypt(&mut tx, 2, ssrc, 0x02);

        let mut bad = good.clone();
        bad[20] ^= 0x01; // flip a ciphertext byte
        assert!(matches!(
            rx.decrypt_rtp(&mut bad),
            Err(SrtpError::AuthFailed)
        ));

        let mut bad_tag = good;
        let l = bad_tag.len();
        bad_tag[l - 1] ^= 0x80; // flip a tag byte
        assert!(matches!(
            rx.decrypt_rtp(&mut bad_tag),
            Err(SrtpError::AuthFailed)
        ));

        // State not poisoned: seq 2 still decrypts.
        let mut b = next;
        let n = rx.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(2, ssrc, 0x02)[..]);
    }

    /// Malformed and truncated inputs error out; nothing panics.
    #[test]
    fn malformed_and_truncated() {
        let mut rx = gcm128();
        let mut tx = gcm128();

        // Empty / tiny buffers.
        assert!(matches!(rx.decrypt_rtp(&mut []), Err(SrtpError::TooShort)));
        assert!(matches!(
            rx.decrypt_rtp(&mut [0u8; 27]),
            Err(SrtpError::TooShort)
        ));
        assert!(matches!(rx.decrypt_rtcp(&mut []), Err(SrtpError::TooShort)));
        assert!(matches!(
            rx.decrypt_rtcp(&mut [0u8; 27]),
            Err(SrtpError::TooShort)
        ));

        // Bad RTP version.
        let mut v1 = encrypt(&mut tx, 1, 0x9, 0);
        v1[0] = 0x40;
        assert!(matches!(rx.decrypt_rtp(&mut v1), Err(SrtpError::Malformed)));

        // Every truncation of a valid protected packet must fail cleanly.
        let good = encrypt(&mut tx, 2, 0x9, 0);
        for cut in 0..good.len() {
            let mut b = good[..cut].to_vec();
            let _ = rx.decrypt_rtp(&mut b); // must not panic
        }

        // Header that claims an extension running past the packet.
        let mut ext_lie = rtp_packet(3, 0x9, 0).to_vec();
        ext_lie[0] = 0x90; // X bit set
        ext_lie.extend_from_slice(&[0xbe, 0xde, 0x00, 0xff]); // ext claims 255*4 bytes
        let n = ext_lie.len();
        ext_lie.resize(n + SRTP_TAG_LEN, 0);
        // Parse succeeds on the extended region (tag bytes serve as ext
        // data) or fails Malformed — either way no panic; with the ext
        // region overlapping the tag, auth must fail.
        let mut buf = [0u8; 128];
        buf[..ext_lie.len()].copy_from_slice(&ext_lie);
        // encrypt it as-is (treating it as a packet to send) — parse must
        // fail because claimed header runs past len.
        let res = tx.encrypt_rtp(&mut buf, n);
        assert!(matches!(res, Err(SrtpError::Malformed)));

        // encrypt with no room for the tag.
        let pkt = rtp_packet(4, 0x9, 0);
        let mut tight = [0u8; 13];
        tight.copy_from_slice(&pkt);
        assert!(matches!(
            tx.encrypt_rtp(&mut tight, 13),
            Err(SrtpError::BufferTooSmall)
        ));
        assert!(matches!(
            tx.encrypt_rtcp(&mut tight, 13),
            Err(SrtpError::BufferTooSmall)
        ));
    }

    /// The per-SSRC table is bounded: streams beyond MAX_STREAMS are
    /// refused on both directions.
    #[test]
    fn ssrc_table_bounded() {
        let mut tx = gcm128();
        let mut rx = gcm128();
        for ssrc in 0..MAX_STREAMS as u32 {
            let w = encrypt(&mut tx, 1, ssrc, 0);
            let mut b = w;
            rx.decrypt_rtp(&mut b).unwrap();
        }
        assert_eq!(rx.rx.streams.len(), MAX_STREAMS);
        assert_eq!(tx.tx.streams.len(), MAX_STREAMS);

        // Outbound: a fresh SSRC can't be allocated.
        let pkt = rtp_packet(2, 0xFFFF, 0);
        let mut buf = [0u8; 64];
        buf[..13].copy_from_slice(&pkt);
        assert!(matches!(
            tx.encrypt_rtp(&mut buf, 13),
            Err(SrtpError::TooManyStreams)
        ));

        // Inbound: a valid packet for a new SSRC authenticates fine but
        // can't be tracked — dropped, never panics.
        let mut tx_other = gcm128();
        let w = encrypt(&mut tx_other, 1, 0xFFFF, 0);
        let mut b = w;
        assert!(matches!(
            rx.decrypt_rtp(&mut b),
            Err(SrtpError::TooManyStreams)
        ));
    }

    // ---------------------------------------------------------------
    // AES-CM round-trips and failure modes
    // ---------------------------------------------------------------

    /// Full round-trip through `from_keying_material` on the CM profile:
    /// a client view (swapped halves) must interoperate with the server
    /// view, in both directions, RTP and RTCP.
    #[test]
    fn cm_keying_material_roundtrip() {
        // client_key ‖ server_key ‖ client_salt ‖ server_salt
        let mut material = Vec::new();
        material.extend_from_slice(&hex(CM_MASTER_KEY)); // client key
        material.extend_from_slice(&hex("202122232425262728292a2b2c2d2e2f")); // server key
        material.extend_from_slice(&hex(CM_MASTER_SALT)); // client salt
        material.extend_from_slice(&hex("b0b1b2b3b4b5b6b7b8b9babbbcbd")); // server salt

        let mut server =
            Srtp::from_keying_material(SrtpProfile::AES128_CM_SHA1_80, &material).unwrap();
        let mut client = Srtp::from_keying_material_as(
            SrtpProfile::AES128_CM_SHA1_80,
            &material,
            Role::Client,
        )
        .unwrap();

        let ssrc = 0xabcd;
        let wire = encrypt(&mut client, 7, ssrc, 0x99);
        // Client → server: header stays cleartext, +10-octet tag.
        assert_eq!(wire.len(), 13 + CM_TAG_LEN);
        assert_eq!(&wire[..12], &rtp_packet(7, ssrc, 0x99)[..12]);
        let mut b = wire;
        let n = server.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(7, ssrc, 0x99)[..]);

        let wire = encrypt(&mut server, 9, ssrc, 0x77);
        let mut b = wire;
        let n = client.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(9, ssrc, 0x77)[..]);

        // RTCP both ways: E bit set, body encrypted, index advances.
        let plain = hex(RFC_RTCP);
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = server.encrypt_rtcp(&mut buf, plain.len()).unwrap();
        let esrtcp = u32::from_be_bytes(buf[n - 14..n - 10].try_into().unwrap());
        assert_eq!(esrtcp, SRTCP_E_BIT); // E set, index 0
        // Body must actually be encrypted.
        assert_ne!(&buf[8..n - 14], &plain[8..]);
        let mut wire = buf[..n].to_vec();
        let n = client.decrypt_rtcp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);

        buf[..plain.len()].copy_from_slice(&plain);
        let n = client.encrypt_rtcp(&mut buf, plain.len()).unwrap();
        let mut wire = buf[..n].to_vec();
        let n = server.decrypt_rtcp(&mut wire).unwrap();
        assert_eq!(&wire[..n], &plain[..]);
    }

    /// Tampered packets fail authentication and do not poison the
    /// replay state; duplicates are replayed; send-side SEQ reuse is
    /// refused (CM keystream reuse is a two-time pad).
    #[test]
    fn cm_failure_modes() {
        let mut tx = cm_srtp();
        let mut rx = cm_srtp();
        let ssrc = 0x7777;

        let good = encrypt(&mut tx, 1, ssrc, 0x01);
        let next = encrypt(&mut tx, 2, ssrc, 0x02);

        let mut bad = good.clone();
        bad[15] ^= 0x01; // flip a ciphertext byte
        assert!(matches!(
            rx.decrypt_rtp(&mut bad),
            Err(SrtpError::AuthFailed)
        ));

        let mut bad_tag = good.clone();
        let l = bad_tag.len();
        bad_tag[l - 1] ^= 0x80; // flip a tag byte
        assert!(matches!(
            rx.decrypt_rtp(&mut bad_tag),
            Err(SrtpError::AuthFailed)
        ));

        // Untouched replay: authenticates, then the window rejects it —
        // but only after it was first accepted. Deliver it once, then
        // replay.
        let mut b = good.clone();
        rx.decrypt_rtp(&mut b).unwrap();
        let mut dup = good;
        assert!(matches!(rx.decrypt_rtp(&mut dup), Err(SrtpError::Replayed)));

        // State not poisoned: seq 2 still decrypts.
        let mut b = next;
        let n = rx.decrypt_rtp(&mut b).unwrap();
        assert_eq!(&b[..n], &rtp_packet(2, ssrc, 0x02)[..]);

        // Same SEQ again on the send side → keystream-reuse refusal.
        assert!(matches!(
            {
                let pkt = rtp_packet(2, ssrc, 0);
                let mut buf = [0u8; 64];
                buf[..13].copy_from_slice(&pkt);
                tx.encrypt_rtp(&mut buf, 13)
            },
            Err(SrtpError::IndexReuse)
        ));

        // Every truncation of a valid packet fails cleanly.
        let good = encrypt(&mut tx, 5, ssrc, 0x05);
        for cut in 0..good.len() {
            let mut b = good[..cut].to_vec();
            let _ = rx.decrypt_rtp(&mut b); // must not panic
        }
    }

    /// SRTCP under CM: indices count per SSRC starting at 0 with the E
    /// bit set; a replayed packet is dropped; the E=0 (authenticate-only)
    /// form round-trips with the body left in cleartext.
    #[test]
    fn cm_srtcp_index_e0_and_replay() {
        let mut tx = cm_srtp();
        let mut rx = cm_srtp();
        let plain = hex(RFC_RTCP); // SSRC 0x4d617273

        // Two E=1 packets: indices 0, 1.
        let mut wires = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 512];
            buf[..plain.len()].copy_from_slice(&plain);
            let n = tx.encrypt_rtcp(&mut buf, plain.len()).unwrap();
            wires.push(buf[..n].to_vec());
        }
        for (i, w) in wires.iter().enumerate() {
            // E/index word sits before the tag: n-14..n-10.
            let idx = u32::from_be_bytes(w[w.len() - 14..w.len() - 10].try_into().unwrap());
            assert_eq!(idx, SRTCP_E_BIT | i as u32);
            let mut b = w.clone();
            let n = rx.decrypt_rtcp(&mut b).unwrap();
            assert_eq!(&b[..n], &plain[..]);
        }
        let mut dup = wires[0].clone();
        assert!(matches!(
            rx.decrypt_rtcp(&mut dup),
            Err(SrtpError::Replayed)
        ));

        // E=0 form: body stays plaintext, still authenticated.
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = tx.seal_rtcp_cm(&mut buf, plain.len(), false).unwrap();
        let esrtcp = u32::from_be_bytes(buf[n - 14..n - 10].try_into().unwrap());
        assert_eq!(esrtcp, 2); // E clear, index 2
        assert_eq!(&buf[8..n - 14], &plain[8..]); // body not encrypted
        let mut wire = buf[..n].to_vec();
        let m = rx.decrypt_rtcp(&mut wire).unwrap();
        assert_eq!(&wire[..m], &plain[..]);

        // A tampered E=0 packet fails authentication — the tag covers
        // the plaintext body too.
        let mut buf = [0u8; 512];
        buf[..plain.len()].copy_from_slice(&plain);
        let n = tx.seal_rtcp_cm(&mut buf, plain.len(), false).unwrap();
        let mut wire = buf[..n].to_vec();
        wire[10] ^= 0x01;
        assert!(matches!(
            rx.decrypt_rtcp(&mut wire),
            Err(SrtpError::AuthFailed)
        ));
    }

    /// ROC rollover under CM: the ROC folds into both the keystream IV
    /// and the HMAC input, so a wrapped sequence still round-trips.
    #[test]
    fn cm_roc_rollover() {
        let mut tx = cm_srtp();
        let mut rx = cm_srtp();
        let ssrc = 0x12345678;

        for seq in [65534u16, 65535, 0, 1, 2] {
            let wire = encrypt(&mut tx, seq, ssrc, seq as u8);
            let mut buf = wire;
            let n = rx.decrypt_rtp(&mut buf).unwrap();
            assert_eq!(&buf[..n], &rtp_packet(seq, ssrc, seq as u8)[..]);
        }
        assert_eq!(
            rx.rx.streams.get(ssrc).unwrap().rtp.highest,
            Some((1 << 16) | 2)
        );
    }
}
