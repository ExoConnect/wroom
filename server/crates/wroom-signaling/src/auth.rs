//! Join-token verification (D16): behind an interface so providers are
//! pluggable — unsigned dev tokens now, OIDC-compatible or hosted
//! providers later, without touching the session flow.

/// Identity a verified token grants: room membership and display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub room_id: String,
    pub display_name: String,
}

/// Verifies an opaque join token into room + identity claims.
/// Implementations must be cheap and non-blocking; verification happens
/// on the signaling path.
pub trait TokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Option<Claims>;
}

/// M0 development provider: the token is plaintext `room_id:display_name`
/// — no crypto, no lookup. Rooms are ephemeral links (D16), so anyone
/// holding the room slug may join; this exists to wire the flow, not to
/// keep anyone out.
#[derive(Debug, Default, Clone, Copy)]
pub struct DevTokenVerifier;

/// Room ids are URL slugs: keep them to a conservative charset so a room
/// is always a clean path segment.
fn valid_room_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= wroom_core::room::MAX_ID_LEN
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_display_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= wroom_core::room::MAX_NAME_LEN
        && !s.chars().any(char::is_control)
}

impl TokenVerifier for DevTokenVerifier {
    fn verify(&self, token: &str) -> Option<Claims> {
        // The display name may itself contain ':'; only the first is the
        // separator.
        let (room_id, display_name) = token.split_once(':')?;
        (valid_room_id(room_id) && valid_display_name(display_name)).then(|| Claims {
            room_id: room_id.to_string(),
            display_name: display_name.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_token_parses() {
        let v = DevTokenVerifier;
        assert_eq!(
            v.verify("standup-42:Alice"),
            Some(Claims {
                room_id: "standup-42".to_string(),
                display_name: "Alice".to_string(),
            })
        );
        // Display name keeps everything after the first ':'.
        assert_eq!(
            v.verify("room:A:B").unwrap().display_name,
            "A:B"
        );
    }

    #[test]
    fn dev_token_rejects_garbage() {
        let v = DevTokenVerifier;
        for token in [
            "",              // empty
            "nocolon",       // no separator
            ":name",         // empty room
            "room:",         // empty name
            "ro om:name",    // room not a slug
            "room:na\u{7}e", // control char in name
        ] {
            assert_eq!(v.verify(token), None, "token {token:?} must be rejected");
        }
    }
}
