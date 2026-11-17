//! Routing UDP flows by the USERNAME of their first STUN message.
//!
//! A WebRTC (ICE) flow starts with a STUN Binding Request (RFC 8489) whose
//! USERNAME attribute is `<receiver's ufrag>:<sender's ufrag>` (RFC 8445,
//! 7.2.2). When each backend generates its ufrag from its own name, the first
//! packet of a flow says which backend it is for, and many sessions can share
//! one public UDP port.

use std::fmt;

use anyhow::{Result, bail};
use serde::Deserialize;

/// First 4 bytes after the type and length of every STUN message.
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const USERNAME: u16 = 0x0006;

/// The USERNAME of `packet` if it is a STUN Binding Request that has one.
pub fn binding_username(packet: &[u8]) -> Option<&str> {
    if packet.len() < HEADER_LEN || packet[4..8] != MAGIC_COOKIE {
        return None;
    }
    let kind = u16::from_be_bytes([packet[0], packet[1]]);
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    // The two top bits of every STUN message are zero, and the body is made of
    // 4-byte aligned attributes; anything else is another protocol.
    if kind != BINDING_REQUEST || length % 4 != 0 || HEADER_LEN + length > packet.len() {
        return None;
    }

    let mut rest = &packet[HEADER_LEN..HEADER_LEN + length];
    while rest.len() >= 4 {
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let value = rest.get(4..4 + len)?;
        if kind == USERNAME {
            return std::str::from_utf8(value).ok();
        }
        // Values are padded to a multiple of 4 bytes.
        let padded = (4 + len).div_ceil(4) * 4;
        rest = rest.get(padded..)?;
    }
    None
}

/// The ufrag a Binding Request is addressed to: the part of its USERNAME
/// before the colon.
pub fn receiver_ufrag(username: &str) -> &str {
    username.split_once(':').map_or(username, |(ufrag, _)| ufrag)
}

/// A string with exactly one `{id}` in it, such as `nsp{id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    prefix: String,
    suffix: String,
}

const PLACEHOLDER: &str = "{id}";

impl Template {
    pub fn parse(text: &str) -> Result<Self> {
        let Some((prefix, suffix)) = text.split_once(PLACEHOLDER) else {
            bail!("{text:?} has no {PLACEHOLDER}");
        };
        if suffix.contains(PLACEHOLDER) {
            bail!("{text:?} has more than one {PLACEHOLDER}");
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    /// The id that `text` was made from, if it was made from this template.
    pub fn id<'a>(&self, text: &'a str) -> Option<&'a str> {
        let id = text
            .strip_prefix(self.prefix.as_str())?
            .strip_suffix(self.suffix.as_str())?;
        (!id.is_empty()).then_some(id)
    }

    pub fn fill(&self, id: &str) -> String {
        format!("{}{id}{}", self.prefix, self.suffix)
    }

    /// The characters of the template outside `{id}`.
    fn literal(&self) -> impl Iterator<Item = char> + '_ {
        self.prefix.chars().chain(self.suffix.chars())
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{PLACEHOLDER}{}", self.prefix, self.suffix)
    }
}

/// How a `stun-username` listener finds the backend of a new flow.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawStunUsername")]
pub struct StunUsername {
    /// What the backends' ufrags look like; `{id}` is taken out of them.
    pub ufrag: Template,
    /// The Kubernetes pod name an id stands for.
    pub pod: Template,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStunUsername {
    ufrag: String,
    #[serde(default = "default_pod")]
    pod: String,
}

fn default_pod() -> String {
    PLACEHOLDER.to_owned()
}

impl TryFrom<RawStunUsername> for StunUsername {
    type Error = anyhow::Error;

    fn try_from(raw: RawStunUsername) -> Result<Self> {
        let ufrag = Template::parse(&raw.ufrag)?;
        // RFC 8839: ice-char = ALPHA / DIGIT / "+" / "/". Browsers reject
        // other ufrags, so a template with any could never match.
        if let Some(bad) = ufrag
            .literal()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '+' || *c == '/'))
        {
            bail!(
                "ufrag {:?}: {bad:?} is not allowed in an ICE ufrag (only letters, digits, '+' and '/')",
                raw.ufrag
            );
        }
        Ok(Self {
            ufrag,
            pod: Template::parse(&raw.pod)?,
        })
    }
}

impl StunUsername {
    /// The pod that the first packet of a flow is for, or why there is none.
    pub fn pod(&self, packet: &[u8]) -> Result<String, Unroutable> {
        let username = binding_username(packet).ok_or(Unroutable::NotStun)?;
        let id = self
            .ufrag
            .id(receiver_ufrag(username))
            .ok_or(Unroutable::UnknownUfrag)?;
        Ok(self.pod.fill(id))
    }
}

/// Why the first packet of a flow could not be routed by its USERNAME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unroutable {
    /// Not a STUN Binding Request with a USERNAME.
    NotStun,
    /// The ufrag does not match the template.
    UnknownUfrag,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Binding Request with `attributes` (type, value) after the header.
    fn request(attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (kind, value) in attributes {
            body.extend_from_slice(&kind.to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
            body.resize(body.len().div_ceil(4) * 4, 0);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[7; 12]); // transaction id
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn reads_the_username_after_other_attributes() {
        // PRIORITY (4 bytes) and a 5-byte attribute that needs padding first.
        let packet = request(&[
            (0x0024, &[0, 0, 0, 1]),
            (0x8022, b"agent"),
            (USERNAME, b"nspab12:cl1e"),
            (0x0008, &[0; 20]), // MESSAGE-INTEGRITY
        ]);
        assert_eq!(binding_username(&packet), Some("nspab12:cl1e"));
        assert_eq!(receiver_ufrag("nspab12:cl1e"), "nspab12");
    }

    #[test]
    fn ignores_everything_else() {
        let stun = request(&[(USERNAME, b"a:b")]);
        assert_eq!(binding_username(&stun[..19]), None);

        // A Binding response, not a request.
        let mut response = stun.clone();
        response[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        assert_eq!(binding_username(&response), None);

        // No magic cookie: an RFC 3489 message or another protocol.
        let mut old = stun.clone();
        old[4] = 0;
        assert_eq!(binding_username(&old), None);

        // DTLS ClientHello, the next thing a WebRTC flow sends.
        let dtls = [22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0, 0, 0x34, 0, 0, 0];
        assert_eq!(binding_username(&dtls), None);

        // No USERNAME, and a length that runs past the packet.
        assert_eq!(binding_username(&request(&[(0x0024, &[0; 4])])), None);
        let mut truncated = stun.clone();
        truncated.truncate(stun.len() - 4);
        assert_eq!(binding_username(&truncated), None);

        // An attribute that claims more bytes than the message has.
        let mut lying = request(&[(USERNAME, b"abcd")]);
        lying[22..24].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(binding_username(&lying), None);
    }

    fn config(ufrag: &str, pod: &str) -> StunUsername {
        StunUsername::try_from(RawStunUsername {
            ufrag: ufrag.into(),
            pod: pod.into(),
        })
        .unwrap()
    }

    #[test]
    fn maps_a_ufrag_to_its_pod() {
        let routing = config("nsp{id}", "nes-session-{id}");
        let packet = |username: &[u8]| request(&[(USERNAME, username)]);

        assert_eq!(
            routing.pod(&packet(b"nspx7k2p:abcd")),
            Ok("nes-session-x7k2p".into())
        );
        assert_eq!(routing.pod(&packet(b"other:abcd")), Err(Unroutable::UnknownUfrag));
        // The prefix alone carries no id.
        assert_eq!(routing.pod(&packet(b"nsp:abcd")), Err(Unroutable::UnknownUfrag));
        // The client's half of the username is not looked at.
        assert_eq!(routing.pod(&packet(b"abcd:nspx7k2p")), Err(Unroutable::UnknownUfrag));
        assert_eq!(routing.pod(b"\x16\xfe\xfd"), Err(Unroutable::NotStun));

        let plain = config("{id}", "{id}");
        assert_eq!(plain.pod(&packet(b"session1:abcd")), Ok("session1".into()));
        let suffixed = config("u{id}x", "{id}");
        assert_eq!(suffixed.pod(&packet(b"u42x:abcd")), Ok("42".into()));
    }

    #[test]
    fn rejects_bad_templates() {
        let error = |ufrag: &str, pod: &str| {
            StunUsername::try_from(RawStunUsername {
                ufrag: ufrag.into(),
                pod: pod.into(),
            })
            .unwrap_err()
            .to_string()
        };
        assert!(error("nsp", "{id}").contains("has no {id}"));
        assert!(error("{id}{id}", "{id}").contains("more than one"));
        assert!(error("nsp-{id}", "{id}").contains("'-' is not allowed"));
        assert!(error("nsp{id}", "pod").contains("has no {id}"));
    }
}
