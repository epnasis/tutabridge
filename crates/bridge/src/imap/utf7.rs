//! Modified UTF-7 for IMAP mailbox names (RFC 3501 §5.1.3).
//!
//! Printable ASCII (0x20–0x7E) represents itself, except `&` which is encoded
//! as `&-`. Any other run of characters is encoded as `&<b64>-` where `<b64>`
//! is the modified BASE64 (alphabet `+,` instead of `+/`, no padding) of the
//! run encoded as UTF-16BE.

use base64::alphabet::Alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use std::sync::LazyLock;

/// Modified BASE64 alphabet: standard, but `/` becomes `,`.
static MODIFIED_B64: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    let alphabet =
        Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,")
            .expect("valid alphabet");
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone);
    GeneralPurpose::new(&alphabet, config)
});

fn is_direct(c: char) -> bool {
    // Printable ASCII except `&`.
    ('\u{20}'..='\u{7e}').contains(&c) && c != '&'
}

/// Encode a UTF-8 mailbox name into modified UTF-7.
pub fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut shifted: Vec<u16> = Vec::new();

    let flush = |shifted: &mut Vec<u16>, out: &mut String| {
        if shifted.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(shifted.len() * 2);
        for unit in shifted.drain(..) {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        out.push('&');
        out.push_str(&MODIFIED_B64.encode(&bytes));
        out.push('-');
    };

    for c in input.chars() {
        if c == '&' {
            flush(&mut shifted, &mut out);
            out.push_str("&-");
        } else if is_direct(c) {
            flush(&mut shifted, &mut out);
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            shifted.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut shifted, &mut out);
    out
}

/// Decode a modified UTF-7 mailbox name back to UTF-8. Returns `None` if the
/// input is not valid modified UTF-7.
pub fn decode(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'&' {
            // Find the closing '-'.
            let end = bytes[i + 1..].iter().position(|&x| x == b'-')? + i + 1;
            let chunk = &input[i + 1..end];
            if chunk.is_empty() {
                // "&-" => literal '&'
                out.push('&');
            } else {
                let decoded = MODIFIED_B64.decode(chunk.as_bytes()).ok()?;
                if decoded.len() % 2 != 0 {
                    return None;
                }
                let units: Vec<u16> = decoded
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                out.push_str(&String::from_utf16(&units).ok()?);
            }
            i = end + 1;
        } else {
            // Direct ASCII byte.
            out.push(b as char);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(plain: &str, wire: &str) {
        assert_eq!(encode(plain), wire, "encode {plain:?}");
        assert_eq!(decode(wire).as_deref(), Some(plain), "decode {wire:?}");
    }

    #[test]
    fn ascii_is_identity() {
        roundtrip("INBOX", "INBOX");
        roundtrip("Work/Projects", "Work/Projects");
        roundtrip("Not Important", "Not Important");
    }

    #[test]
    fn ampersand_is_escaped() {
        roundtrip("R&D", "R&-D");
        roundtrip("&", "&-");
    }

    #[test]
    fn non_ascii_is_shifted() {
        // Examples from RFC 3501.
        roundtrip("Café", "Caf&AOk-");
        roundtrip("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
    }

    #[test]
    fn mixed_runs() {
        roundtrip("Dossier éàü test", "Dossier &AOkA4AD8- test");
    }

    #[test]
    fn decode_rejects_unterminated_shift() {
        assert_eq!(decode("&AOk"), None);
    }
}
