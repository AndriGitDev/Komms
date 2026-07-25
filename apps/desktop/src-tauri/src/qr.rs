//! QR rendering and compact pairing-bundle encoding. SVG stays crisp at any
//! size; RFC 9285 Base45 keeps opaque bundle bytes in QR alphanumeric mode
//! without the 2x expansion of hex. A post-quantum prekey bundle is still
//! too dense for reliable camera scanning as one symbol, so B2 pairing uses
//! bounded, independently scannable frames.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

const BASE45_ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const BUNDLE_QR_PREFIX: &str = "KOMMS:B1:";
const BUNDLE_QR_FRAME_PREFIX: &str = "KOMMS:B2:";
const BUNDLE_QR_CHUNK_BYTES: usize = 420;
const MAX_BUNDLE_QR_CHARS: usize = 16_384;

/// Encode bytes using RFC 9285 Base45.
fn base45_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 3).div_ceil(2));
    let mut index = 0;
    while index + 1 < bytes.len() {
        let mut value = usize::from(bytes[index]) * 256 + usize::from(bytes[index + 1]);
        output.push(char::from(BASE45_ALPHABET[value % 45]));
        value /= 45;
        output.push(char::from(BASE45_ALPHABET[value % 45]));
        output.push(char::from(BASE45_ALPHABET[value / 45]));
        index += 2;
    }
    if index < bytes.len() {
        let value = usize::from(bytes[index]);
        output.push(char::from(BASE45_ALPHABET[value % 45]));
        output.push(char::from(BASE45_ALPHABET[value / 45]));
    }
    output
}

/// Decode strict RFC 9285 Base45, rejecting invalid groups and oversized input.
fn base45_decode(text: &str) -> Option<Vec<u8>> {
    let encoded = text.as_bytes();
    if encoded.len() > MAX_BUNDLE_QR_CHARS || encoded.len() % 3 == 1 {
        return None;
    }
    let value = |byte: u8| {
        BASE45_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
    };
    let mut output = Vec::with_capacity(encoded.len() * 2 / 3);
    let mut index = 0;
    while index < encoded.len() {
        let remaining = encoded.len() - index;
        let first = value(encoded[index])?;
        let second = value(*encoded.get(index + 1)?)?;
        if remaining == 2 {
            let decoded = first + second * 45;
            if decoded > u8::MAX.into() {
                return None;
            }
            output.push(decoded as u8);
            index += 2;
        } else {
            let third = value(encoded[index + 2])?;
            let decoded = first + second * 45 + third * 45 * 45;
            if decoded > u16::MAX.into() {
                return None;
            }
            output.push((decoded / 256) as u8);
            output.push((decoded % 256) as u8);
            index += 3;
        }
    }
    Some(output)
}

/// Build the versioned, cross-shell pairing QR text for opaque bundle bytes.
pub fn bundle_text(bytes: &[u8]) -> String {
    format!("{BUNDLE_QR_PREFIX}{}", base45_encode(bytes))
}

/// Split a bundle into camera-friendly, order-independent QR frames.
///
/// The identifier only groups frames; the reconstructed prekey bundle's
/// signatures remain the security boundary.
pub fn bundle_frames(bytes: &[u8]) -> Vec<String> {
    let total = bytes.len().div_ceil(BUNDLE_QR_CHUNK_BYTES).max(1);
    let identifier = bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    bytes
        .chunks(BUNDLE_QR_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "{BUNDLE_QR_FRAME_PREFIX}{identifier}:{}:{total}:{}:{}",
                index + 1,
                bytes.len(),
                base45_encode(chunk)
            )
        })
        .collect()
}

/// Decode compact pairing QR text, returning `None` for non-QR input.
pub fn decode_bundle_text(text: &str) -> Option<Vec<u8>> {
    text.strip_prefix(BUNDLE_QR_PREFIX).and_then(base45_decode)
}

/// Render `data` as an SVG string sized by the UI (the SVG scales).
pub fn svg(data: &[u8]) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L)
        .map_err(|e| format!("QR encoding: {e}"))?;
    // Opaque black-on-white regardless of app theme: phone cameras need
    // the contrast, and the UI shows codes on their own light card.
    Ok(code
        .render()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base45_matches_rfc_9285_vectors_and_rejects_malformed_groups() {
        assert_eq!(base45_encode(b"AB"), "BB8");
        assert_eq!(base45_encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(base45_encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(base45_decode("QED8WEX0").unwrap(), b"ietf!");
        assert!(base45_decode("A").is_none());
        assert!(base45_decode(":::").is_none());
    }

    #[test]
    fn pairing_payload_is_compact_round_trips_and_renders() {
        let bytes: Vec<u8> = (0..1500).map(|value| (value * 31) as u8).collect();
        let payload = bundle_text(&bytes);
        assert!(payload.starts_with(BUNDLE_QR_PREFIX));
        assert!(payload.len() < bytes.len() * 2);
        assert_eq!(decode_bundle_text(&payload).unwrap(), bytes);
        let legacy_hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
        let compact_code =
            QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L).unwrap();
        let legacy_code =
            QrCode::with_error_correction_level(legacy_hex.as_bytes(), EcLevel::L).unwrap();
        assert!(compact_code.width() < legacy_code.width());
        let svg = svg(payload.as_bytes()).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
    }

    #[test]
    fn pairing_frames_are_bounded_and_camera_friendlier() {
        let bytes: Vec<u8> = (0..1584).map(|value| (value * 31) as u8).collect();
        let frames = bundle_frames(&bytes);
        assert_eq!(frames.len(), 4);
        assert!(frames.iter().all(|frame| {
            frame.starts_with("KOMMS:B2:001F3E5D7C9BBAD9:")
                && frame.len() < 700
                && svg(frame.as_bytes()).is_ok()
        }));
        assert!(frames
            .iter()
            .all(|frame| frame.len() < bundle_text(&bytes).len()));
    }

    #[test]
    fn small_payloads_render_too() {
        assert!(svg(b"KK1EXAMPLEADDRESS").unwrap().contains("<svg"));
    }
}
