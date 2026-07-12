//! QR rendering for the verification and pairing screens. SVG (crisp at
//! any size, no raster dependency); content is passed in as bytes — the
//! callers keep uppercase-hex payloads so large codes stay in the QR
//! alphanumeric mode (a full prekey bundle is ~3 000 hex chars, past the
//! byte-mode ceiling but comfortably inside alphanumeric's).

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

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
    fn renders_a_bundle_sized_alphanumeric_payload() {
        // A realistic prekey-bundle hex length (~1.5 KiB of bytes → ~3000
        // chars): too big for QR byte mode, must fit via alphanumeric.
        let payload = "A0".repeat(1500);
        let svg = svg(payload.as_bytes()).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
    }

    #[test]
    fn small_payloads_render_too() {
        assert!(svg(b"KK1EXAMPLEADDRESS").unwrap().contains("<svg"));
    }
}
