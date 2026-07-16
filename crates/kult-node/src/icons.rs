//! B13 private custom icons over the accepted F5 sealed metadata record.
//!
//! Image bytes remain endpoint-local. Caller-selected JPEG/PNG input is
//! content-verified, orientation-normalized, square-cropped, resized, and
//! re-encoded as one canonical metadata-free PNG before it reaches storage.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::imageops::FilterType as ResizeFilter;
use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Limits, Rgba, RgbaImage,
};
use rand_core::CryptoRngCore;

use kult_store::{
    CustomIconRecord, CustomIconTarget, CUSTOM_ICON_BUNDLED_GLYPHS, CUSTOM_ICON_DIMENSION,
    CUSTOM_ICON_MEDIA_TYPE, MAX_CUSTOM_ICON_BYTES,
};

use crate::{CustomIconCrop, CustomIconInfo, CustomIconUsage, Event, Node, NodeError, Result};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INPUT_DIMENSION: u32 = 4_096;
const MAX_INPUT_PIXELS: u64 = 12_000_000;
const MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;

fn invalid_icon<T>() -> Result<T> {
    Err(NodeError::InvalidCustomIcon)
}

fn checked_input_area(width: u32, height: u32) -> Result<()> {
    let area = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(NodeError::InvalidCustomIcon)?;
    if width == 0
        || height == 0
        || width > MAX_INPUT_DIMENSION
        || height > MAX_INPUT_DIMENSION
        || area > MAX_INPUT_PIXELS
    {
        return invalid_icon();
    }
    Ok(())
}

fn reject_animated_png(path: &Path) -> Result<()> {
    let mut reader = BufReader::new(File::open(path).map_err(NodeError::CustomIconIo)?);
    let mut signature = [0u8; 8];
    reader
        .read_exact(&mut signature)
        .map_err(NodeError::CustomIconIo)?;
    if &signature != b"\x89PNG\r\n\x1a\n" {
        return invalid_icon();
    }
    loop {
        let mut header = [0u8; 8];
        reader
            .read_exact(&mut header)
            .map_err(NodeError::CustomIconIo)?;
        let len = u32::from_be_bytes(header[..4].try_into().expect("fixed slice"));
        let kind = &header[4..];
        if matches!(kind, b"acTL" | b"fcTL" | b"fdAT") {
            return invalid_icon();
        }
        reader
            .seek_relative(i64::from(len) + 4)
            .map_err(NodeError::CustomIconIo)?;
        if kind == b"IEND" {
            return Ok(());
        }
    }
}

fn decode_source(path: &Path) -> Result<DynamicImage> {
    let source = File::open(path).map_err(NodeError::CustomIconIo)?;
    let encoded_bytes = source.metadata().map_err(NodeError::CustomIconIo)?.len();
    if !(1..=MAX_INPUT_BYTES).contains(&encoded_bytes) {
        return invalid_icon();
    }
    let mut reader = ImageReader::new(BufReader::new(source))
        .with_guessed_format()
        .map_err(|_| NodeError::InvalidCustomIcon)?;
    let format = reader.format();
    if !matches!(format, Some(ImageFormat::Jpeg | ImageFormat::Png)) {
        return invalid_icon();
    }
    if format == Some(ImageFormat::Png) {
        reject_animated_png(path)?;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_INPUT_DIMENSION);
    limits.max_image_height = Some(MAX_INPUT_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| NodeError::InvalidCustomIcon)?;
    let (width, height) = decoder.dimensions();
    checked_input_area(width, height)?;
    if decoder.total_bytes() > MAX_DECODE_ALLOC {
        return invalid_icon();
    }
    let orientation = decoder
        .orientation()
        .map_err(|_| NodeError::InvalidCustomIcon)?;
    let mut image =
        DynamicImage::from_decoder(decoder).map_err(|_| NodeError::InvalidCustomIcon)?;
    image.apply_orientation(orientation);
    checked_input_area(image.width(), image.height())?;
    Ok(image)
}

fn crop_and_resize(image: DynamicImage, crop: Option<CustomIconCrop>) -> Result<RgbaImage> {
    let crop = crop.unwrap_or_else(|| {
        let edge = image.width().min(image.height());
        CustomIconCrop {
            x: (image.width() - edge) / 2,
            y: (image.height() - edge) / 2,
            width: edge,
            height: edge,
        }
    });
    if crop.width == 0
        || crop.width != crop.height
        || crop
            .x
            .checked_add(crop.width)
            .is_none_or(|right| right > image.width())
        || crop
            .y
            .checked_add(crop.height)
            .is_none_or(|bottom| bottom > image.height())
    {
        return invalid_icon();
    }
    Ok(image
        .crop_imm(crop.x, crop.y, crop.width, crop.height)
        .resize_exact(
            CUSTOM_ICON_DIMENSION,
            CUSTOM_ICON_DIMENSION,
            ResizeFilter::Lanczos3,
        )
        .to_rgba8())
}

fn encode_canonical(image: &RgbaImage) -> Result<Vec<u8>> {
    if image.width() != CUSTOM_ICON_DIMENSION || image.height() != CUSTOM_ICON_DIMENSION {
        return invalid_icon();
    }
    let mut bytes = Vec::new();
    PngEncoder::new_with_quality(&mut bytes, CompressionType::Best, FilterType::Adaptive)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| NodeError::InvalidCustomIcon)?;
    if bytes.is_empty() || bytes.len() > MAX_CUSTOM_ICON_BYTES {
        return invalid_icon();
    }
    verify_canonical(&bytes)?;
    Ok(bytes)
}

fn verify_canonical(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return invalid_icon();
    }
    let mut offset = 8usize;
    let mut ihdr = 0usize;
    let mut idat = 0usize;
    let mut iend = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return invalid_icon();
        }
        let len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| NodeError::InvalidCustomIcon)?,
        ) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(len))
            .ok_or(NodeError::InvalidCustomIcon)?;
        if end > bytes.len() {
            return invalid_icon();
        }
        let kind = &bytes[offset + 4..offset + 8];
        match kind {
            b"IHDR" if offset == 8 && len == 13 && ihdr == 0 => {
                let header = &bytes[offset + 8..offset + 21];
                let width = u32::from_be_bytes(header[..4].try_into().expect("fixed slice"));
                let height = u32::from_be_bytes(header[4..8].try_into().expect("fixed slice"));
                if width != CUSTOM_ICON_DIMENSION
                    || height != CUSTOM_ICON_DIMENSION
                    || header[8] != 8
                    || header[9] != 6
                    || header[10] != 0
                    || header[11] != 0
                    || header[12] != 0
                {
                    return invalid_icon();
                }
                ihdr = 1;
            }
            b"IDAT" if ihdr == 1 && iend == 0 => idat += 1,
            b"IEND" if len == 0 && ihdr == 1 && idat != 0 && iend == 0 => iend = 1,
            _ => return invalid_icon(),
        }
        offset = end;
        if iend == 1 && offset != bytes.len() {
            return invalid_icon();
        }
    }
    if ihdr != 1 || idat == 0 || iend != 1 {
        return invalid_icon();
    }
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes));
    reader.set_format(ImageFormat::Png);
    let image = reader.decode().map_err(|_| NodeError::InvalidCustomIcon)?;
    if image.width() != CUSTOM_ICON_DIMENSION || image.height() != CUSTOM_ICON_DIMENSION {
        return invalid_icon();
    }
    Ok(())
}

fn fill_rect(image: &mut RgbaImage, left: u32, top: u32, right: u32, bottom: u32, color: Rgba<u8>) {
    for y in top.min(CUSTOM_ICON_DIMENSION)..bottom.min(CUSTOM_ICON_DIMENSION) {
        for x in left.min(CUSTOM_ICON_DIMENSION)..right.min(CUSTOM_ICON_DIMENSION) {
            image.put_pixel(x, y, color);
        }
    }
}

fn fill_circle(image: &mut RgbaImage, cx: i32, cy: i32, radius: i32, color: Rgba<u8>) {
    let r2 = radius * radius;
    for y in (cy - radius).max(0)..=(cy + radius).min(CUSTOM_ICON_DIMENSION as i32 - 1) {
        for x in (cx - radius).max(0)..=(cx + radius).min(CUSTOM_ICON_DIMENSION as i32 - 1) {
            let dx = x - cx;
            let dy = y - cy;
            if dx * dx + dy * dy <= r2 {
                image.put_pixel(x as u32, y as u32, color);
            }
        }
    }
}

fn bundled_icon(glyph: &str) -> Result<RgbaImage> {
    let index = CUSTOM_ICON_BUNDLED_GLYPHS
        .iter()
        .position(|candidate| candidate == &glyph)
        .ok_or(NodeError::InvalidCustomIcon)?;
    let backgrounds = [
        [34, 94, 168, 255],
        [111, 66, 193, 255],
        [181, 88, 23, 255],
        [15, 118, 110, 255],
        [148, 100, 10, 255],
        [173, 45, 78, 255],
        [42, 113, 75, 255],
        [74, 78, 105, 255],
    ];
    let mut image = RgbaImage::from_pixel(
        CUSTOM_ICON_DIMENSION,
        CUSTOM_ICON_DIMENSION,
        Rgba(backgrounds[index]),
    );
    let ink = Rgba([255, 255, 255, 255]);
    match glyph {
        "person" => {
            fill_circle(&mut image, 128, 88, 39, ink);
            fill_circle(&mut image, 128, 196, 72, ink);
        }
        "group" => {
            fill_circle(&mut image, 128, 76, 31, ink);
            fill_circle(&mut image, 70, 111, 25, ink);
            fill_circle(&mut image, 186, 111, 25, ink);
            fill_circle(&mut image, 128, 190, 62, ink);
            fill_circle(&mut image, 54, 201, 45, ink);
            fill_circle(&mut image, 202, 201, 45, ink);
        }
        "folder" => {
            fill_rect(&mut image, 39, 73, 126, 113, ink);
            fill_rect(&mut image, 31, 99, 225, 203, ink);
        }
        "note" => {
            fill_rect(&mut image, 54, 35, 202, 221, ink);
            let line = Rgba(backgrounds[index]);
            for top in [82, 112, 142, 172] {
                fill_rect(&mut image, 81, top, 176, top + 8, line);
            }
        }
        "star" => {
            for y in 38..220 {
                for x in 32..224 {
                    let dx = (x as i32 - 128).abs();
                    let dy = (y as i32 - 128).abs();
                    if dx + dy < 61 || (dx < 22 && dy < 91) || (dy < 22 && dx < 91) {
                        image.put_pixel(x, y, ink);
                    }
                }
            }
        }
        "heart" => {
            for y in 42..222 {
                for x in 35..221 {
                    let px = (x as f64 - 128.0) / 76.0;
                    let py = (128.0 - y as f64) / 76.0;
                    let value = (px * px + py * py - 1.0).powi(3) - px * px * py.powi(3);
                    if value <= 0.0 {
                        image.put_pixel(x, y, ink);
                    }
                }
            }
        }
        "shield" => {
            for y in 35..225 {
                let half = if y < 125 { 78 } else { (225 - y) * 78 / 100 };
                let left = 128u32.saturating_sub(half);
                let right = (128 + half).min(255);
                for x in left..=right {
                    image.put_pixel(x, y, ink);
                }
            }
        }
        "compass" => {
            fill_circle(&mut image, 128, 128, 88, ink);
            fill_circle(&mut image, 128, 128, 66, Rgba(backgrounds[index]));
            for y in 57..199 {
                let half = ((y as i32 - 128).abs() / 3) as u32;
                for x in 128u32.saturating_sub(24 - half.min(24))..=(128 + 24 - half.min(24)) {
                    image.put_pixel(x, y, ink);
                }
            }
        }
        _ => unreachable!("validated glyph"),
    }
    Ok(image)
}

impl Node {
    fn ensure_custom_icon_target(&self, target: &CustomIconTarget) -> Result<()> {
        let available = match target {
            CustomIconTarget::Contact(peer) => self.store.get_contact(peer)?.is_some(),
            CustomIconTarget::Group(group) => self.store.get_group(group)?.is_some(),
            CustomIconTarget::Folder(folder) => self.store.folder(folder)?.is_some(),
            CustomIconTarget::NoteToSelf => true,
        };
        if available {
            Ok(())
        } else {
            Err(NodeError::UnavailableCustomIconTarget)
        }
    }

    /// Read one canonical sealed icon. Missing or malformed legacy bytes
    /// safely return `None`, allowing shells to render generated initials.
    pub fn custom_icon(&self, target: &CustomIconTarget) -> Result<Option<CustomIconInfo>> {
        let Some(record) = self.store.custom_icon(target)? else {
            return Ok(None);
        };
        if record.media_type != CUSTOM_ICON_MEDIA_TYPE || verify_canonical(&record.bytes).is_err() {
            return Ok(None);
        }
        Ok(Some(CustomIconInfo {
            target: record.target,
            media_type: record.media_type,
            bytes: record.bytes,
            width: CUSTOM_ICON_DIMENSION,
            height: CUSTOM_ICON_DIMENSION,
        }))
    }

    /// Sanitize a caller-selected local JPEG/PNG and seal it for one exact target.
    pub fn set_custom_icon_from_path(
        &mut self,
        target: CustomIconTarget,
        source: &Path,
        crop: Option<CustomIconCrop>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<CustomIconInfo> {
        self.ensure_custom_icon_target(&target)?;
        let image = crop_and_resize(decode_source(source)?, crop)?;
        let bytes = encode_canonical(&image)?;
        let record = CustomIconRecord {
            target: target.clone(),
            media_type: CUSTOM_ICON_MEDIA_TYPE.to_owned(),
            bytes: bytes.clone(),
        };
        if self.store.set_custom_icon(&record, rng)? {
            self.events.push_back(Event::CustomIconsChanged);
        }
        Ok(CustomIconInfo {
            target,
            media_type: CUSTOM_ICON_MEDIA_TYPE.to_owned(),
            bytes,
            width: CUSTOM_ICON_DIMENSION,
            height: CUSTOM_ICON_DIMENSION,
        })
    }

    /// Render and seal one deterministic bundled glyph for an exact target.
    pub fn set_bundled_custom_icon(
        &mut self,
        target: CustomIconTarget,
        glyph: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<CustomIconInfo> {
        self.ensure_custom_icon_target(&target)?;
        let bytes = encode_canonical(&bundled_icon(glyph)?)?;
        let record = CustomIconRecord {
            target: target.clone(),
            media_type: CUSTOM_ICON_MEDIA_TYPE.to_owned(),
            bytes: bytes.clone(),
        };
        if self.store.set_custom_icon(&record, rng)? {
            self.events.push_back(Event::CustomIconsChanged);
        }
        Ok(CustomIconInfo {
            target,
            media_type: CUSTOM_ICON_MEDIA_TYPE.to_owned(),
            bytes,
            width: CUSTOM_ICON_DIMENSION,
            height: CUSTOM_ICON_DIMENSION,
        })
    }

    /// Remove one custom icon and return to generated-initials fallback.
    pub fn clear_custom_icon(&mut self, target: &CustomIconTarget) -> Result<bool> {
        let changed = self.store.delete_custom_icon(target)?;
        if changed {
            self.events.push_back(Event::CustomIconsChanged);
        }
        Ok(changed)
    }

    /// Read current sealed custom-icon quota usage.
    pub fn custom_icon_usage(&self) -> Result<CustomIconUsage> {
        let (records, bytes) = self.store.custom_icon_usage()?;
        Ok(CustomIconUsage { records, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_glyph_is_canonical_and_distinct() {
        let mut encoded = Vec::new();
        for glyph in CUSTOM_ICON_BUNDLED_GLYPHS {
            let bytes = encode_canonical(&bundled_icon(glyph).unwrap()).unwrap();
            verify_canonical(&bytes).unwrap();
            assert!(!encoded.contains(&bytes));
            encoded.push(bytes);
        }
        assert!(bundled_icon("remote-url").is_err());
    }
}
