//! Bounded, deterministic, metadata-free still-image editing shared by every shell.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Limits, RgbaImage,
};

use crate::FfiError;

/// Canonical media type for every edited still image.
pub const IMAGE_MEDIA_TYPE: &str = "image/png";
/// Maximum encoded JPEG/PNG source size accepted by the editor.
pub const IMAGE_MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum encoded canonical PNG size produced by the editor.
pub const IMAGE_MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum width or height accepted before orientation normalization.
pub const IMAGE_MAX_DIMENSION: u32 = 4_096;
/// Maximum decoded pixel count. This bounds RGBA allocation to 48 MiB per image buffer.
pub const IMAGE_MAX_PIXELS: u64 = 12_000_000;
/// Maximum number of user-positioned blur/pixelation operations.
pub const IMAGE_MAX_REGIONS: usize = 16;

const IMAGE_MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;
const BLUR_MAX_RADIUS: u32 = 32;
const PIXELATE_MAX_BLOCK: u32 = 64;

/// Crop rectangle in oriented source pixels. Coordinates are applied after EXIF
/// orientation normalization and before the explicit quarter-turn rotation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImageCrop {
    /// Left edge in oriented source pixels.
    pub x: u32,
    /// Top edge in oriented source pixels.
    pub y: u32,
    /// Non-zero crop width.
    pub width: u32,
    /// Non-zero crop height.
    pub height: u32,
}

/// Manual privacy operation applied to a region of the cropped, explicitly
/// rotated canvas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImageEditRegionKind {
    /// Deterministic integer box blur.
    Blur,
    /// Deterministic square pixelation anchored at the region's top-left edge.
    Pixelate,
}

/// One bounded manual privacy region. Regions are applied in array order, so
/// overlapping operations have stable and testable semantics.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImageEditRegion {
    /// Privacy operation.
    pub kind: ImageEditRegionKind,
    /// Left edge in final-canvas pixels.
    pub x: u32,
    /// Top edge in final-canvas pixels.
    pub y: u32,
    /// Non-zero region width.
    pub width: u32,
    /// Non-zero region height.
    pub height: u32,
    /// Blur radius (`1..=32`) or pixel block edge (`2..=64`).
    pub strength: u32,
}

/// Complete deterministic edit recipe. Crop coordinates are exact integer
/// pixels: shells perform any normalized-control rounding once, using nearest
/// integer with ties toward the lower coordinate, before crossing FFI.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImageEditRecipe {
    /// Optional crop; absence selects the whole oriented image.
    pub crop: Option<ImageCrop>,
    /// Clockwise quarter turns after crop (`0..=3`).
    pub rotation_quarter_turns: u8,
    /// Ordered user-positioned privacy operations.
    pub regions: Vec<ImageEditRegion>,
}

/// Safe local facts derived from the canonical edited bytes.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImageInfo {
    /// Final width in pixels.
    pub width: u32,
    /// Final height in pixels.
    pub height: u32,
    /// Exact encoded PNG byte count.
    pub encoded_bytes: u64,
    /// True when at least one pixel is not fully opaque.
    pub has_alpha: bool,
    /// Canonical attachment media type (`image/png`).
    pub media_type: String,
}

fn image_error(reason: impl Into<String>) -> FfiError {
    FfiError::Node {
        reason: format!("still image: {}", reason.into()),
    }
}

fn private_destination(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn checked_area(width: u32, height: u32) -> Result<u64, FfiError> {
    let area = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or_else(|| image_error("dimension overflow"))?;
    if width == 0
        || height == 0
        || width > IMAGE_MAX_DIMENSION
        || height > IMAGE_MAX_DIMENSION
        || area > IMAGE_MAX_PIXELS
    {
        return Err(image_error(
            "dimensions exceed the 4096 edge / 12 megapixel limit",
        ));
    }
    Ok(area)
}

fn reject_animated_png(path: &Path) -> Result<(), FfiError> {
    let mut reader =
        BufReader::new(File::open(path).map_err(|error| image_error(error.to_string()))?);
    let mut signature = [0u8; 8];
    reader
        .read_exact(&mut signature)
        .map_err(|error| image_error(format!("truncated PNG signature: {error}")))?;
    if &signature != b"\x89PNG\r\n\x1a\n" {
        return Err(image_error("spoofed PNG signature"));
    }
    loop {
        let mut header = [0u8; 8];
        reader
            .read_exact(&mut header)
            .map_err(|error| image_error(format!("truncated PNG chunk: {error}")))?;
        let len = u32::from_be_bytes(header[..4].try_into().expect("fixed slice"));
        let kind = &header[4..];
        if matches!(kind, b"acTL" | b"fcTL" | b"fdAT") {
            return Err(image_error("animated PNG is not a supported still image"));
        }
        reader
            .seek_relative(i64::from(len) + 4)
            .map_err(|error| image_error(format!("invalid PNG chunk: {error}")))?;
        if kind == b"IEND" {
            break;
        }
    }
    Ok(())
}

fn decode_source(path: &Path) -> Result<DynamicImage, FfiError> {
    let source = File::open(path).map_err(|error| image_error(error.to_string()))?;
    let encoded_bytes = source
        .metadata()
        .map_err(|error| image_error(error.to_string()))?
        .len();
    if !(1..=IMAGE_MAX_INPUT_BYTES).contains(&encoded_bytes) {
        return Err(image_error("source is empty or exceeds 32 MiB"));
    }

    let mut reader = ImageReader::new(BufReader::new(source))
        .with_guessed_format()
        .map_err(|error| image_error(error.to_string()))?;
    let format = reader.format();
    match format {
        Some(ImageFormat::Jpeg | ImageFormat::Png) => {}
        _ => {
            return Err(image_error(
                "only content-verified JPEG and PNG are supported",
            ))
        }
    }
    if format == Some(ImageFormat::Png) {
        reject_animated_png(path)?;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
    limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
    limits.max_alloc = Some(IMAGE_MAX_DECODE_ALLOC);
    reader.limits(limits);
    let mut decoder = reader
        .into_decoder()
        .map_err(|error| image_error(format!("decode header: {error}")))?;
    let (width, height) = decoder.dimensions();
    checked_area(width, height)?;
    if decoder.total_bytes() > IMAGE_MAX_DECODE_ALLOC {
        return Err(image_error("decoded allocation exceeds 64 MiB"));
    }
    let orientation = decoder
        .orientation()
        .map_err(|error| image_error(format!("orientation metadata: {error}")))?;
    let mut image = DynamicImage::from_decoder(decoder)
        .map_err(|error| image_error(format!("malformed or truncated image: {error}")))?;
    image.apply_orientation(orientation);
    checked_area(image.width(), image.height())?;
    Ok(image)
}

fn checked_rect(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    canvas_width: u32,
    canvas_height: u32,
    label: &str,
) -> Result<(), FfiError> {
    if width == 0
        || height == 0
        || x.checked_add(width)
            .is_none_or(|right| right > canvas_width)
        || y.checked_add(height)
            .is_none_or(|bottom| bottom > canvas_height)
    {
        return Err(image_error(format!("{label} is outside the image")));
    }
    Ok(())
}

fn apply_pixelation(image: &mut RgbaImage, region: &ImageEditRegion) {
    let right = region.x + region.width;
    let bottom = region.y + region.height;
    let block = region.strength;
    let mut top = region.y;
    while top < bottom {
        let block_bottom = top.saturating_add(block).min(bottom);
        let mut left = region.x;
        while left < right {
            let block_right = left.saturating_add(block).min(right);
            let mut sums = [0u64; 4];
            let mut count = 0u64;
            for y in top..block_bottom {
                for x in left..block_right {
                    let pixel = image.get_pixel(x, y).0;
                    for channel in 0..4 {
                        sums[channel] += u64::from(pixel[channel]);
                    }
                    count += 1;
                }
            }
            let mut average = [0u8; 4];
            for channel in 0..4 {
                average[channel] = ((sums[channel] + count / 2) / count) as u8;
            }
            for y in top..block_bottom {
                for x in left..block_right {
                    image.put_pixel(x, y, image::Rgba(average));
                }
            }
            left = block_right;
        }
        top = block_bottom;
    }
}

fn temp_offset(x: u32, y: u32, width: u32) -> usize {
    ((y as usize * width as usize) + x as usize) * 4
}

fn apply_blur(image: &mut RgbaImage, region: &ImageEditRegion) -> Result<(), FfiError> {
    let temp_len = usize::try_from(
        u64::from(region.width)
            .saturating_mul(u64::from(region.height))
            .saturating_mul(4),
    )
    .map_err(|_| image_error("blur allocation overflow"))?;
    let mut horizontal = Vec::new();
    horizontal
        .try_reserve_exact(temp_len)
        .map_err(|_| image_error("not enough storage for blur scratch"))?;
    horizontal.resize(temp_len, 0u8);
    let radius = region.strength;

    for local_y in 0..region.height {
        let mut sums = [0u64; 4];
        let initial_right = radius.min(region.width - 1);
        for local_x in 0..=initial_right {
            let pixel = image.get_pixel(region.x + local_x, region.y + local_y).0;
            for channel in 0..4 {
                sums[channel] += u64::from(pixel[channel]);
            }
        }
        for local_x in 0..region.width {
            let left = local_x.saturating_sub(radius);
            let right = local_x.saturating_add(radius).min(region.width - 1);
            let count = u64::from(right - left + 1);
            let offset = temp_offset(local_x, local_y, region.width);
            for channel in 0..4 {
                horizontal[offset + channel] = ((sums[channel] + count / 2) / count) as u8;
            }
            if local_x >= radius {
                let leaving = image
                    .get_pixel(region.x + local_x - radius, region.y + local_y)
                    .0;
                for channel in 0..4 {
                    sums[channel] -= u64::from(leaving[channel]);
                }
            }
            if let Some(entering_x) = local_x.checked_add(radius + 1) {
                if entering_x < region.width {
                    let entering = image.get_pixel(region.x + entering_x, region.y + local_y).0;
                    for channel in 0..4 {
                        sums[channel] += u64::from(entering[channel]);
                    }
                }
            }
        }
    }

    for local_x in 0..region.width {
        let mut sums = [0u64; 4];
        let initial_bottom = radius.min(region.height - 1);
        for local_y in 0..=initial_bottom {
            let offset = temp_offset(local_x, local_y, region.width);
            for channel in 0..4 {
                sums[channel] += u64::from(horizontal[offset + channel]);
            }
        }
        for local_y in 0..region.height {
            let top = local_y.saturating_sub(radius);
            let bottom = local_y.saturating_add(radius).min(region.height - 1);
            let count = u64::from(bottom - top + 1);
            let mut pixel = [0u8; 4];
            for channel in 0..4 {
                pixel[channel] = ((sums[channel] + count / 2) / count) as u8;
            }
            image.put_pixel(region.x + local_x, region.y + local_y, image::Rgba(pixel));
            if local_y >= radius {
                let leaving = temp_offset(local_x, local_y - radius, region.width);
                for channel in 0..4 {
                    sums[channel] -= u64::from(horizontal[leaving + channel]);
                }
            }
            if let Some(entering_y) = local_y.checked_add(radius + 1) {
                if entering_y < region.height {
                    let entering = temp_offset(local_x, entering_y, region.width);
                    for channel in 0..4 {
                        sums[channel] += u64::from(horizontal[entering + channel]);
                    }
                }
            }
        }
    }
    Ok(())
}

fn apply_recipe(mut image: DynamicImage, recipe: &ImageEditRecipe) -> Result<RgbaImage, FfiError> {
    if recipe.rotation_quarter_turns > 3 {
        return Err(image_error("rotation must be 0, 90, 180, or 270 degrees"));
    }
    if recipe.regions.len() > IMAGE_MAX_REGIONS {
        return Err(image_error("at most 16 privacy regions are allowed"));
    }
    if let Some(crop) = &recipe.crop {
        checked_rect(
            crop.x,
            crop.y,
            crop.width,
            crop.height,
            image.width(),
            image.height(),
            "crop",
        )?;
        image = image.crop_imm(crop.x, crop.y, crop.width, crop.height);
    }
    image = match recipe.rotation_quarter_turns {
        0 => image,
        1 => image.rotate90(),
        2 => image.rotate180(),
        3 => image.rotate270(),
        _ => unreachable!(),
    };
    checked_area(image.width(), image.height())?;
    let mut image = image.to_rgba8();
    for region in &recipe.regions {
        checked_rect(
            region.x,
            region.y,
            region.width,
            region.height,
            image.width(),
            image.height(),
            "privacy region",
        )?;
        match region.kind {
            ImageEditRegionKind::Blur if (1..=BLUR_MAX_RADIUS).contains(&region.strength) => {
                apply_blur(&mut image, region)?;
            }
            ImageEditRegionKind::Pixelate
                if (2..=PIXELATE_MAX_BLOCK).contains(&region.strength) =>
            {
                apply_pixelation(&mut image, region);
            }
            ImageEditRegionKind::Blur => {
                return Err(image_error("blur radius must be in 1..=32"));
            }
            ImageEditRegionKind::Pixelate => {
                return Err(image_error("pixel block size must be in 2..=64"));
            }
        }
    }
    Ok(image)
}

fn encode_canonical(image: &RgbaImage, destination: &Path) -> Result<ImageInfo, FfiError> {
    let mut output = private_destination(destination)
        .map_err(|error| image_error(format!("destination: {error}")))?;
    let result = (|| {
        PngEncoder::new_with_quality(&mut output, CompressionType::Best, FilterType::Adaptive)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )
            .map_err(|error| image_error(format!("PNG encode: {error}")))?;
        output
            .sync_all()
            .map_err(|error| image_error(error.to_string()))?;
        drop(output);
        let info = probe_edited_image(destination.display().to_string())?;
        if info.encoded_bytes > IMAGE_MAX_OUTPUT_BYTES {
            return Err(image_error("canonical PNG exceeds 64 MiB"));
        }
        Ok(info)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

fn verify_canonical_png_chunks(bytes: &[u8]) -> Result<(), FfiError> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 8 || &bytes[..8] != SIGNATURE {
        return Err(image_error("canonical output is not PNG"));
    }
    let mut offset = 8usize;
    let mut ihdr = 0usize;
    let mut idat = 0usize;
    let mut iend = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(image_error("truncated PNG chunk"));
        }
        let len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| image_error("truncated PNG length"))?,
        ) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(len))
            .ok_or_else(|| image_error("PNG chunk overflow"))?;
        if end > bytes.len() {
            return Err(image_error("truncated PNG payload"));
        }
        let kind = &bytes[offset + 4..offset + 8];
        match kind {
            b"IHDR" if offset == 8 && len == 13 && ihdr == 0 => {
                ihdr += 1;
                let header = &bytes[offset + 8..offset + 21];
                if header[8] != 8
                    || header[9] != 6
                    || header[10] != 0
                    || header[11] != 0
                    || header[12] != 0
                {
                    return Err(image_error(
                        "canonical PNG must be non-interlaced 8-bit RGBA",
                    ));
                }
            }
            b"IDAT" if ihdr == 1 && iend == 0 => idat += 1,
            b"IEND" if len == 0 && ihdr == 1 && idat != 0 && iend == 0 => iend += 1,
            _ => {
                return Err(image_error(
                    "canonical PNG contains metadata or unexpected chunks",
                ))
            }
        }
        offset = end;
        if iend == 1 && offset != bytes.len() {
            return Err(image_error("canonical PNG has trailing bytes"));
        }
    }
    if ihdr != 1 || idat == 0 || iend != 1 {
        return Err(image_error("canonical PNG is incomplete"));
    }
    Ok(())
}

/// Decode a content-verified bounded JPEG/PNG, normalize EXIF orientation,
/// apply crop then quarter-turn rotation then ordered manual privacy regions,
/// and create a new metadata-free RGBA PNG. The destination is never
/// overwritten and is removed on every failure.
#[uniffi::export]
pub fn edit_image(
    source: String,
    destination: String,
    recipe: ImageEditRecipe,
) -> Result<ImageInfo, FfiError> {
    let source = PathBuf::from(source);
    let destination = PathBuf::from(destination);
    if source == destination {
        return Err(image_error("source and destination must differ"));
    }
    let decoded = decode_source(&source)?;
    let edited = apply_recipe(decoded, &recipe)?;
    encode_canonical(&edited, &destination)
}

/// Validate and inspect an already canonical edited image. Only the exact
/// metadata-free RGBA PNG profile emitted by [`edit_image`] is accepted.
#[uniffi::export]
pub fn probe_edited_image(path: String) -> Result<ImageInfo, FfiError> {
    let path = PathBuf::from(path);
    let mut file = File::open(&path).map_err(|error| image_error(error.to_string()))?;
    let encoded_bytes = file
        .metadata()
        .map_err(|error| image_error(error.to_string()))?
        .len();
    if !(1..=IMAGE_MAX_OUTPUT_BYTES).contains(&encoded_bytes) {
        return Err(image_error("canonical PNG is empty or exceeds 64 MiB"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_bytes as usize)
        .map_err(|_| image_error("not enough storage to validate PNG"))?;
    file.read_to_end(&mut bytes)
        .map_err(|error| image_error(error.to_string()))?;
    verify_canonical_png_chunks(&bytes)?;

    let mut reader = ImageReader::new(std::io::Cursor::new(&bytes));
    reader.set_format(ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
    limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
    limits.max_alloc = Some(IMAGE_MAX_DECODE_ALLOC);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| image_error(format!("canonical PNG decode: {error}")))?
        .to_rgba8();
    checked_area(image.width(), image.height())?;
    Ok(ImageInfo {
        width: image.width(),
        height: image.height(),
        encoded_bytes,
        has_alpha: image.pixels().any(|pixel| pixel.0[3] != 255),
        media_type: IMAGE_MEDIA_TYPE.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::jpeg::JpegEncoder;
    use image::{ImageBuffer, Rgba};

    fn source_pixels() -> RgbaImage {
        ImageBuffer::from_fn(5, 3, |x, y| {
            Rgba([
                (x * 40 + y) as u8,
                (y * 70 + x) as u8,
                (x * 11 + y * 17) as u8,
                if x == 4 && y == 2 { 80 } else { 255 },
            ])
        })
    }

    fn write_png(path: &Path, pixels: &RgbaImage) {
        let file = File::create(path).unwrap();
        PngEncoder::new(file)
            .write_image(
                pixels.as_raw(),
                pixels.width(),
                pixels.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
    }

    fn orientation_exif(value: u16) -> Vec<u8> {
        let mut exif = Vec::new();
        exif.extend_from_slice(b"II*");
        exif.push(0);
        exif.extend_from_slice(&8u32.to_le_bytes());
        exif.extend_from_slice(&1u16.to_le_bytes());
        exif.extend_from_slice(&0x0112u16.to_le_bytes());
        exif.extend_from_slice(&3u16.to_le_bytes());
        exif.extend_from_slice(&1u32.to_le_bytes());
        exif.extend_from_slice(&value.to_le_bytes());
        exif.extend_from_slice(&0u16.to_le_bytes());
        exif.extend_from_slice(&0u32.to_le_bytes());
        exif
    }

    #[test]
    fn orientation_crop_rotation_regions_and_metadata_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("camera.bin");
        let first = dir.path().join("edited-one.png");
        let second = dir.path().join("edited-two.png");
        let rgb = DynamicImage::ImageRgba8(source_pixels()).to_rgb8();
        let mut encoded = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut encoded, 100);
        encoder.set_exif_metadata(orientation_exif(6)).unwrap();
        encoder
            .write_image(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        std::fs::write(&source, encoded).unwrap();

        let recipe = ImageEditRecipe {
            // EXIF orientation 6 makes the oriented source 3x5.
            crop: Some(ImageCrop {
                x: 0,
                y: 1,
                width: 3,
                height: 4,
            }),
            rotation_quarter_turns: 1,
            regions: vec![
                ImageEditRegion {
                    kind: ImageEditRegionKind::Pixelate,
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                    strength: 2,
                },
                ImageEditRegion {
                    kind: ImageEditRegionKind::Blur,
                    x: 2,
                    y: 0,
                    width: 2,
                    height: 3,
                    strength: 1,
                },
            ],
        };
        let info = edit_image(
            source.display().to_string(),
            first.display().to_string(),
            recipe.clone(),
        )
        .unwrap();
        edit_image(
            source.display().to_string(),
            second.display().to_string(),
            recipe,
        )
        .unwrap();
        assert_eq!((info.width, info.height), (4, 3));
        assert_eq!(
            std::fs::read(&first).unwrap(),
            std::fs::read(&second).unwrap()
        );
        let output = std::fs::read(first).unwrap();
        for secret in [b"Exif".as_slice(), b"GPS", b"camera", b"XML", b"tEXt"] {
            assert!(!output.windows(secret.len()).any(|window| window == secret));
        }
    }

    #[test]
    fn png_alpha_is_preserved_and_output_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.png");
        let output = dir.path().join("output.png");
        write_png(&source, &source_pixels());
        let info = edit_image(
            source.display().to_string(),
            output.display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            },
        )
        .unwrap();
        assert_eq!((info.width, info.height, info.has_alpha), (5, 3, true));
        assert_eq!(
            info,
            probe_edited_image(output.display().to_string()).unwrap()
        );
    }

    #[test]
    fn malformed_spoofed_truncated_oversized_dimensions_and_recipes_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("never-created.png");
        for (name, bytes) in [
            ("spoof.jpg", b"not an image".to_vec()),
            ("truncated.png", b"\x89PNG\r\n\x1a\n\0\0".to_vec()),
        ] {
            let source = dir.path().join(name);
            std::fs::write(&source, bytes).unwrap();
            assert!(edit_image(
                source.display().to_string(),
                destination.display().to_string(),
                ImageEditRecipe {
                    crop: None,
                    rotation_quarter_turns: 0,
                    regions: vec![],
                }
            )
            .is_err());
            assert!(!destination.exists());
        }

        let source = dir.path().join("valid.png");
        write_png(&source, &source_pixels());
        assert!(edit_image(
            source.display().to_string(),
            destination.display().to_string(),
            ImageEditRecipe {
                crop: Some(ImageCrop {
                    x: 4,
                    y: 0,
                    width: 2,
                    height: 1,
                }),
                rotation_quarter_turns: 0,
                regions: vec![],
            }
        )
        .is_err());
        assert!(!destination.exists());

        let over_dimension = dir.path().join("over-dimension.png");
        write_png(&over_dimension, &RgbaImage::new(IMAGE_MAX_DIMENSION + 1, 1));
        assert!(edit_image(
            over_dimension.display().to_string(),
            destination.display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            }
        )
        .is_err());
        assert!(!destination.exists());

        let animated = dir.path().join("animated.png");
        let mut animated_bytes = std::fs::read(&source).unwrap();
        let iend = animated_bytes.len() - 12;
        animated_bytes.splice(
            iend..iend,
            [
                0, 0, 0, 8, b'a', b'c', b'T', b'L', 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
        std::fs::write(&animated, animated_bytes).unwrap();
        let error = edit_image(
            animated.display().to_string(),
            destination.display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("animated PNG"), "got: {error}");
        assert!(!destination.exists());

        let oversized = dir.path().join("oversized.jpg");
        let oversized_file = std::fs::File::create(&oversized).unwrap();
        oversized_file.set_len(IMAGE_MAX_INPUT_BYTES + 1).unwrap();
        assert!(edit_image(
            oversized.display().to_string(),
            destination.display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            }
        )
        .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn destination_is_create_new_and_noncanonical_png_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.png");
        let destination = dir.path().join("existing.png");
        write_png(&source, &source_pixels());
        std::fs::write(&destination, b"keep").unwrap();
        assert!(edit_image(
            source.display().to_string(),
            destination.display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            }
        )
        .is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep");
        let metadata = dir.path().join("metadata.png");
        let mut bytes = std::fs::read(&source).unwrap();
        let iend = bytes.len() - 12;
        bytes.splice(
            iend..iend,
            [
                0, 0, 0, 4, b't', b'E', b'X', b't', b'l', b'e', b'a', b'k', 0, 0, 0, 0,
            ],
        );
        std::fs::write(&metadata, bytes).unwrap();
        assert!(probe_edited_image(metadata.display().to_string()).is_err());
    }
}
