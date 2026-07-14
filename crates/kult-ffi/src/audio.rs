//! Bounded, metadata-free recorded-audio profile shared by every shell.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::FfiError;

/// Canonical attachment MIME type for recorded audio.
pub const AUDIO_MEDIA_TYPE: &str = "audio/wav";
/// Canonical mono sample rate supported by every application floor.
pub const AUDIO_SAMPLE_RATE: u32 = 16_000;
/// Canonical channel count.
pub const AUDIO_CHANNELS: u16 = 1;
/// Canonical signed little-endian PCM sample width.
pub const AUDIO_BITS_PER_SAMPLE: u16 = 16;
/// Maximum recording duration. Recorders stop at this boundary and never truncate silently.
pub const AUDIO_MAX_DURATION_MS: u64 = 60_000;
/// Maximum canonical file size, including the 44-byte RIFF/WAVE header.
pub const AUDIO_MAX_BYTES: u64 = 44 + 60 * 16_000 * 2;
/// Fixed number of locally derived waveform peaks.
pub const AUDIO_WAVEFORM_BINS: usize = 64;

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const PCM_BYTES_PER_SECOND: u64 = AUDIO_SAMPLE_RATE as u64 * 2;

/// Safe local presentation data derived from the actual canonical bytes.
/// Nothing in this record is sent on the wire.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AudioInfo {
    /// Exact duration rounded down to milliseconds.
    pub duration_ms: u64,
    /// Exact encoded file size.
    pub encoded_bytes: u64,
    /// Mono PCM sample count.
    pub sample_count: u64,
    /// Sixty-four peak amplitudes in source order, each in `0..=32768`.
    pub waveform: Vec<u16>,
}

#[derive(Clone, Copy)]
struct WaveData {
    offset: u64,
    len: u64,
}

fn audio_error(reason: impl Into<String>) -> FfiError {
    FfiError::Node {
        reason: format!("recorded audio: {}", reason.into()),
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn locate_pcm(file: &mut File) -> Result<WaveData, FfiError> {
    let file_len = file
        .metadata()
        .map_err(|error| audio_error(error.to_string()))?
        .len();
    if !(44..=MAX_SOURCE_BYTES).contains(&file_len) {
        return Err(audio_error("source size is outside the 60 second limit"));
    }
    let mut header = [0u8; 12];
    file.read_exact(&mut header)
        .map_err(|_| audio_error("truncated RIFF header"))?;
    if &header[..4] != b"RIFF" || &header[8..] != b"WAVE" {
        return Err(audio_error("content is not RIFF/WAVE PCM"));
    }
    let declared = u64::from(read_u32(&header[4..8])) + 8;
    if declared != file_len {
        return Err(audio_error("RIFF length does not match the file"));
    }

    let mut position = 12u64;
    let mut format_seen = false;
    let mut data = None;
    while position < file_len {
        if file_len - position < 8 {
            return Err(audio_error("truncated chunk header"));
        }
        file.seek(SeekFrom::Start(position))
            .map_err(|error| audio_error(error.to_string()))?;
        let mut chunk = [0u8; 8];
        file.read_exact(&mut chunk)
            .map_err(|_| audio_error("truncated chunk header"))?;
        let chunk_len = u64::from(read_u32(&chunk[4..]));
        let payload = position + 8;
        let padded = chunk_len
            .checked_add(chunk_len & 1)
            .ok_or_else(|| audio_error("chunk length overflow"))?;
        let next = payload
            .checked_add(padded)
            .ok_or_else(|| audio_error("chunk length overflow"))?;
        if next > file_len {
            return Err(audio_error("truncated chunk payload"));
        }
        match &chunk[..4] {
            b"fmt " => {
                if format_seen || !(16..=64).contains(&chunk_len) {
                    return Err(audio_error("invalid format chunk"));
                }
                let mut format = [0u8; 16];
                file.read_exact(&mut format)
                    .map_err(|_| audio_error("truncated format chunk"))?;
                if read_u16(&format[0..2]) != 1
                    || read_u16(&format[2..4]) != AUDIO_CHANNELS
                    || read_u32(&format[4..8]) != AUDIO_SAMPLE_RATE
                    || read_u32(&format[8..12]) != AUDIO_SAMPLE_RATE * 2
                    || read_u16(&format[12..14]) != 2
                    || read_u16(&format[14..16]) != AUDIO_BITS_PER_SAMPLE
                {
                    return Err(audio_error(
                        "expected mono 16-bit little-endian PCM at 16000 Hz",
                    ));
                }
                format_seen = true;
            }
            b"data" => {
                if data.is_some() || chunk_len == 0 || chunk_len % 2 != 0 {
                    return Err(audio_error("invalid PCM data chunk"));
                }
                data = Some(WaveData {
                    offset: payload,
                    len: chunk_len,
                });
            }
            _ => {}
        }
        position = next;
    }
    if !format_seen {
        return Err(audio_error("missing format chunk"));
    }
    let data = data.ok_or_else(|| audio_error("missing PCM data chunk"))?;
    if data.len > AUDIO_MAX_BYTES - 44 {
        return Err(audio_error("recording exceeds 60 seconds"));
    }
    Ok(data)
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

fn canonical_header(data_len: u32) -> [u8; 44] {
    let mut header = [0u8; 44];
    header[0..4].copy_from_slice(b"RIFF");
    header[4..8].copy_from_slice(&(36 + data_len).to_le_bytes());
    header[8..12].copy_from_slice(b"WAVE");
    header[12..16].copy_from_slice(b"fmt ");
    header[16..20].copy_from_slice(&16u32.to_le_bytes());
    header[20..22].copy_from_slice(&1u16.to_le_bytes());
    header[22..24].copy_from_slice(&AUDIO_CHANNELS.to_le_bytes());
    header[24..28].copy_from_slice(&AUDIO_SAMPLE_RATE.to_le_bytes());
    header[28..32].copy_from_slice(&(AUDIO_SAMPLE_RATE * 2).to_le_bytes());
    header[32..34].copy_from_slice(&2u16.to_le_bytes());
    header[34..36].copy_from_slice(&AUDIO_BITS_PER_SAMPLE.to_le_bytes());
    header[36..40].copy_from_slice(b"data");
    header[40..44].copy_from_slice(&data_len.to_le_bytes());
    header
}

fn derive_info(file: &mut File, data: WaveData, encoded_bytes: u64) -> Result<AudioInfo, FfiError> {
    let samples = data.len / 2;
    let mut peaks = [0u16; AUDIO_WAVEFORM_BINS];
    file.seek(SeekFrom::Start(data.offset))
        .map_err(|error| audio_error(error.to_string()))?;
    let mut buffer = [0u8; 8192];
    let mut remaining = data.len;
    let mut sample_index = 0u64;
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..take])
            .map_err(|_| audio_error("truncated PCM data"))?;
        for bytes in buffer[..take].chunks_exact(2) {
            let sample = i16::from_le_bytes([bytes[0], bytes[1]]);
            let amplitude = sample.unsigned_abs();
            let bin =
                usize::try_from(sample_index.saturating_mul(AUDIO_WAVEFORM_BINS as u64) / samples)
                    .unwrap_or(AUDIO_WAVEFORM_BINS - 1)
                    .min(AUDIO_WAVEFORM_BINS - 1);
            peaks[bin] = peaks[bin].max(amplitude);
            sample_index += 1;
        }
        remaining -= take as u64;
    }
    Ok(AudioInfo {
        duration_ms: data.len.saturating_mul(1_000) / PCM_BYTES_PER_SECOND,
        encoded_bytes,
        sample_count: samples,
        waveform: peaks.to_vec(),
    })
}

/// Rewrite a supported PCM WAVE recording into the one canonical, metadata-free
/// Komms representation. The destination is private, newly created, and removed
/// on every failure. Callers delete the raw source after this returns.
#[uniffi::export]
pub fn canonicalize_recorded_audio(
    source: String,
    destination: String,
) -> Result<AudioInfo, FfiError> {
    let source = PathBuf::from(source);
    let destination = PathBuf::from(destination);
    if source == destination {
        return Err(audio_error("source and destination must differ"));
    }
    let mut input = File::open(&source).map_err(|error| audio_error(error.to_string()))?;
    let data = locate_pcm(&mut input)?;
    let mut output = private_destination(&destination)
        .map_err(|error| audio_error(format!("destination: {error}")))?;
    let result = (|| {
        output
            .write_all(&canonical_header(data.len as u32))
            .map_err(|error| audio_error(error.to_string()))?;
        input
            .seek(SeekFrom::Start(data.offset))
            .map_err(|error| audio_error(error.to_string()))?;
        io::copy(&mut Read::by_ref(&mut input).take(data.len), &mut output)
            .map_err(|error| audio_error(error.to_string()))?;
        output
            .sync_all()
            .map_err(|error| audio_error(error.to_string()))?;
        drop(output);
        probe_recorded_audio(destination.display().to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&destination);
    }
    result
}

/// Validate and probe an already-canonical recorded-audio attachment. Extra
/// chunks, trailing bytes, spoofed formats, and oversized allocations fail closed.
#[uniffi::export]
pub fn probe_recorded_audio(path: String) -> Result<AudioInfo, FfiError> {
    let mut file = File::open(&path).map_err(|error| audio_error(error.to_string()))?;
    let encoded_bytes = file
        .metadata()
        .map_err(|error| audio_error(error.to_string()))?
        .len();
    if !(46..=AUDIO_MAX_BYTES).contains(&encoded_bytes) {
        return Err(audio_error("canonical size is outside the 60 second limit"));
    }
    let data = locate_pcm(&mut file)?;
    if data.offset != 44 || data.len + 44 != encoded_bytes {
        return Err(audio_error(
            "file contains non-canonical metadata or chunks",
        ));
    }
    derive_info(&mut file, data, encoded_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wave(samples: &[i16], extra_chunk: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let extra = if extra_chunk { 12 } else { 0 };
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36u32 + samples.len() as u32 * 2 + extra).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&16_000u32.to_le_bytes());
        bytes.extend_from_slice(&32_000u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        if extra_chunk {
            bytes.extend_from_slice(b"LIST");
            bytes.extend_from_slice(&4u32.to_le_bytes());
            bytes.extend_from_slice(b"leak");
        }
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&(samples.len() as u32 * 2).to_le_bytes());
        for sample in samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn canonicalization_strips_metadata_and_derives_duration_waveform() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("native.wav");
        let destination = dir.path().join("canonical.wav");
        let mut samples = vec![0i16; 16_000];
        samples[8_000] = -12_345;
        std::fs::write(&source, wave(&samples, true)).unwrap();

        let info = canonicalize_recorded_audio(
            source.display().to_string(),
            destination.display().to_string(),
        )
        .unwrap();
        assert_eq!(info.duration_ms, 1_000);
        assert_eq!(info.encoded_bytes, 32_044);
        assert_eq!(info.sample_count, 16_000);
        assert_eq!(info.waveform.iter().copied().max(), Some(12_345));
        let bytes = std::fs::read(destination).unwrap();
        assert_eq!(&bytes[0..12], b"RIFF$}\0\0WAVE");
        assert!(!bytes
            .windows(4)
            .any(|part| part == b"LIST" || part == b"leak"));
    }

    #[test]
    fn malformed_spoofed_truncated_and_noncanonical_audio_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("spoof.wav", b"not a wave".to_vec()),
            ("truncated.wav", wave(&[1, 2, 3], false)[..45].to_vec()),
            ("metadata.wav", wave(&[1, 2, 3], true)),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(
                probe_recorded_audio(path.display().to_string()).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn destination_is_not_overwritten_or_retained_after_failure() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.wav");
        let destination = dir.path().join("destination.wav");
        std::fs::write(&source, wave(&[1, 2], false)).unwrap();
        std::fs::write(&destination, b"keep").unwrap();
        assert!(canonicalize_recorded_audio(
            source.display().to_string(),
            destination.display().to_string(),
        )
        .is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"keep");
    }
}
