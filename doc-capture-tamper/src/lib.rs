//! `doc-capture-tamper` — Error-Level Analysis tamper detector.
//!
//! Identifies regions of a JPEG image whose compression artifacts
//! diverge from the rest, which correlates with digital editing.
//! The technique is well-known in forensic image analysis under the
//! name "Error-Level Analysis" (ELA).
//!
//! ## Algorithm
//!
//! 1. Decode the input image to RGB8.
//! 2. Re-encode it as a JPEG at a fixed quality (default 90).
//! 3. Decode the re-encoded JPEG back to RGB8.
//! 4. Compute per-pixel L∞ distance between original and re-decoded.
//! 5. Score = mean distance / 255 (roughly `[0.0, 1.0]`, heavily
//!    skewed toward 0).
//! 6. `suspicious` = score > threshold (default 0.05).
//!
//! ## Caveats
//!
//! ELA is a HEURISTIC, not a proof. A camera-captured image of an
//! authentic document with strong contrast edges (e.g. high-DPI ID
//! card photos) will produce a moderate ELA score. An expertly-
//! edited image with careful re-compression at matching quality
//! will produce a low ELA score. Use ELA as ONE signal among
//! several — never as a sole tamper verdict.
//!
//! ## Why pure Rust
//!
//! No native deps (Tesseract, OpenCV, ImageMagick). The `image`
//! crate has pure-Rust JPEG + PNG codecs which are slow but
//! deterministic and trivially portable. For the volume a
//! per-capture sidecar handles (10s-100s/min, not 1000s), this is
//! adequate. If throughput becomes an issue, swap in `mozjpeg-sys`
//! behind a feature gate.

#![deny(missing_docs)]

use doc_capture_core::{Error, TamperSignals};
use image::{ImageEncoder, ImageReader};
use std::io::Cursor;

/// Default JPEG quality for the re-encode step. 90 is a typical
/// "high" quality that's close to what camera apps emit, so a
/// genuine camera capture should produce a low ELA score against
/// this baseline.
pub const DEFAULT_REENCODE_QUALITY: u8 = 90;

/// Default suspicious threshold. Cameras-of-IDs typically score
/// 0.01-0.03; edited regions push the score above 0.05.
pub const DEFAULT_SUSPICIOUS_THRESHOLD: f32 = 0.05;

/// Run Error-Level Analysis on the supplied image bytes.
///
/// `bytes` must be JPEG or PNG. Returns a [`TamperSignals`] struct
/// with `ela_score` in `[0.0, ~0.3]` and `suspicious` set per the
/// default threshold.
///
/// Errors:
/// - [`Error::InvalidImage`] if the bytes don't decode as an image.
/// - [`Error::Upstream`] if re-encode + re-decode fails (rare;
///   shouldn't happen on bytes that already decoded once).
pub fn analyze_ela(bytes: &[u8]) -> Result<TamperSignals, Error> {
    analyze_ela_with(
        bytes,
        DEFAULT_REENCODE_QUALITY,
        DEFAULT_SUSPICIOUS_THRESHOLD,
    )
}

/// Run Error-Level Analysis with caller-specified quality and
/// threshold. Most callers want [`analyze_ela`]; this exists for
/// testing different operating points + for consumers with a
/// non-default threshold policy.
pub fn analyze_ela_with(
    bytes: &[u8],
    reencode_quality: u8,
    suspicious_threshold: f32,
) -> Result<TamperSignals, Error> {
    // Decode input → RGB8.
    let img = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| Error::InvalidImage(format!("format guess: {e}")))?
        .decode()
        .map_err(|e| Error::InvalidImage(format!("decode: {e}")))?
        .to_rgb8();

    // Re-encode as JPEG.
    let mut reencoded: Vec<u8> = Vec::new();
    {
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
            &mut reencoded,
            reencode_quality,
        );
        encoder
            .write_image(
                img.as_raw(),
                img.width(),
                img.height(),
                image::ExtendedColorType::Rgb8,
            )
            .map_err(|e| Error::Upstream(format!("ela reencode: {e}")))?;
    }

    // Decode re-encoded JPEG.
    let reimg = ImageReader::new(Cursor::new(&reencoded))
        .with_guessed_format()
        .map_err(|e| Error::Upstream(format!("ela reread guess: {e}")))?
        .decode()
        .map_err(|e| Error::Upstream(format!("ela reread decode: {e}")))?
        .to_rgb8();

    if reimg.dimensions() != img.dimensions() {
        return Err(Error::Upstream(format!(
            "ela dimension mismatch original={:?} reencoded={:?}",
            img.dimensions(),
            reimg.dimensions()
        )));
    }

    // Compute per-pixel L∞ distance + accumulate into mean.
    let orig = img.as_raw();
    let re = reimg.as_raw();
    debug_assert_eq!(orig.len(), re.len());
    let pixel_count = (img.width() as usize) * (img.height() as usize);
    let mut sum_distance: u64 = 0;
    let mut max_distance: u8 = 0;
    for i in 0..pixel_count {
        let r = (orig[i * 3] as i16 - re[i * 3] as i16).unsigned_abs() as u8;
        let g = (orig[i * 3 + 1] as i16 - re[i * 3 + 1] as i16).unsigned_abs() as u8;
        let b = (orig[i * 3 + 2] as i16 - re[i * 3 + 2] as i16).unsigned_abs() as u8;
        let d = r.max(g).max(b);
        sum_distance += d as u64;
        if d > max_distance {
            max_distance = d;
        }
    }
    let mean_distance = sum_distance as f32 / pixel_count as f32;
    // Score is mean_distance scaled to [0, 1] by dividing by 255.
    let ela_score = (mean_distance / 255.0).clamp(0.0, 1.0);
    let suspicious = ela_score > suspicious_threshold;

    Ok(TamperSignals {
        suspicious,
        ela_score,
        // Estimating original JPEG quality from quantization tables
        // is a separate analysis (see Hany Farid's quality-from-
        // quantization-table work). Stub at 0.0 for MVP; a follow-
        // up commit can wire a quality estimator.
        estimated_jpeg_quality: 0.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};

    /// Encode an RgbImage to JPEG bytes at the given quality.
    fn rgb_to_jpeg(img: &ImageBuffer<Rgb<u8>, Vec<u8>>, quality: u8) -> Vec<u8> {
        let mut out = Vec::new();
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
        encoder
            .write_image(
                img.as_raw(),
                img.width(),
                img.height(),
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        out
    }

    /// Make a 64x64 solid-color image.
    fn solid_image(r: u8, g: u8, b: u8) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        ImageBuffer::from_fn(64, 64, |_, _| Rgb([r, g, b]))
    }

    /// Make a 64x64 gradient image (smooth, low-frequency).
    fn gradient_image() -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        ImageBuffer::from_fn(64, 64, |x, y| {
            Rgb([
                (x * 4) as u8,
                (y * 4) as u8,
                ((x + y) * 2) as u8,
            ])
        })
    }

    /// Make a 64x64 image with a sharp colour block pasted into the
    /// center (simulating "edit a region into an otherwise clean
    /// camera capture").
    fn pasted_block_image() -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        let mut img = gradient_image();
        for y in 20..44 {
            for x in 20..44 {
                img.put_pixel(x, y, Rgb([255, 0, 0])); // pure red block
            }
        }
        img
    }

    #[test]
    fn solid_image_has_very_low_ela_score() {
        // A constant-colour image compresses identically every time
        // — ELA score should be effectively zero.
        let jpeg = rgb_to_jpeg(&solid_image(128, 128, 128), 90);
        let sig = analyze_ela(&jpeg).unwrap();
        assert!(
            sig.ela_score < 0.01,
            "solid image ELA should be near-zero, got {}",
            sig.ela_score
        );
        assert!(!sig.suspicious);
    }

    #[test]
    fn gradient_image_has_low_ela_score() {
        // A smooth gradient at high JPEG quality should also
        // produce a low score (well under the threshold).
        let jpeg = rgb_to_jpeg(&gradient_image(), 90);
        let sig = analyze_ela(&jpeg).unwrap();
        assert!(
            sig.ela_score < DEFAULT_SUSPICIOUS_THRESHOLD,
            "gradient should be under threshold {}, got {}",
            DEFAULT_SUSPICIOUS_THRESHOLD,
            sig.ela_score
        );
        assert!(!sig.suspicious);
    }

    #[test]
    fn invalid_bytes_return_invalid_image_error() {
        let r = analyze_ela(b"not an image");
        assert!(matches!(r, Err(Error::InvalidImage(_))));
    }

    #[test]
    fn ela_score_in_valid_range() {
        // The score is always in [0.0, 1.0] regardless of input.
        let jpeg = rgb_to_jpeg(&pasted_block_image(), 90);
        let sig = analyze_ela(&jpeg).unwrap();
        assert!(
            (0.0..=1.0).contains(&sig.ela_score),
            "score out of [0,1]: {}",
            sig.ela_score
        );
    }

    #[test]
    fn custom_threshold_changes_suspicious_verdict() {
        // Same image, different thresholds — verdict should flip.
        let jpeg = rgb_to_jpeg(&pasted_block_image(), 90);
        let lenient = analyze_ela_with(&jpeg, 90, 1.0).unwrap();
        let strict = analyze_ela_with(&jpeg, 90, 0.0).unwrap();
        assert!(!lenient.suspicious, "lenient threshold should pass");
        assert!(strict.suspicious, "strict threshold should flag");
        // Score itself is independent of threshold.
        assert_eq!(lenient.ela_score, strict.ela_score);
    }

    #[test]
    fn png_input_also_works() {
        // PNG inputs are common for synthesized fixtures (the
        // PDF417 test in doc-capture-pdf417 emits PNG). ELA still
        // runs by re-encoding to JPEG internally.
        let png = {
            let mut out = Vec::new();
            let img = gradient_image();
            let dyn_img = image::DynamicImage::ImageRgb8(img);
            dyn_img
                .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
                .unwrap();
            out
        };
        let sig = analyze_ela(&png).unwrap();
        assert!(sig.ela_score < DEFAULT_SUSPICIOUS_THRESHOLD);
    }
}
