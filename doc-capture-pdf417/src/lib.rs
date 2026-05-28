//! `doc-capture-pdf417` — PDF417 binary barcode decoder.
//!
//! Takes raw image bytes (JPEG/PNG) and extracts the text payload
//! encoded in any PDF417 barcode visible in the image. The decoded
//! text is what the AAMVA decoder consumes downstream.
//!
//! ## Why a thin wrapper
//!
//! [`rxing`](https://crates.io/crates/rxing) is the de-facto Rust
//! port of the `ZXing` barcode library. It supports every modern 2D
//! and 1D barcode format including PDF417 with full Reed-Solomon
//! error correction and the various binary/text mode-switching
//! states the PDF417 spec defines. Re-implementing all that would
//! take months and would duplicate work that's already been audited
//! by the `ZXing` community.
//!
//! Per the project's AVP-2 absorption doctrine we wrap rxing behind
//! a small adapter so the consumer-facing surface is tiny and stable.
//! When the AVP-2 absorption pass for rxing completes we can swap to
//! a hardened fork without touching call sites.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

// FOSS-ABSORBED: rxing 0.9 (Apache-2.0), the Rust port of ZXing. Wrapped
// behind the thin `decode_pdf417_from_image_bytes` adapter below so the
// dependency surface stays tiny and a future hardened fork can be swapped
// in without touching call sites. Full AVP-2 absorption pass pending.
use doc_capture_core::Error;
use rxing::BarcodeFormat;

/// Decode the FIRST PDF417 barcode found in the supplied image bytes.
///
/// Accepts any image format rxing can ingest (JPEG, PNG, BMP, GIF,
/// TIFF). Returns the raw text payload — typically an AAMVA-format
/// string for US driver licenses, or arbitrary text for other
/// PDF417 use cases.
///
/// # Errors
///
/// Returns [`Error::InvalidImage`] when the image bytes can't be
/// decoded as an image, [`Error::Pdf417DecodeFailed`] when no PDF417
/// barcode is found or the decode fails for any other reason.
pub fn decode_pdf417_from_image_bytes(bytes: &[u8]) -> Result<String, Error> {
    let result =
        rxing::helpers::detect_in_buffer(bytes, Some(BarcodeFormat::PDF_417)).map_err(|e| {
            // rxing surfaces two failure shapes: image-decode failure
            // (bytes weren't an image) and detect failure (image OK but
            // no PDF417 found / unreadable). Distinguish by the prefix
            // of the error string — the image-load path emits "buffer
            // cannot be loaded as image" verbatim per helpers.rs:138.
            let s = e.to_string();
            if s.contains("cannot be loaded as image") {
                Error::InvalidImage(s)
            } else {
                Error::Pdf417DecodeFailed(s)
            }
        })?;

    Ok(result.getText().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rxing::Writer;

    /// Encode + decode roundtrip via rxing.
    ///
    /// Synthesizes a PDF417 image from a known payload, then feeds
    /// that image back through the decoder and verifies the text
    /// comes through intact. This pins both that we wired rxing
    /// correctly AND that the decoder works against bytes we
    /// produced ourselves (i.e. it's not skipping the actual scan).
    #[test]
    fn pdf417_roundtrip_short_payload() {
        let payload = "ROUNDTRIP TEST PAYLOAD 12345";
        let img = synthesize_pdf417_png(payload).expect("encode");
        let decoded = decode_pdf417_from_image_bytes(&img).expect("decode");
        assert_eq!(decoded, payload, "PDF417 roundtrip should preserve text");
    }

    #[test]
    fn pdf417_roundtrip_realistic_aamva_length() {
        // Real AAMVA payloads are 300-800 bytes. Test with a
        // representative-length payload.
        let mut payload = String::from("@\nANSI 636040100000DL00330700DL\n");
        payload.push_str("DAQX12345678\n");
        payload.push_str("DCSDOE\n");
        payload.push_str("DACJOHN\n");
        payload.push_str("DADMICHAEL\n");
        payload.push_str("DBB01151985\n");
        payload.push_str("DBA12312030\n");
        payload.push_str("DBD06012024\n");
        payload.push_str("DAG3071 LIMESTONE DR\n");
        payload.push_str("DAISAINT GEORGE\n");
        payload.push_str("DAJUT\n");
        payload.push_str("DAK847900000\n");
        payload.push_str("DBC1\n");
        let img = synthesize_pdf417_png(&payload).expect("encode");
        let decoded = decode_pdf417_from_image_bytes(&img).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_rejects_non_image_bytes() {
        let r = decode_pdf417_from_image_bytes(b"not an image at all");
        assert!(matches!(r, Err(Error::InvalidImage(_))));
    }

    /// Synthesize a PDF417 image PNG from a text payload. Used by
    /// roundtrip tests above. Not exposed publicly because consumers
    /// of this crate only DECODE — encoding lives in test code.
    fn synthesize_pdf417_png(text: &str) -> Result<Vec<u8>, String> {
        let writer = rxing::pdf417::PDF417Writer {};
        let bitmatrix = writer
            .encode(text, &BarcodeFormat::PDF_417, 600, 300)
            .map_err(|e| format!("encode: {e}"))?;
        // Convert bitmatrix to a luma8 image then PNG.
        let w = bitmatrix.getWidth();
        let h = bitmatrix.getHeight();
        let mut buf: Vec<u8> = Vec::with_capacity((w * h) as usize);
        for y in 0..h {
            for x in 0..w {
                buf.push(if bitmatrix.get(x, y) { 0 } else { 255 });
            }
        }
        let img =
            image::GrayImage::from_raw(w, h, buf).ok_or_else(|| "image::from_raw".to_string())?;
        let dyn_img = image::DynamicImage::ImageLuma8(img);
        let mut png = Vec::new();
        let mut cur = std::io::Cursor::new(&mut png);
        dyn_img
            .write_to(&mut cur, image::ImageFormat::Png)
            .map_err(|e| format!("png write: {e}"))?;
        Ok(png)
    }
}
