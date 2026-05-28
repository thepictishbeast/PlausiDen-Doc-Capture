//! `doc-capture-ocr` — OCR adapter for the document-capture pipeline.
//!
//! Exposes a small typed trait, [`OcrEngine`], that the pipeline
//! orchestrator calls. Implementations are pluggable so a consumer
//! can choose between:
//!
//!   - [`MockOcrEngine`] — deterministic, returns canned text.
//!     Always available, no native deps. Used by tests and in
//!     "OCR disabled" deployments.
//!   - `TesseractCliEngine` — shells out to the `tesseract`
//!     command-line binary. Available when the crate is built
//!     with `--features tesseract-cli`. Tesseract must be on the
//!     server's PATH at runtime.
//!
//! Future engines (FFI Tesseract via `tesseract-rs`, `PaddleOCR` via
//! sidecar, vendor adapters) implement the same trait without
//! touching consumer call sites.
//!
//! ## Privacy posture
//!
//! Implementations receive image bytes by reference, never persist
//! them, and never log their content. The CLI adapter writes the
//! image to a temp file (Tesseract needs a path), invokes
//! `tesseract`, then deletes the temp file in a `Drop` guard before
//! returning. On panic / crash the OS-level temp-file cleanup
//! catches anything the `Drop` missed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use doc_capture_core::{Error, OcrSignals};
use std::collections::HashMap;

/// Output of an OCR pass: extracted text + per-stage signals.
#[derive(Debug, Clone)]
pub struct OcrResult {
    /// Full text extracted from the image.
    pub text: String,
    /// Per-stage signals to feed back into the pipeline's
    /// [`PipelineSignals`](doc_capture_core::PipelineSignals).
    pub signals: OcrSignals,
    /// Per-line text + confidence, when the engine surfaces it.
    /// Tesseract emits this via `tsv` output mode; the Mock engine
    /// returns an empty vec.
    pub lines: Vec<OcrLine>,
}

/// One line of OCR output.
#[derive(Debug, Clone)]
pub struct OcrLine {
    /// Recognized text on this line.
    pub text: String,
    /// Per-line confidence in `[0.0, 1.0]`.
    pub confidence: f32,
}

/// Pluggable OCR engine trait.
///
/// Implementations are stateless from the consumer's POV: pass image
/// bytes, get back text + signals. Engines that need warmup state
/// (e.g. a Tesseract instance) own that internally.
pub trait OcrEngine: Send + Sync {
    /// Run OCR on the supplied image bytes.
    ///
    /// `language` is an engine-specific hint (e.g. `"eng"` for
    /// Tesseract). Engines that don't honor it ignore the value.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the image cannot be decoded or the
    /// underlying OCR backend fails.
    fn recognize(&self, image_bytes: &[u8], language: &str) -> Result<OcrResult, Error>;

    /// Engine identifier for logs and `/info`.
    fn name(&self) -> &'static str;
}

/// Mock OCR engine: returns canned text from a pre-loaded fixture
/// map keyed on `sha256(image_bytes)`.
///
/// Used by tests to drive the orchestrator without needing
/// Tesseract installed. Also useful in deployments where OCR is
/// explicitly disabled — the Mock returns
/// `OcrSignals { text_confidence: 0.0, required_fields_present:
/// false, detected_orientation: 0 }` for any unknown image, which
/// the pipeline reads as "OCR didn't recognize anything" without
/// failing the whole capture.
#[derive(Debug, Default)]
pub struct MockOcrEngine {
    fixtures: HashMap<String, OcrResult>,
}

impl MockOcrEngine {
    /// Construct an empty Mock. Any image not added via
    /// [`with_fixture`](Self::with_fixture) returns the zero-signal
    /// "no recognition" outcome.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a canned OCR result for a specific image-byte hash.
    /// Tests use this to set up known-good and known-bad fixtures
    /// without involving an OCR engine.
    #[must_use]
    pub fn with_fixture(mut self, image_bytes: &[u8], result: OcrResult) -> Self {
        let key = hex::encode(sha256(image_bytes));
        self.fixtures.insert(key, result);
        self
    }
}

impl OcrEngine for MockOcrEngine {
    fn recognize(&self, image_bytes: &[u8], _language: &str) -> Result<OcrResult, Error> {
        let key = hex::encode(sha256(image_bytes));
        if let Some(result) = self.fixtures.get(&key) {
            Ok(result.clone())
        } else {
            Ok(OcrResult {
                text: String::new(),
                signals: OcrSignals {
                    text_confidence: 0.0,
                    required_fields_present: false,
                    detected_orientation: 0,
                },
                lines: vec![],
            })
        }
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

/// SHA-256 of arbitrary bytes. Used as the fixture key in
/// [`MockOcrEngine`] so identical images always resolve to the same
/// canned result, no matter the encoding wrapper.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let v = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Feature-gated Tesseract CLI engine. Available when the crate is
/// built with `--features tesseract-cli`.
#[cfg(feature = "tesseract-cli")]
pub mod tesseract_cli {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    /// Tesseract CLI engine. Shells out to the `tesseract` binary
    /// per call.
    pub struct TesseractCliEngine {
        binary_path: String,
    }

    impl TesseractCliEngine {
        /// Construct with the default `tesseract` binary (must be
        /// on PATH).
        pub fn new() -> Self {
            Self {
                binary_path: "tesseract".to_string(),
            }
        }

        /// Construct with a specific binary path. Useful for
        /// containerized deployments that bundle their own
        /// tesseract build.
        pub fn with_binary(path: impl Into<String>) -> Self {
            Self {
                binary_path: path.into(),
            }
        }
    }

    impl Default for TesseractCliEngine {
        fn default() -> Self {
            Self::new()
        }
    }

    impl OcrEngine for TesseractCliEngine {
        fn recognize(&self, image_bytes: &[u8], language: &str) -> Result<OcrResult, Error> {
            // Write image bytes to a temp file. The TempDir's
            // Drop impl deletes the directory after the function
            // returns even on early-return / panic.
            let dir = tempfile::tempdir().map_err(|e| Error::OcrFailed(format!("tempdir: {e}")))?;
            let img_path = dir.path().join("input");
            {
                let mut f = std::fs::File::create(&img_path)
                    .map_err(|e| Error::OcrFailed(format!("tempfile create: {e}")))?;
                f.write_all(image_bytes)
                    .map_err(|e| Error::OcrFailed(format!("tempfile write: {e}")))?;
                f.sync_all()
                    .map_err(|e| Error::OcrFailed(format!("tempfile sync: {e}")))?;
            }

            // `tesseract <input_path> stdout -l <lang>` writes
            // recognized text to stdout. Quiet, deterministic.
            let lang = if language.is_empty() { "eng" } else { language };
            let output = Command::new(&self.binary_path)
                .arg(&img_path)
                .arg("stdout")
                .arg("-l")
                .arg(lang)
                .output()
                .map_err(|e| Error::OcrFailed(format!("tesseract spawn: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::OcrFailed(format!(
                    "tesseract exit {}: {}",
                    output.status,
                    stderr.lines().next().unwrap_or("(no stderr)")
                )));
            }

            let text = String::from_utf8_lossy(&output.stdout).to_string();
            let trimmed = text.trim();
            let required_fields_present = !trimmed.is_empty();
            // The plain `tesseract … stdout` mode doesn't surface
            // confidence. Future iteration: switch to `tsv` mode
            // and parse the per-word confidence. Default to 0.7
            // when text is non-empty — placeholder until tsv mode
            // is wired.
            let text_confidence = if required_fields_present { 0.7 } else { 0.0 };

            Ok(OcrResult {
                text: trimmed.to_string(),
                signals: OcrSignals {
                    text_confidence,
                    required_fields_present,
                    detected_orientation: 0,
                },
                lines: vec![],
            })
        }

        fn name(&self) -> &'static str {
            "tesseract-cli"
        }
    }
}

// Re-export the gated engine when the feature is on so consumers
// don't need to know the submodule path.
#[cfg(feature = "tesseract-cli")]
pub use tesseract_cli::TesseractCliEngine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_unknown_image_returns_zero_signal() {
        let engine = MockOcrEngine::new();
        let result = engine.recognize(b"any unknown image bytes", "eng").unwrap();
        assert_eq!(result.text, "");
        assert!(result.signals.text_confidence.abs() < f32::EPSILON);
        assert!(!result.signals.required_fields_present);
    }

    #[test]
    fn mock_fixture_round_trip() {
        let bytes = b"fixture image bytes" as &[u8];
        let canned = OcrResult {
            text: "DOE\nJOHN\n01/15/1985".to_string(),
            signals: OcrSignals {
                text_confidence: 0.92,
                required_fields_present: true,
                detected_orientation: 0,
            },
            lines: vec![
                OcrLine {
                    text: "DOE".into(),
                    confidence: 0.95,
                },
                OcrLine {
                    text: "JOHN".into(),
                    confidence: 0.91,
                },
            ],
        };
        let engine = MockOcrEngine::new().with_fixture(bytes, canned.clone());
        let result = engine.recognize(bytes, "eng").unwrap();
        assert_eq!(result.text, canned.text);
        assert!((result.signals.text_confidence - 0.92).abs() < f32::EPSILON);
        assert!(result.signals.required_fields_present);
        assert_eq!(result.lines.len(), 2);
    }

    #[test]
    fn mock_distinguishes_different_images() {
        let engine = MockOcrEngine::new().with_fixture(
            b"image-a",
            OcrResult {
                text: "A".into(),
                signals: OcrSignals {
                    text_confidence: 1.0,
                    required_fields_present: true,
                    detected_orientation: 0,
                },
                lines: vec![],
            },
        );
        assert_eq!(engine.recognize(b"image-a", "eng").unwrap().text, "A");
        assert_eq!(engine.recognize(b"image-b", "eng").unwrap().text, "");
    }

    #[test]
    fn mock_name_is_stable() {
        let engine = MockOcrEngine::new();
        assert_eq!(engine.name(), "mock");
    }

    #[test]
    fn sha256_is_deterministic() {
        let a = sha256(b"hello");
        let b = sha256(b"hello");
        let c = sha256(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
