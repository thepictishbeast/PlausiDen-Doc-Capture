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
    use super::{Error, HashMap, OcrEngine, OcrLine, OcrResult, OcrSignals};
    use std::io::Write;
    use std::process::Command;

    /// Parse Tesseract `tsv` output mode into an [`OcrResult`].
    ///
    /// Tesseract emits a 12-column, tab-separated table — one row per
    /// layout element (page, block, paragraph, line, word). Word rows
    /// carry `level == 5` and a `conf` column in `[0, 100]`; coarser
    /// rows carry `conf == -1` and are skipped. Words are grouped into
    /// lines by their `(block_num, par_num, line_num)` triple,
    /// preserving the order Tesseract reports them.
    ///
    /// Per-line confidence is the mean of that line's word
    /// confidences; the overall [`OcrSignals::text_confidence`] is the
    /// mean across every word, each normalized from `[0, 100]` to
    /// `[0.0, 1.0]`. With no recognized words the result is the
    /// zero-signal "nothing recognized" outcome, matching
    /// [`MockOcrEngine`]'s contract for unknown images.
    ///
    /// Orientation is not derivable from `tsv` output (it needs a
    /// separate `--psm 0` OSD pass), so `detected_orientation` stays
    /// `0` here.
    fn parse_tsv(tsv: &str) -> OcrResult {
        // Words accumulated per line, keyed by (block, par, line),
        // kept in first-seen order so reading order is preserved.
        let mut order: Vec<(u32, u32, u32)> = Vec::new();
        let mut words: HashMap<(u32, u32, u32), Vec<(String, f32)>> = HashMap::new();

        for row in tsv.lines() {
            let cols: Vec<&str> = row.split('\t').collect();
            // A valid word row has all 12 columns.
            if cols.len() < 12 {
                continue;
            }
            // Skip the header row (`level` etc.) and any non-word row.
            if cols[0] != "5" {
                continue;
            }
            let text = cols[11].trim();
            if text.is_empty() {
                continue;
            }
            let (Ok(block), Ok(par), Ok(line)) = (
                cols[2].parse::<u32>(),
                cols[3].parse::<u32>(),
                cols[4].parse::<u32>(),
            ) else {
                continue;
            };
            let Ok(conf) = cols[10].parse::<f32>() else {
                continue;
            };
            if conf < 0.0 {
                continue;
            }
            let key = (block, par, line);
            if !words.contains_key(&key) {
                order.push(key);
            }
            words.entry(key).or_default().push((text.to_string(), conf));
        }

        let mut lines: Vec<OcrLine> = Vec::with_capacity(order.len());
        let mut all_confs: Vec<f32> = Vec::new();
        for key in &order {
            let line_words = &words[key];
            let line_text = line_words
                .iter()
                .map(|(w, _)| w.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let confs: Vec<f32> = line_words.iter().map(|(_, c)| *c).collect();
            all_confs.extend(confs.iter().copied());
            lines.push(OcrLine {
                text: line_text,
                confidence: mean(&confs) / 100.0,
            });
        }

        let text = lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let required_fields_present = !text.trim().is_empty();
        let text_confidence = if required_fields_present {
            mean(&all_confs) / 100.0
        } else {
            0.0
        };

        OcrResult {
            text,
            signals: OcrSignals {
                text_confidence,
                required_fields_present,
                detected_orientation: 0,
            },
            lines,
        }
    }

    /// Arithmetic mean of a confidence slice. Empty slice yields `0.0`
    /// so an all-skipped page reads as zero confidence rather than
    /// dividing by zero.
    fn mean(xs: &[f32]) -> f32 {
        if xs.is_empty() {
            return 0.0;
        }
        let sum: f32 = xs.iter().sum();
        // Word counts per page are small (hundreds at most), so the
        // usize->f32 widening is exact in practice.
        #[allow(clippy::cast_precision_loss)]
        let n = xs.len() as f32;
        sum / n
    }

    /// Tesseract CLI engine. Shells out to the `tesseract` binary
    /// per call.
    pub struct TesseractCliEngine {
        binary_path: String,
    }

    impl TesseractCliEngine {
        /// Construct with the default `tesseract` binary (must be
        /// on PATH).
        #[must_use]
        pub fn new() -> Self {
            Self {
                binary_path: "tesseract".to_string(),
            }
        }

        /// Construct with a specific binary path. Useful for
        /// containerized deployments that bundle their own
        /// tesseract build.
        #[must_use]
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

            // `tesseract <input_path> stdout -l <lang> tsv` writes a
            // tab-separated layout table to stdout, one row per
            // recognized element, with a per-word confidence column.
            // Quiet, deterministic, and richer than the plain text
            // mode (which surfaces no confidence at all).
            let lang = if language.is_empty() { "eng" } else { language };
            let output = Command::new(&self.binary_path)
                .arg(&img_path)
                .arg("stdout")
                .arg("-l")
                .arg(lang)
                .arg("tsv")
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

            let tsv = String::from_utf8_lossy(&output.stdout);
            Ok(parse_tsv(&tsv))
        }

        fn name(&self) -> &'static str {
            "tesseract-cli"
        }
    }

    #[cfg(test)]
    mod tsv_tests {
        use super::parse_tsv;

        const SAMPLE: &str = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
1\t1\t0\t0\t0\t0\t0\t0\t600\t800\t-1\t\n\
2\t1\t1\t0\t0\t0\t36\t40\t200\t30\t-1\t\n\
3\t1\t1\t1\t0\t0\t36\t40\t200\t30\t-1\t\n\
4\t1\t1\t1\t1\t0\t36\t40\t200\t30\t-1\t\n\
5\t1\t1\t1\t1\t1\t36\t40\t60\t30\t95\tDOE\n\
5\t1\t1\t1\t1\t2\t100\t40\t80\t30\t88\tJOHN\n\
4\t1\t1\t1\t2\t0\t36\t80\t200\t30\t-1\t\n\
5\t1\t1\t1\t2\t1\t36\t80\t160\t30\t72\t01/15/1985\n";

        #[test]
        fn parses_lines_and_confidence() {
            let r = parse_tsv(SAMPLE);
            assert_eq!(r.text, "DOE JOHN\n01/15/1985");
            assert!(r.signals.required_fields_present);
            assert_eq!(r.lines.len(), 2);
            // line 1: mean(95, 88)/100 = 0.915
            assert!((r.lines[0].confidence - 0.915).abs() < 1e-4);
            // line 2: 72/100 = 0.72
            assert!((r.lines[1].confidence - 0.72).abs() < 1e-4);
            // overall: mean(95, 88, 72)/100 = 0.85
            assert!((r.signals.text_confidence - 0.85).abs() < 1e-4);
            assert_eq!(r.signals.detected_orientation, 0);
        }

        #[test]
        fn no_words_is_zero_signal() {
            let header_only = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
1\t1\t0\t0\t0\t0\t0\t0\t600\t800\t-1\t\n";
            let r = parse_tsv(header_only);
            assert_eq!(r.text, "");
            assert!(!r.signals.required_fields_present);
            assert!(r.signals.text_confidence.abs() < f32::EPSILON);
            assert!(r.lines.is_empty());
        }

        #[test]
        fn skips_negative_conf_and_blank_words() {
            let tsv = "5\t1\t1\t1\t1\t1\t0\t0\t1\t1\t-1\tghost\n\
5\t1\t1\t1\t1\t2\t0\t0\t1\t1\t90\t   \n\
5\t1\t1\t1\t1\t3\t0\t0\t1\t1\t80\tREAL\n";
            let r = parse_tsv(tsv);
            assert_eq!(r.text, "REAL");
            assert_eq!(r.lines.len(), 1);
            assert!((r.signals.text_confidence - 0.80).abs() < 1e-4);
        }

        #[test]
        fn groups_words_across_distinct_lines() {
            let tsv = "5\t1\t1\t1\t1\t1\t0\t0\t1\t1\t100\tA\n\
5\t1\t1\t1\t2\t1\t0\t0\t1\t1\t100\tB\n\
5\t1\t2\t1\t1\t1\t0\t0\t1\t1\t100\tC\n";
            let r = parse_tsv(tsv);
            assert_eq!(r.lines.len(), 3);
            assert_eq!(r.text, "A\nB\nC");
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
