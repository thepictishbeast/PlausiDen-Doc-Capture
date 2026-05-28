//! `doc-capture-core` — typed surface for document-capture identity
//! verification.
//!
//! Defines the data structures every downstream pipeline stage
//! produces or consumes:
//!
//!   - [`DocumentClaims`] — the parsed identity fields. Output of
//!     OCR + MRZ + PDF417 stages, consumed by attestation.
//!   - [`Attestation`] — cryptographic claim that "this person holds
//!     this document." What the substrate returns to the consumer.
//!   - [`PipelineSignals`] — per-stage diagnostic signals (OCR
//!     confidence, MRZ checksum results, tamper flags, face-match
//!     distance). Kept separate from the attestation so an operator
//!     can audit pipeline behaviour without re-running it.
//!   - [`enum@Error`] — the typed error enum every stage produces.
//!
//! No image bytes anywhere in this crate — only parsed claims, hashes,
//! and structured signals. The image-handling crates live one tier up
//! and never leak their inputs into core types.
//!
//! Consumer-agnostic: this crate makes no assumption about who the
//! end user is (account holder, applicant, member, participant). The salt
//! argument to [`hash_field`] is whatever stable opaque identifier
//! the consumer wants to bind the attestation to.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Parsed identity claims from a captured document.
///
/// Field values are normalized (uppercase, trimmed, ASCII-stripped of
/// control characters) but not yet hashed. Hashing into the
/// attestation happens at the very last step — keeping raw values in
/// this struct lets cross-validators (OCR vs MRZ vs PDF417) detect
/// mismatches between the document's representations of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentClaims {
    /// ISO 3166-1 alpha-3 issuing country (e.g. "USA").
    pub issuing_country: String,
    /// State / subdivision code (e.g. "UT" for Utah).
    pub issuing_state: Option<String>,
    /// Document type per ICAO 9303: "P" (passport), "I"
    /// (national-ID), "AC" / "ID" for AAMVA cards.
    pub document_type: String,
    /// Document number (driver license number, passport number).
    pub document_number: String,
    /// Surname as printed/encoded on the document.
    pub surname: String,
    /// Given names as printed/encoded (single string; multi-given
    /// names are space-separated).
    pub given_names: String,
    /// Date of birth in `YYYY-MM-DD`.
    pub date_of_birth: String,
    /// Date of expiration in `YYYY-MM-DD`.
    pub expiration_date: String,
    /// Sex marker as encoded ("M", "F", "X", or "<" for unspecified).
    pub sex: String,
    /// Nationality per ICAO (alpha-3); usually equals `issuing_country`
    /// but can differ on diplomatic passports.
    pub nationality: Option<String>,
}

/// Cryptographic attestation the consumer stores after a successful
/// capture.
///
/// The attestation contains HASHED claims and per-stage signal
/// summaries. The raw document image is never included; the raw
/// claims are hashed (with a per-subject salt the caller supplies)
/// before being placed in `disclosed_field_hashes`.
// Eq is NOT derivable here: PipelineSignals contains f32 fields
// (NaN). PartialEq is sufficient for the assertion shapes the
// caller needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Random per-attestation identifier.
    pub attestation_id: String,
    /// Claim type marker; always `"document_capture_v1"` for this
    /// pipeline. Distinguishes from zkTLS / mDL attestations in the
    /// same `attestation_json` storage column.
    pub claim_type: String,
    /// Per-field hashes that the verifier can later check claim
    /// disclosure against. `field_name → sha256_hex(salt || value)`.
    pub disclosed_field_hashes: std::collections::BTreeMap<String, String>,
    /// Field values disclosed in plaintext per the caller's
    /// disclosure mask. Privacy-preserving disclosure typically
    /// reveals `issuing_state`, `age_over_18`, possibly `surname`
    /// plus first initial. Names + DOB + document number stay
    /// redacted unless the consumer explicitly opts them in.
    pub disclosed_claims: std::collections::BTreeMap<String, serde_json::Value>,
    /// Per-stage signal summary (see [`PipelineSignals`]).
    pub signals: PipelineSignals,
    /// RFC3339 timestamp of attestation issuance.
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// RFC3339 timestamp of expiration (default: 30 days).
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Per-pipeline-stage diagnostic signals.
///
/// Each stage records its own confidence / pass-fail signal. The
/// final `verified` boolean (decided by the orchestrator) typically
/// requires `ocr.text_confidence >= 0.8`, `mrz.all_checksums_valid`
/// or `pdf417.aamva_checksum_valid`, `tamper.suspicious == false`,
/// and `face_match.distance < threshold`. The thresholds are policy
/// inputs the orchestrator owns, not core invariants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PipelineSignals {
    /// OCR-stage signals. `None` when OCR was skipped (e.g.
    /// MRZ-only test fixture).
    pub ocr: Option<OcrSignals>,
    /// MRZ-stage signals. `None` when document has no MRZ.
    pub mrz: Option<MrzSignals>,
    /// PDF417/AAMVA-stage signals. `None` when document has no
    /// PDF417 barcode (e.g. passport, foreign ID).
    pub pdf417: Option<Pdf417Signals>,
    /// Tamper-detection signals. `None` when skipped.
    pub tamper: Option<TamperSignals>,
    /// Face-match signals. `None` when skipped.
    pub face_match: Option<FaceMatchSignals>,
}

/// OCR stage signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OcrSignals {
    /// Confidence in `[0.0, 1.0]`; typically Tesseract's mean
    /// word-confidence normalized to that range.
    pub text_confidence: f32,
    /// Whether OCR succeeded in extracting all REQUIRED fields
    /// (name, DOB, document number). If false, the caller should
    /// fail the verification regardless of other signals.
    pub required_fields_present: bool,
    /// Detected document orientation (degrees rotated from upright).
    pub detected_orientation: i32,
}

/// MRZ stage signals (passport / national ID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MrzSignals {
    /// All MRZ check digits matched their computed values.
    pub all_checksums_valid: bool,
    /// Number of MRZ lines parsed (2 for TD3 passport, 3 for
    /// TD1/TD2 ID cards).
    pub lines_parsed: u8,
    /// Per-check-digit results, useful for diagnostics when
    /// `all_checksums_valid` is false. Keys like
    /// `document_number`, `dob`, `expiration`, `composite`.
    pub checksum_results: std::collections::BTreeMap<String, bool>,
}

/// PDF417 / AAMVA stage signals (US driver licenses + state IDs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pdf417Signals {
    /// PDF417 barcode decoded successfully.
    pub barcode_decoded: bool,
    /// AAMVA header verification passed (file type "ANSI ",
    /// jurisdiction code present, etc.).
    pub aamva_header_valid: bool,
    /// PDF417 internal CRC checksum (in the barcode wire format
    /// itself, distinct from any AAMVA-content checksums).
    pub pdf417_crc_valid: bool,
    /// AAMVA jurisdiction code (issuing state, 6-digit IIN).
    pub aamva_jurisdiction_iin: Option<String>,
}

/// Tamper-detection stage signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TamperSignals {
    /// True if Error-Level Analysis flagged the image as suspicious.
    pub suspicious: bool,
    /// ELA score in `[0.0, 1.0]`; higher = more likely tampered.
    pub ela_score: f32,
    /// Mean JPEG quality estimate; very low values suggest
    /// re-compression after editing.
    pub estimated_jpeg_quality: f32,
}

/// Face-match stage signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FaceMatchSignals {
    /// Cosine distance between selfie face-embedding and ID
    /// portrait face-embedding. Lower = more similar.
    pub distance: f32,
    /// Threshold used for the match decision (typically 0.5).
    pub threshold: f32,
    /// Decision: distance < threshold.
    pub matched: bool,
    /// Liveness check passed (challenge-response or passive).
    /// `None` when liveness is skipped (e.g. MVP).
    pub liveness_passed: Option<bool>,
}

/// Typed error surface for the pipeline.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum Error {
    /// Image bytes could not be decoded as a known image format
    /// (JPEG, PNG, WEBP).
    #[error("invalid image: {0}")]
    InvalidImage(String),
    /// OCR pipeline could not extract text.
    #[error("ocr failed: {0}")]
    OcrFailed(String),
    /// MRZ-line parse failure (wrong length, bad characters).
    #[error("mrz parse failed: {0}")]
    MrzParseFailed(String),
    /// MRZ checksum mismatch (specific field).
    #[error("mrz checksum mismatch on field '{0}'")]
    MrzChecksumMismatch(String),
    /// PDF417 barcode could not be decoded.
    #[error("pdf417 decode failed: {0}")]
    Pdf417DecodeFailed(String),
    /// AAMVA content parse failure (after PDF417 decode).
    #[error("aamva parse failed: {0}")]
    AamvaParseFailed(String),
    /// Face embedding could not be computed (no face detected).
    #[error("face embedding failed: {0}")]
    FaceEmbeddingFailed(String),
    /// Tamper detection identified the image as compromised.
    #[error("tamper detected: {0}")]
    TamperDetected(String),
    /// Cross-validator detected disagreement between two
    /// representations of the document (e.g. OCR vs MRZ name
    /// differ).
    #[error("cross-validation failed: {0}")]
    CrossValidationFailed(String),
    /// Generic upstream failure that doesn't fit the above; carries
    /// a short reason for the operator log.
    #[error("upstream error: {0}")]
    Upstream(String),
}

/// Hash a single claim field for inclusion in
/// `disclosed_field_hashes`.
///
/// Implementation: `sha256_hex(salt || ":" || field_name || ":" ||
/// value)`. Per-field hashing prevents rainbow-table lookup of any
/// single attribute (which would otherwise be feasible for
/// low-entropy fields like sex or state).
///
/// The `salt` argument is supplied by the consumer per-subject and
/// is typically a stable opaque identifier the consumer already
/// holds (e.g. a hashed user ID), so the per-attestation hash of
/// `issuing_state=UT` is subject-distinguishable in storage and
/// cannot collide across subjects.
#[must_use]
pub fn hash_field(salt: &[u8], field_name: &str, value: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(salt);
    h.update(b":");
    h.update(field_name.as_bytes());
    h.update(b":");
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_field_is_deterministic() {
        let h1 = hash_field(b"subject-salt-1", "issuing_state", "UT");
        let h2 = hash_field(b"subject-salt-1", "issuing_state", "UT");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex = 64 chars
    }

    #[test]
    fn hash_field_changes_with_salt() {
        let a = hash_field(b"subject-1", "state", "UT");
        let b = hash_field(b"subject-2", "state", "UT");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_field_changes_with_value() {
        let a = hash_field(b"subject", "state", "UT");
        let b = hash_field(b"subject", "state", "CA");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_field_changes_with_field_name() {
        // Verifies the field_name boundary in the hash input prevents
        // collisions across fields with the same value.
        let a = hash_field(b"subject", "state", "M");
        let b = hash_field(b"subject", "sex", "M");
        assert_ne!(a, b);
    }

    #[test]
    fn pipeline_signals_default_is_all_none() {
        let s = PipelineSignals::default();
        assert!(s.ocr.is_none());
        assert!(s.mrz.is_none());
        assert!(s.pdf417.is_none());
        assert!(s.tamper.is_none());
        assert!(s.face_match.is_none());
    }

    #[test]
    fn error_displays_friendly_message() {
        let e = Error::MrzChecksumMismatch("document_number".into());
        assert!(e.to_string().contains("document_number"));
    }
}
