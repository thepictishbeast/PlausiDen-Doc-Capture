//! `doc-capture-face` — face match + liveness adapter.
//!
//! Exposes a small typed trait, [`FaceMatchEngine`], that the
//! pipeline orchestrator calls when both a captured selfie AND a
//! document portrait image are available. Implementations are
//! pluggable so a consumer can choose between:
//!
//!   - [`MockFaceMatchEngine`] — deterministic, returns canned
//!     distances + liveness verdicts. Always available, no native
//!     deps. Used by tests and "face match disabled" deployments.
//!   - Real engines (`InsightFace` via ONNX, dlib via FFI, etc.) —
//!     deferred to a follow-up phase. Feature-flag names reserved
//!     in `Cargo.toml` so consumers can pin Cargo entries today
//!     and the engine lands without API churn.
//!
//! ## Why two responsibilities in one crate
//!
//! Face match and liveness usually share a model pipeline (the
//! same face-detector + landmark-extractor feeds both). Splitting
//! them across crates would duplicate work for production engines.
//! The trait exposes them as separate methods so consumers that
//! only need ONE (e.g. liveness for a session-token mint, no
//! photo-to-document match) can still call the cheap operation.
//!
//! ## Privacy posture
//!
//! Implementations receive image bytes by reference, hold them in
//! memory only for the duration of the call, never persist them,
//! never log their content. Hashes of the input bytes (sha256)
//! ARE acceptable to log — they're keyed lookups, not identity.
//!
//! ## Liveness semantics
//!
//! "Liveness passed" means the engine believes the supplied selfie
//! depicts a live person at capture time (not a printed photo, not
//! a screen replay, not a static mask). Engines vary in
//! sophistication; the trait does NOT prescribe an algorithm.
//! Consumers that need challenge-response (active) liveness should
//! capture the multi-frame challenge sequence client-side and pass
//! it through a separate channel — the trait surface here is
//! single-frame passive liveness.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use doc_capture_core::{Error, FaceMatchSignals};
use std::collections::HashMap;

/// Pluggable face-match + liveness engine trait.
pub trait FaceMatchEngine: Send + Sync {
    /// Compare two face images and return match + liveness signals.
    ///
    /// `selfie_bytes` is the user-captured selfie. `portrait_bytes`
    /// is the document portrait extracted from the front-of-card
    /// image (the pipeline crops the portrait region upstream).
    /// `threshold` is the cosine-distance threshold below which
    /// the engine reports `matched: true`. Typical: 0.5.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying engine fails to decode
    /// either image or the recognizer backend errors.
    fn match_faces(
        &self,
        selfie_bytes: &[u8],
        portrait_bytes: &[u8],
        threshold: f32,
    ) -> Result<FaceMatchSignals, Error>;

    /// Engine identifier for logs and `/info`.
    fn name(&self) -> &'static str;
}

/// Mock face-match engine: returns canned results keyed on
/// `sha256(selfie_bytes) ++ sha256(portrait_bytes)`.
///
/// Used by tests to drive the orchestrator without a real face
/// recognizer. Also useful in deployments where face match is
/// explicitly disabled — unknown image pairs return a deterministic
/// "no match, no liveness" outcome.
#[derive(Debug, Default)]
pub struct MockFaceMatchEngine {
    fixtures: HashMap<String, FaceMatchSignals>,
}

impl MockFaceMatchEngine {
    /// Construct an empty Mock. Any image pair not added via
    /// [`with_fixture`](Self::with_fixture) returns the zero-signal
    /// "no match" outcome (distance 1.0, matched false, liveness
    /// None).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a canned match result for a specific (selfie,
    /// portrait) byte pair. Tests use this to set up known-good
    /// and known-bad fixtures without involving a real engine.
    ///
    /// The fixture is keyed on the concatenation
    /// `sha256(selfie) || sha256(portrait)`, so changing either
    /// image creates a different key.
    #[must_use]
    pub fn with_fixture(
        mut self,
        selfie_bytes: &[u8],
        portrait_bytes: &[u8],
        signals: FaceMatchSignals,
    ) -> Self {
        let key = fixture_key(selfie_bytes, portrait_bytes);
        self.fixtures.insert(key, signals);
        self
    }
}

impl FaceMatchEngine for MockFaceMatchEngine {
    fn match_faces(
        &self,
        selfie_bytes: &[u8],
        portrait_bytes: &[u8],
        threshold: f32,
    ) -> Result<FaceMatchSignals, Error> {
        let key = fixture_key(selfie_bytes, portrait_bytes);
        if let Some(signals) = self.fixtures.get(&key) {
            return Ok(signals.clone());
        }
        // Unknown pair → "no match" outcome. distance 1.0 sits at
        // the far edge of the cosine-distance range so the pipeline
        // can't accidentally pass it.
        Ok(FaceMatchSignals {
            distance: 1.0,
            threshold,
            matched: false,
            liveness_passed: None,
        })
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

/// Build the fixture-map key from a (selfie, portrait) byte pair.
/// Public-in-module so tests can verify keying behaviour
/// independently.
fn fixture_key(selfie_bytes: &[u8], portrait_bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(selfie_bytes);
    let selfie_hash = h.finalize_reset();
    h.update(portrait_bytes);
    let portrait_hash = h.finalize();
    format!(
        "{}|{}",
        hex::encode(selfie_hash),
        hex::encode(portrait_hash)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_unknown_pair_returns_no_match() {
        let engine = MockFaceMatchEngine::new();
        let result = engine
            .match_faces(b"any selfie", b"any portrait", 0.5)
            .unwrap();
        assert!((result.distance - 1.0).abs() < f32::EPSILON);
        assert!((result.threshold - 0.5).abs() < f32::EPSILON);
        assert!(!result.matched);
        assert_eq!(result.liveness_passed, None);
    }

    #[test]
    fn mock_fixture_round_trip_matched() {
        let selfie = b"fixture selfie bytes" as &[u8];
        let portrait = b"fixture portrait bytes" as &[u8];
        let canned = FaceMatchSignals {
            distance: 0.32,
            threshold: 0.5,
            matched: true,
            liveness_passed: Some(true),
        };
        let engine = MockFaceMatchEngine::new().with_fixture(selfie, portrait, canned.clone());
        let result = engine.match_faces(selfie, portrait, 0.5).unwrap();
        assert!((result.distance - 0.32).abs() < f32::EPSILON);
        assert!(result.matched);
        assert_eq!(result.liveness_passed, Some(true));
    }

    #[test]
    fn mock_fixture_distinguishes_pair_order() {
        // (selfie=A, portrait=B) is a different key than
        // (selfie=B, portrait=A). Critical — a face-match engine
        // that swapped the two inputs would still be detected by
        // testing.
        let a = b"image-A" as &[u8];
        let b = b"image-B" as &[u8];
        let canned = FaceMatchSignals {
            distance: 0.1,
            threshold: 0.5,
            matched: true,
            liveness_passed: Some(true),
        };
        let engine = MockFaceMatchEngine::new().with_fixture(a, b, canned);
        let forward = engine.match_faces(a, b, 0.5).unwrap();
        let reverse = engine.match_faces(b, a, 0.5).unwrap();
        assert!(forward.matched, "(A, B) should match the fixture");
        assert!(!reverse.matched, "(B, A) should miss the fixture");
    }

    #[test]
    fn fixture_key_changes_with_inputs() {
        let k1 = fixture_key(b"selfie", b"portrait");
        let k2 = fixture_key(b"selfie", b"portrait");
        let k3 = fixture_key(b"selfie2", b"portrait");
        let k4 = fixture_key(b"selfie", b"portrait2");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
        // Key contains TWO sha256 hex hashes separated by '|'.
        assert_eq!(k1.len(), 64 + 1 + 64);
    }

    #[test]
    fn mock_threshold_passes_through() {
        let engine = MockFaceMatchEngine::new();
        let r1 = engine.match_faces(b"a", b"b", 0.3).unwrap();
        let r2 = engine.match_faces(b"a", b"b", 0.7).unwrap();
        assert!((r1.threshold - 0.3).abs() < f32::EPSILON);
        assert!((r2.threshold - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn mock_name_is_stable() {
        let engine = MockFaceMatchEngine::new();
        assert_eq!(engine.name(), "mock");
    }
}
