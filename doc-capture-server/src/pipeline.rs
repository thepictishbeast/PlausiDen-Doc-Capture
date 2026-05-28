//! Pipeline orchestrator.
//!
//! Takes a captured-document upload and runs every available
//! pipeline stage against it, composing the per-stage signals into a
//! single [`Attestation`].
//!
//! Stages wired: MRZ (caller-supplied text, or recovered from OCR of
//! the front image — passport flow), PDF417+AAMVA (back-image bytes —
//! US DL flow), OCR (front-image text + confidence), tamper (ELA), and
//! face-match (selfie vs document portrait). Liveness (selfie
//! anti-spoofing) is the one stage still unimplemented.

use doc_capture_core::{hash_field, Attestation, DocumentClaims, Error, PipelineSignals};
use doc_capture_face::FaceMatchEngine;
use doc_capture_ocr::OcrEngine;
use std::sync::Arc;

/// Default cosine-distance threshold for face-match. Mirrors
/// `FaceMatchSignals::threshold` semantics; engines that need a
/// different threshold per deployment override via the caller's
/// pipeline policy (not yet a config knob; future iter).
pub const DEFAULT_FACE_THRESHOLD: f32 = 0.5;

/// All inputs the /capture handler hands to the orchestrator.
pub struct CaptureInput {
    /// Raw bytes of the front-of-document image (JPEG/PNG). Empty
    /// when the caller is exercising the MRZ-only path.
    pub front_bytes: Vec<u8>,
    /// Raw bytes of the back-of-document image (US DL barcode side).
    /// Empty when the caller is exercising a passport (no back).
    pub back_bytes: Vec<u8>,
    /// Raw bytes of the selfie image. Empty when face-match is not
    /// being requested for this capture.
    pub selfie_bytes: Vec<u8>,
    /// Caller-supplied template ID indicating expected document
    /// shape (e.g. `"us-driver-license-v1"`, `"icao-passport-v1"`).
    pub template_id: String,
    /// Optional ICAO 9303 MRZ lines, when the caller has already
    /// OCR'd them client-side. Skips the server-side OCR pass.
    pub mrz_lines: Vec<String>,
    /// Caller-supplied opaque salt for per-field claim hashes. The
    /// hash output is stable per (salt, field, value) so a downstream
    /// auditor can prove a specific (subject, claim) pair was
    /// asserted without re-handling raw PII.
    pub salt: Vec<u8>,
}

/// Output of one capture run.
pub struct CaptureOutput {
    /// Session id (random per call).
    pub session_id: String,
    /// Composed identity claims. `None` when no stage extracted
    /// anything (e.g. all inputs empty).
    pub claims: Option<DocumentClaims>,
    /// Cryptographic attestation. `None` when claims is `None` —
    /// nothing to attest to.
    pub attestation: Option<Attestation>,
    /// Per-stage signals (always present, even on partial failure).
    pub signals: PipelineSignals,
    /// Sum of all stage errors. Empty when verification succeeded.
    pub stage_errors: Vec<String>,
}

/// Run every wired pipeline stage against the input.
///
/// The orchestrator does NOT itself decide if a capture is
/// "verified" — that policy is the consumer's. The consumer reads
/// the signals and applies thresholds based on its trust posture.
///
/// `ocr` is the engine injected by the server. Tests can pass a
/// Mock with pre-loaded fixtures; production deployments pass a
/// real engine like `TesseractCliEngine`.
#[allow(clippy::too_many_lines)] // linear stage-by-stage orchestration reads clearest as one function
pub fn run(
    input: &CaptureInput,
    ocr: &Arc<dyn OcrEngine>,
    face: &Arc<dyn FaceMatchEngine>,
) -> CaptureOutput {
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut signals = PipelineSignals::default();
    let mut stage_errors: Vec<String> = Vec::new();
    let mut claims_from_mrz: Option<DocumentClaims> = None;
    let mut claims_from_aamva: Option<DocumentClaims> = None;

    // ── MRZ stage (passport / TD1-TD3 ID card) ───────────────────
    if !input.mrz_lines.is_empty() {
        let line_refs: Vec<&str> = input.mrz_lines.iter().map(String::as_str).collect();
        match doc_capture_mrz::parse_mrz(&line_refs) {
            Ok(mrz) => {
                signals.mrz = Some(mrz.to_signals());
                claims_from_mrz = Some(mrz_to_claims(&mrz));
            }
            Err(e) => {
                stage_errors.push(format!("mrz: {e}"));
            }
        }
    }

    // ── PDF417 + AAMVA stage (US DL / state ID) ──────────────────
    if !input.back_bytes.is_empty() {
        match doc_capture_pdf417::decode_pdf417_from_image_bytes(&input.back_bytes) {
            Ok(text) => match doc_capture_aamva::parse_aamva(&text) {
                Ok(aamva) => {
                    signals.pdf417 = Some(aamva.to_signals(true, true));
                    claims_from_aamva = Some(DocumentClaims {
                        issuing_country: "USA".to_string(),
                        issuing_state: Some(aamva.address_state.clone()),
                        document_type: aamva.document_type.clone(),
                        document_number: aamva.document_number.clone(),
                        surname: aamva.family_name.clone(),
                        given_names: format!(
                            "{} {}",
                            aamva.first_name.trim(),
                            aamva.middle_name.trim()
                        )
                        .trim()
                        .to_string(),
                        date_of_birth: aamva.date_of_birth.clone(),
                        expiration_date: aamva.expiration_date.clone(),
                        sex: aamva.sex_normalized().to_string(),
                        nationality: Some("USA".to_string()),
                    });
                }
                Err(e) => stage_errors.push(format!("aamva: {e}")),
            },
            Err(Error::InvalidImage(s)) => {
                stage_errors.push(format!("pdf417 invalid image: {s}"));
            }
            Err(e) => stage_errors.push(format!("pdf417: {e}")),
        }
    }

    // ── OCR stage (phase 3) ──────────────────────────────────────
    //
    // Runs only when the caller supplied front_bytes. The engine
    // is injected by the server; tests pass a MockOcrEngine with
    // pre-loaded fixtures, production passes TesseractCliEngine
    // (or other future impl).
    if !input.front_bytes.is_empty() {
        match ocr.recognize(&input.front_bytes, "eng") {
            Ok(ocr_result) => {
                signals.ocr = Some(ocr_result.signals.clone());
                // OCR-derived MRZ fallback: when the caller did NOT
                // supply machine-read MRZ lines (claims_from_mrz is
                // still None) but the OCR'd front contains an ICAO
                // MRZ block (passport / TD1-TD3 card photographed
                // whole), recover it from the OCR text. The MRZ check
                // digits are the integrity gate — an OCR misread
                // breaks a checksum, so we only accept the claims
                // when EVERY checksum validates. Garbage OCR thus
                // self-rejects and never yields false claims.
                //
                // General per-template field extraction (labeled
                // fields without an MRZ) is still future work.
                if claims_from_mrz.is_none() {
                    if let Some(lines) = extract_mrz_candidate_lines(&ocr_result.text) {
                        let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
                        if let Ok(mrz) = doc_capture_mrz::parse_mrz(&line_refs) {
                            let sig = mrz.to_signals();
                            if sig.all_checksums_valid {
                                claims_from_mrz = Some(mrz_to_claims(&mrz));
                                signals.mrz = Some(sig);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                stage_errors.push(format!("ocr: {e}"));
            }
        }
    }

    // ── Tamper stage (phase 4) ───────────────────────────────────
    //
    // Runs ELA on whichever image bytes we have — front preferred,
    // back if front is absent. Only one analysis is needed per
    // capture; ELA on the document front catches the same class of
    // edits that ELA on the back catches.
    let tamper_target = if !input.front_bytes.is_empty() {
        Some(input.front_bytes.as_slice())
    } else if !input.back_bytes.is_empty() {
        Some(input.back_bytes.as_slice())
    } else {
        None
    };
    if let Some(bytes) = tamper_target {
        match doc_capture_tamper::analyze_ela(bytes) {
            Ok(t) => signals.tamper = Some(t),
            Err(e) => stage_errors.push(format!("tamper: {e}")),
        }
    }

    // ── Face match + liveness stage (phase 5) ────────────────────
    //
    // Runs only when BOTH selfie_bytes and a portrait source are
    // supplied. The "portrait source" today is the front-of-doc
    // image (the front-image crop is done upstream — the engine
    // gets the full image and is expected to locate the face).
    // When face crop extraction becomes a discrete pipeline step
    // (phase 5.5) this passes a tighter region instead.
    if !input.selfie_bytes.is_empty() && !input.front_bytes.is_empty() {
        match face.match_faces(
            &input.selfie_bytes,
            &input.front_bytes,
            DEFAULT_FACE_THRESHOLD,
        ) {
            Ok(sig) => signals.face_match = Some(sig),
            Err(e) => stage_errors.push(format!("face: {e}")),
        }
    }

    let _ = &input.template_id;

    // Cross-validator: if both MRZ and AAMVA produced claims, the
    // two surname fields should agree (case-insensitive, trimmed).
    // Disagreement is a strong tamper signal — record but don't
    // hard-fail; let the consumer decide.
    if let (Some(m), Some(a)) = (&claims_from_mrz, &claims_from_aamva) {
        if !names_match(&m.surname, &a.surname) {
            stage_errors.push(format!(
                "cross-validation: surname MRZ={:?} AAMVA={:?}",
                m.surname, a.surname
            ));
        }
    }

    // Prefer AAMVA when present (richer fields), fall back to MRZ.
    let claims = claims_from_aamva.or(claims_from_mrz);

    let attestation = claims
        .as_ref()
        .map(|c| build_attestation(c, &signals, &input.salt));

    CaptureOutput {
        session_id,
        claims,
        attestation,
        signals,
        stage_errors,
    }
}

/// Map a parsed MRZ into the pipeline's [`DocumentClaims`] shape.
///
/// Shared by the explicit-MRZ path (caller-supplied lines) and the
/// OCR-derived MRZ fallback so both produce identical claim
/// structures.
fn mrz_to_claims(mrz: &doc_capture_mrz::ParsedMrz) -> DocumentClaims {
    DocumentClaims {
        issuing_country: mrz.issuing_country.clone(),
        issuing_state: None,
        document_type: mrz.document_type.clone(),
        document_number: mrz.document_number.clone(),
        surname: mrz.surname.clone(),
        given_names: mrz.given_names.clone(),
        date_of_birth: yymmdd_to_iso(&mrz.date_of_birth_yymmdd),
        expiration_date: yymmdd_to_iso(&mrz.expiration_yymmdd),
        sex: mrz.sex.clone(),
        nationality: Some(mrz.nationality.clone()),
    }
}

/// Find an ICAO MRZ block inside free-form OCR text.
///
/// MRZ lines use a restricted alphabet (`A-Z`, `0-9`, and the filler
/// `<`) and pack data into fixed widths: TD3 passports are two
/// 44-char lines, TD2 cards two 36-char lines, TD1 cards three
/// 30-char lines. The human-readable text printed elsewhere on the
/// document mixes case, includes spaces, and rarely contains `<`, so
/// requiring the filler character cleanly discriminates MRZ rows from
/// the rest of the page.
///
/// Returns the longest run of consecutive MRZ-looking rows (2 or 3),
/// each normalized to the nearest standard width via
/// [`normalize_mrz_line`], or `None` when no such run exists. This
/// only narrows the haystack — `parse_mrz`'s check-digit validation
/// is the real integrity gate, applied by the caller.
fn extract_mrz_candidate_lines(ocr_text: &str) -> Option<Vec<String>> {
    let is_candidate = |raw: &str| -> Option<String> {
        let compact: String = raw
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let compact = compact.to_uppercase();
        let len = compact.len();
        if (20..=50).contains(&len)
            && compact.contains('<')
            && compact
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '<')
        {
            Some(compact)
        } else {
            None
        }
    };

    // Longest maximal run of consecutive candidate rows.
    let mut best: Vec<String> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in ocr_text.lines() {
        if let Some(c) = is_candidate(line) {
            current.push(c);
        } else if current.len() > best.len() {
            best = std::mem::take(&mut current);
        } else {
            current.clear();
        }
    }
    if current.len() > best.len() {
        best = current;
    }

    match best.len() {
        // A 3-row run is a TD1 card (30-char lines).
        n if n >= 3 => Some(
            best.iter()
                .take(3)
                .map(|l| normalize_mrz_line(l, 30))
                .collect(),
        ),
        // A 2-row run is TD3 (44) when the rows are long, else TD2 (36).
        2 => {
            let width = if best.iter().map(String::len).max().unwrap_or(0) >= 40 {
                44
            } else {
                36
            };
            Some(best.iter().map(|l| normalize_mrz_line(l, width)).collect())
        }
        _ => None,
    }
}

/// Normalize an OCR'd MRZ row to an exact standard width: drop any
/// characters outside the MRZ alphabet, pad short rows with the filler
/// `<`, and truncate over-long rows. `parse_mrz` requires exact
/// 30/36/44-char lines, so minor OCR length drift would otherwise
/// hard-fail the parse before the check digits even run. A genuine
/// misread still breaks a check digit and is rejected downstream.
fn normalize_mrz_line(line: &str, width: usize) -> String {
    let mut s: String = line
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '<')
        .collect();
    if s.len() > width {
        s.truncate(width);
    } else {
        while s.len() < width {
            s.push('<');
        }
    }
    s
}

/// Convert ICAO `YYMMDD` to ISO `YYYY-MM-DD`. ICAO doesn't carry a
/// century, so we apply a 50-year window: years 00..49 → 20xx,
/// years 50..99 → 19xx. This is the standard ICAO convention.
fn yymmdd_to_iso(yymmdd: &str) -> String {
    if yymmdd.len() != 6 || !yymmdd.chars().all(|c| c.is_ascii_digit()) {
        return String::new();
    }
    let yy: u32 = yymmdd[0..2].parse().unwrap_or(0);
    let mm = &yymmdd[2..4];
    let dd = &yymmdd[4..6];
    let yyyy = if yy <= 49 { 2000 + yy } else { 1900 + yy };
    format!("{yyyy:04}-{mm}-{dd}")
}

/// Loose name match for cross-validation. Case-insensitive, trims
/// whitespace, ignores `.` (Jr., II punctuation), and collapses
/// internal whitespace.
fn names_match(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        s.to_uppercase()
            .replace('.', "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    norm(a) == norm(b)
}

/// Build the attestation from extracted claims + signals.
///
/// All claim fields go in `disclosed_field_hashes` (so the consumer
/// can later verify a claim disclosure without keeping the raw
/// value). A minimal default disclosure surfaces only
/// `issuing_state` and `age_over_18` in `disclosed_claims` —
/// consumers who need more can compute it themselves from the
/// `disclosed_field_hashes` by supplying the salted plaintext.
fn build_attestation(
    claims: &DocumentClaims,
    signals: &PipelineSignals,
    salt: &[u8],
) -> Attestation {
    let mut hashes = std::collections::BTreeMap::new();
    let mut disclosed = std::collections::BTreeMap::new();

    for (name, val) in [
        ("issuing_country", claims.issuing_country.as_str()),
        ("document_type", claims.document_type.as_str()),
        ("document_number", claims.document_number.as_str()),
        ("surname", claims.surname.as_str()),
        ("given_names", claims.given_names.as_str()),
        ("date_of_birth", claims.date_of_birth.as_str()),
        ("expiration_date", claims.expiration_date.as_str()),
        ("sex", claims.sex.as_str()),
    ] {
        hashes.insert(name.to_string(), hash_field(salt, name, val));
    }
    if let Some(state) = &claims.issuing_state {
        hashes.insert(
            "issuing_state".to_string(),
            hash_field(salt, "issuing_state", state),
        );
        disclosed.insert(
            "issuing_state".to_string(),
            serde_json::Value::String(state.clone()),
        );
    }
    // Age-over-18 is computed at attestation time, NOT stored as
    // raw DOB. Default disclosure includes it because most
    // consumers need it.
    if let Some(age_ok) = age_over(&claims.date_of_birth, 18) {
        disclosed.insert("age_over_18".to_string(), serde_json::Value::Bool(age_ok));
    }

    Attestation {
        attestation_id: format!("att-{}", uuid::Uuid::new_v4()),
        claim_type: "document_capture_v1".to_string(),
        disclosed_field_hashes: hashes,
        disclosed_claims: disclosed,
        signals: signals.clone(),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(30),
    }
}

/// Return `Some(true)` when DOB plus `years_required` is on or
/// before today, `Some(false)` when it isn't, `None` when DOB is
/// unparseable.
fn age_over(iso_dob: &str, years_required: u32) -> Option<bool> {
    let dob = chrono::NaiveDate::parse_from_str(iso_dob, "%Y-%m-%d").ok()?;
    let today = chrono::Utc::now().date_naive();
    // years_since returns None when self < since (future DOB).
    // Future DOB means person not yet born; treat as "not over N"
    // rather than "unknown" — the parse succeeded so we know the
    // date is well-formed.
    let age_today = today.years_since(dob).unwrap_or(0);
    Some(age_today >= years_required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yymmdd_century_window() {
        assert_eq!(yymmdd_to_iso("740812"), "1974-08-12"); // 74 -> 1974
        assert_eq!(yymmdd_to_iso("050101"), "2005-01-01"); // 05 -> 2005
        assert_eq!(yymmdd_to_iso("490101"), "2049-01-01"); // 49 boundary
        assert_eq!(yymmdd_to_iso("500101"), "1950-01-01"); // 50 boundary
        assert_eq!(yymmdd_to_iso(""), "");
        assert_eq!(yymmdd_to_iso("not-a-date"), "");
    }

    #[test]
    fn names_match_loose() {
        assert!(names_match("DOE", "doe"));
        assert!(names_match("DOE", " DOE  "));
        assert!(names_match("VAN DER WAAL", "van der waal"));
        assert!(names_match("JR.", "Jr"));
        assert!(!names_match("DOE", "ROE"));
    }

    #[test]
    fn age_over_18_basic() {
        // Past DOB → over 18 is true.
        let long_ago = "1980-01-01";
        assert_eq!(age_over(long_ago, 18), Some(true));
        // Future DOB → over 18 is false.
        let future = "2099-01-01";
        assert_eq!(age_over(future, 18), Some(false));
        // Unparseable.
        assert_eq!(age_over("", 18), None);
        assert_eq!(age_over("not-a-date", 18), None);
    }

    fn mock_ocr() -> Arc<dyn OcrEngine> {
        Arc::new(doc_capture_ocr::MockOcrEngine::new())
    }

    // OCR engine that returns fixed text for the given front bytes,
    // for exercising the OCR-derived MRZ fallback.
    fn ocr_with_text(front: &[u8], text: &str) -> Arc<dyn OcrEngine> {
        let res = doc_capture_ocr::OcrResult {
            text: text.to_string(),
            signals: doc_capture_core::OcrSignals {
                text_confidence: 0.9,
                required_fields_present: true,
                detected_orientation: 0,
            },
            lines: vec![],
        };
        Arc::new(doc_capture_ocr::MockOcrEngine::new().with_fixture(front, res))
    }

    fn mock_face() -> Arc<dyn FaceMatchEngine> {
        Arc::new(doc_capture_face::MockFaceMatchEngine::new())
    }

    // Valid ICAO TD3 (ERIKSSON) example — all check digits pass.
    const ERIKSSON_L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const ERIKSSON_L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    #[test]
    fn extract_mrz_finds_td3_block() {
        let text =
            format!("REPUBLIC OF UTOPIA\nPASSPORT\n{ERIKSSON_L1}\n{ERIKSSON_L2}\nsigned here");
        let lines = extract_mrz_candidate_lines(&text).expect("MRZ block present");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 44);
        assert_eq!(lines[1].len(), 44);
    }

    #[test]
    fn extract_mrz_none_when_absent() {
        assert!(extract_mrz_candidate_lines("just some\nplain text\nno mrz here").is_none());
    }

    #[test]
    fn normalize_mrz_pads_and_truncates() {
        assert_eq!(normalize_mrz_line("ABC", 6), "ABC<<<");
        assert_eq!(normalize_mrz_line("ABCDEFGH", 4), "ABCD");
        // Stray characters (lowercase, punctuation, spaces) are
        // dropped — callers uppercase before normalizing.
        assert_eq!(normalize_mrz_line("A b!C", 5), "AC<<<");
    }

    #[test]
    fn ocr_derived_mrz_yields_claims() {
        let front = b"passport-front-photo" as &[u8];
        let text = format!("REPUBLIC OF UTOPIA\nPASSPORT\n{ERIKSSON_L1}\n{ERIKSSON_L2}\n");
        let out = run(
            &CaptureInput {
                front_bytes: front.to_vec(),
                back_bytes: vec![],
                selfie_bytes: vec![],
                template_id: "icao-passport-v1".to_string(),
                mrz_lines: vec![],
                salt: b"s".to_vec(),
            },
            &ocr_with_text(front, &text),
            &mock_face(),
        );
        let claims = out.claims.expect("OCR-derived MRZ should produce claims");
        assert_eq!(claims.surname, "ERIKSSON");
        assert_eq!(claims.given_names, "ANNA MARIA");
        assert!(
            out.signals
                .mrz
                .expect("mrz signals present")
                .all_checksums_valid
        );
    }

    #[test]
    fn ocr_derived_mrz_rejected_on_bad_checksum() {
        let front = b"corrupt-passport" as &[u8];
        // DOB digits zeroed but the original DOB check digit kept, so
        // the DOB (and composite) check digits no longer match.
        let bad_l2 = "L898902C36UTO0000002F1204159ZE184226B<<<<<10";
        let text = format!("PASSPORT\n{ERIKSSON_L1}\n{bad_l2}\n");
        let out = run(
            &CaptureInput {
                front_bytes: front.to_vec(),
                back_bytes: vec![],
                selfie_bytes: vec![],
                template_id: "icao-passport-v1".to_string(),
                mrz_lines: vec![],
                salt: b"s".to_vec(),
            },
            &ocr_with_text(front, &text),
            &mock_face(),
        );
        assert!(
            out.claims.is_none(),
            "OCR MRZ with a failed checksum must not yield claims"
        );
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let out = run(
            &CaptureInput {
                front_bytes: vec![],
                back_bytes: vec![],
                selfie_bytes: vec![],
                template_id: "test".to_string(),
                mrz_lines: vec![],
                salt: b"test-salt".to_vec(),
            },
            &mock_ocr(),
            &mock_face(),
        );
        assert!(out.claims.is_none());
        assert!(out.attestation.is_none());
        assert!(out.signals.mrz.is_none());
        assert!(out.signals.pdf417.is_none());
        // No stages ran -> no stage errors either.
        assert!(out.stage_errors.is_empty());
    }

    #[test]
    fn mrz_only_path_returns_claims() {
        // ICAO ERIKSSON example.
        let l1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".to_string();
        let l2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10".to_string();
        let out = run(
            &CaptureInput {
                front_bytes: vec![],
                back_bytes: vec![],
                selfie_bytes: vec![],
                template_id: "icao-passport-v1".to_string(),
                mrz_lines: vec![l1, l2],
                salt: b"test-salt".to_vec(),
            },
            &mock_ocr(),
            &mock_face(),
        );
        let claims = out.claims.expect("MRZ should produce claims");
        assert_eq!(claims.surname, "ERIKSSON");
        assert_eq!(claims.given_names, "ANNA MARIA");
        assert_eq!(claims.date_of_birth, "1974-08-12");
        let mrz_sig = out.signals.mrz.expect("mrz signals present");
        assert!(mrz_sig.all_checksums_valid);
        let att = out.attestation.expect("attestation built");
        assert_eq!(att.claim_type, "document_capture_v1");
        assert!(att.disclosed_field_hashes.contains_key("surname"));
        assert!(att.disclosed_claims.contains_key("age_over_18"));
    }

    #[test]
    fn mrz_malformed_records_stage_error() {
        let out = run(
            &CaptureInput {
                front_bytes: vec![],
                back_bytes: vec![],
                selfie_bytes: vec![],
                template_id: "test".to_string(),
                mrz_lines: vec!["only one line".to_string()],
                salt: vec![],
            },
            &mock_ocr(),
            &mock_face(),
        );
        assert!(out.claims.is_none());
        assert!(out.stage_errors.iter().any(|e| e.starts_with("mrz:")));
    }

    #[test]
    fn invalid_back_image_records_stage_error() {
        let out = run(
            &CaptureInput {
                front_bytes: vec![],
                back_bytes: b"not an image".to_vec(),
                selfie_bytes: vec![],
                template_id: "us-dl".to_string(),
                mrz_lines: vec![],
                salt: vec![],
            },
            &mock_ocr(),
            &mock_face(),
        );
        assert!(out.claims.is_none());
        assert!(out
            .stage_errors
            .iter()
            .any(|e| e.starts_with("pdf417 invalid image:")));
    }
}
