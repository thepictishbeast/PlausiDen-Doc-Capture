//! Integration tests: drive the Router directly via tower::ServiceExt
//! without binding a TCP socket.
//!
//! Tests cover the three HTTP endpoints end-to-end including the
//! pipeline orchestrator behind /capture. PDF417 input is synthesized
//! via rxing's encoder so the test owns the full encode-decode loop.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok() {
    let app = doc_capture_server::build_router();
    let res = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn info_returns_server_identity() {
    let app = doc_capture_server::build_router();
    let res = app
        .oneshot(Request::builder().uri("/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(info["name"], "PlausiDen-Doc-Capture");
    let stages = info["stages_wired"].as_array().unwrap();
    let stage_names: Vec<&str> = stages.iter().map(|v| v.as_str().unwrap()).collect();
    // /info must reflect what pipeline::run actually executes. All
    // five stages below are wired (see doc-capture-server/src/pipeline.rs);
    // only liveness (anti-spoofing on the selfie) remains unimplemented.
    for wired in ["mrz", "pdf417_aamva", "ocr", "tamper", "face_match"] {
        assert!(
            stage_names.contains(&wired),
            "{wired} should be reported as wired"
        );
    }
    let pending = info["stages_pending"].as_array().unwrap();
    let pending_names: Vec<&str> = pending.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(pending_names.contains(&"liveness"));
    assert!(
        !pending_names.contains(&"ocr"),
        "ocr is wired, must not be reported pending"
    );
}

#[tokio::test]
async fn capture_empty_multipart_returns_400_or_empty_claims() {
    let app = doc_capture_server::build_router();
    let body = multipart_body(&[("template_id", "test")]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    // Empty multipart with only template_id is valid input; the
    // pipeline runs no stages, returns no claims, no errors.
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["verified"], false);
    assert!(resp["attestation"].is_null());
}

#[tokio::test]
async fn capture_with_mrz_extracts_passport_claims() {
    let app = doc_capture_server::build_router();
    let body = multipart_body(&[
        ("template_id", "icao-passport-v1"),
        ("salt", "test-subject-salt"),
        ("mrz_line_1", "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"),
        ("mrz_line_2", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["verified"], true);
    let att = &resp["attestation"];
    assert!(!att.is_null());
    assert_eq!(att["claim_type"], "document_capture_v1");
    // Surname hash should be present.
    assert!(att["disclosed_field_hashes"]["surname"]
        .as_str()
        .map(|s| s.len() == 64)
        .unwrap_or(false));
    // age_over_18 should be true (DOB 1974 -> > 18).
    assert_eq!(att["disclosed_claims"]["age_over_18"], true);
    let mrz_sig = &resp["signals"]["mrz"];
    assert_eq!(mrz_sig["all_checksums_valid"], true);
    assert_eq!(mrz_sig["lines_parsed"], 2);
}

#[tokio::test]
async fn capture_with_pdf417_image_extracts_aamva_claims() {
    // Build a synthetic AAMVA payload, encode as PDF417 PNG, POST
    // as the `back` multipart field.
    let payload = build_synth_aamva_payload();
    let png = synthesize_pdf417_png(&payload).expect("encode");

    let app = doc_capture_server::build_router();
    let body = multipart_image_body(&[
        ("template_id", b"us-driver-license-v1".to_vec()),
        ("salt", b"test-subject-salt".to_vec()),
        ("back", png),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        resp["verified"], true,
        "expected verified=true; got body: {resp}"
    );
    assert!(!resp["attestation"].is_null());
    let pdf417_sig = &resp["signals"]["pdf417"];
    assert_eq!(pdf417_sig["barcode_decoded"], true);
    assert_eq!(pdf417_sig["aamva_header_valid"], true);
    assert_eq!(
        pdf417_sig["aamva_jurisdiction_iin"], "636040",
        "expected Utah IIN; got: {pdf417_sig}"
    );
    // Disclosed state should be UT.
    assert_eq!(
        resp["attestation"]["disclosed_claims"]["issuing_state"],
        "UT"
    );
}

#[tokio::test]
async fn capture_with_corrupt_back_image_records_stage_error() {
    let app = doc_capture_server::build_router();
    let body = multipart_image_body(&[
        ("template_id", b"us-driver-license-v1".to_vec()),
        ("back", b"definitely not a valid image".to_vec()),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["verified"], false);
    let errs = resp["stage_errors"].as_array().unwrap();
    assert!(errs
        .iter()
        .any(|e| e.as_str().map(|s| s.contains("pdf417")).unwrap_or(false)));
}

// ─── helpers ────────────────────────────────────────────────────

/// Build a multipart body with only text fields. Boundary is fixed
/// to BOUNDARY for test predictability.
fn multipart_body(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(b"--BOUNDARY\r\n");
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--BOUNDARY--\r\n");
    body
}

/// Build a multipart body that mixes text + binary file fields.
/// Binary fields get a Content-Type: image/png so the parser
/// recognizes them as files.
fn multipart_image_body(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, bytes) in fields {
        body.extend_from_slice(b"--BOUNDARY\r\n");
        if *name == "back" || *name == "front" || *name == "selfie" {
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{name}.png\"\r\nContent-Type: image/png\r\n\r\n"
                )
                .as_bytes(),
            );
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--BOUNDARY--\r\n");
    body
}

/// Build the same synthetic AAMVA payload the aamva crate's
/// internal test uses. Pure copy because the aamva test helper is
/// private to its crate.
fn build_synth_aamva_payload() -> String {
    let header = format!(
        "@\n\x1e\rANSI {iin}{ver}{jver}{cnt}{stype}{off:0>4}{len:0>4}",
        iin = "636040",
        ver = "10",
        jver = "00",
        cnt = "01",
        stype = "DL",
        off = 33,
        len = 150,
    );
    let mut payload = header.into_bytes();
    while payload.len() < 33 {
        payload.push(b' ');
    }
    let mut body = String::new();
    body.push_str("DL\n");
    body.push_str("DAQX12345678\n");
    body.push_str("DCSDOE\n");
    body.push_str("DACJOHN\n");
    body.push_str("DADMICHAEL\n");
    body.push_str("DBB01151985\n");
    body.push_str("DBA12312030\n");
    body.push_str("DBD06012024\n");
    body.push_str("DAG3071 LIMESTONE DR\n");
    body.push_str("DAISAINT GEORGE\n");
    body.push_str("DAJUT\n");
    body.push_str("DAK847900000\n");
    body.push_str("DBC1\n");
    while body.len() < 150 {
        body.push(' ');
    }
    body.truncate(150);
    payload.extend_from_slice(body.as_bytes());
    String::from_utf8(payload).unwrap()
}

/// Synthesize a PDF417 PNG image from text (test-side encoder).
fn synthesize_pdf417_png(text: &str) -> Result<Vec<u8>, String> {
    use rxing::{BarcodeFormat, Writer};
    let writer = rxing::pdf417::PDF417Writer {};
    let bitmatrix = writer
        .encode(text, &BarcodeFormat::PDF_417, 600, 300)
        .map_err(|e| format!("encode: {e}"))?;
    let w = bitmatrix.getWidth();
    let h = bitmatrix.getHeight();
    let mut buf: Vec<u8> = Vec::with_capacity((w * h) as usize);
    for y in 0..h {
        for x in 0..w {
            buf.push(if bitmatrix.get(x, y) { 0 } else { 255 });
        }
    }
    let img = image::GrayImage::from_raw(w, h, buf).ok_or_else(|| "image::from_raw".to_string())?;
    let dyn_img = image::DynamicImage::ImageLuma8(img);
    let mut png = Vec::new();
    let mut cur = std::io::Cursor::new(&mut png);
    dyn_img
        .write_to(&mut cur, image::ImageFormat::Png)
        .map_err(|e| format!("png write: {e}"))?;
    Ok(png)
}

// ─── Phase 6: maximalist end-to-end tests ────────────────────────
//
// These tests prove the full pipeline coheres: a single POST with
// FOUR inputs (selfie + front + back + MRZ) flows through ALL FIVE
// wired stages (OCR + MRZ + PDF417/AAMVA + tamper + face match) and
// produces an attestation with every signal sub-struct populated.

/// Build an AAMVA payload whose surname matches the ICAO ERIKSSON
/// example MRZ, so the cross-validator passes.
fn build_eriksson_aamva_payload() -> String {
    let header = format!(
        "@\n\x1e\rANSI {iin}{ver}{jver}{cnt}{stype}{off:0>4}{len:0>4}",
        iin = "636040",
        ver = "10",
        jver = "00",
        cnt = "01",
        stype = "DL",
        off = 33,
        len = 150,
    );
    let mut payload = header.into_bytes();
    while payload.len() < 33 {
        payload.push(b' ');
    }
    let mut body = String::new();
    body.push_str("DL\n");
    body.push_str("DAQL898902C3\n"); // doc number matches MRZ
    body.push_str("DCSERIKSSON\n"); // surname matches MRZ
    body.push_str("DACANNA\n"); // given matches MRZ
    body.push_str("DADMARIA\n"); // middle matches MRZ
    body.push_str("DBB08121974\n"); // DOB matches MRZ (1974-08-12)
    body.push_str("DBA04152012\n"); // exp matches MRZ (2012-04-15)
    body.push_str("DBD01012010\n"); // issue date (arbitrary)
    body.push_str("DAG123 MAIN ST\n");
    body.push_str("DAISALT LAKE CITY\n");
    body.push_str("DAJUT\n");
    body.push_str("DAK841010000\n");
    body.push_str("DBC2\n"); // sex=F to match MRZ
    while body.len() < 150 {
        body.push(' ');
    }
    body.truncate(150);
    payload.extend_from_slice(body.as_bytes());
    String::from_utf8(payload).unwrap()
}

/// Generate a small JPEG image suitable as a "front-of-document"
/// or "selfie" image input. JPEG (not PNG) because the tamper
/// stage's ELA is calibrated for JPEG; PNG inputs ALSO work but
/// the score will be slightly higher.
fn synth_jpeg(width: u32, height: u32, seed: u32) -> Vec<u8> {
    // Build a smooth gradient image — keeps ELA score low so the
    // tamper stage doesn't flag a synthetic input as suspicious.
    let mut img = image::ImageBuffer::<image::Rgb<u8>, Vec<u8>>::new(width, height);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgb([
            ((x.wrapping_mul(2).wrapping_add(seed)) % 256) as u8,
            ((y.wrapping_mul(2).wrapping_add(seed)) % 256) as u8,
            ((x.wrapping_add(y).wrapping_add(seed)) % 256) as u8,
        ]);
    }
    let mut out = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 90);
    use image::ImageEncoder;
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

#[tokio::test]
async fn maximalist_e2e_all_five_stages_fire() {
    use doc_capture_core::{FaceMatchSignals, OcrSignals};

    // Pre-loaded Mock fixtures so the engines return "matched"
    // outcomes for our synthesized fixtures.
    let front_jpeg = synth_jpeg(160, 100, 1);
    let selfie_jpeg = synth_jpeg(160, 200, 7);

    let ocr_fixture = doc_capture_ocr::OcrResult {
        text: "ERIKSSON\nANNA MARIA\n01 AUG 1974".to_string(),
        signals: OcrSignals {
            text_confidence: 0.92,
            required_fields_present: true,
            detected_orientation: 0,
        },
        lines: vec![],
    };
    let face_fixture = FaceMatchSignals {
        distance: 0.21,
        threshold: 0.5,
        matched: true,
        liveness_passed: Some(true),
    };

    let ocr_engine = std::sync::Arc::new(
        doc_capture_ocr::MockOcrEngine::new().with_fixture(&front_jpeg, ocr_fixture),
    );
    let face_engine =
        std::sync::Arc::new(doc_capture_face::MockFaceMatchEngine::new().with_fixture(
            &selfie_jpeg,
            &front_jpeg,
            face_fixture,
        ));
    let state = doc_capture_server::AppState::new()
        .with_ocr_engine(ocr_engine)
        .with_face_engine(face_engine);
    let app = doc_capture_server::build_router_with_state(state);

    // Encode the matching AAMVA payload as a PDF417 PNG for the
    // back-of-document input.
    let aamva = build_eriksson_aamva_payload();
    let back_png = synthesize_pdf417_png(&aamva).expect("encode pdf417");

    let body = multipart_image_body(&[
        ("template_id", b"e2e-passport-and-dl".to_vec()),
        ("salt", b"test-subject-salt".to_vec()),
        // MRZ from the ICAO example.
        (
            "mrz_line_1",
            b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".to_vec(),
        ),
        (
            "mrz_line_2",
            b"L898902C36UTO7408122F1204159ZE184226B<<<<<10".to_vec(),
        ),
        ("front", front_jpeg.clone()),
        ("back", back_png),
        ("selfie", selfie_jpeg.clone()),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        resp["verified"], true,
        "maximalist e2e should verify; got: {resp}"
    );

    // EVERY signal sub-struct should be populated.
    let signals = &resp["signals"];
    assert!(
        !signals["ocr"].is_null(),
        "ocr signals missing in maximalist e2e"
    );
    assert!(
        !signals["mrz"].is_null(),
        "mrz signals missing in maximalist e2e"
    );
    assert!(
        !signals["pdf417"].is_null(),
        "pdf417 signals missing in maximalist e2e"
    );
    assert!(
        !signals["tamper"].is_null(),
        "tamper signals missing in maximalist e2e"
    );
    assert!(
        !signals["face_match"].is_null(),
        "face_match signals missing in maximalist e2e"
    );

    // Per-stage spot checks
    assert_eq!(signals["mrz"]["all_checksums_valid"], true);
    assert_eq!(signals["pdf417"]["barcode_decoded"], true);
    assert_eq!(signals["face_match"]["matched"], true);
    assert_eq!(signals["face_match"]["liveness_passed"], true);
    assert_eq!(signals["ocr"]["required_fields_present"], true);
    // Tamper score should be low for the synthetic gradient JPEG.
    let ela = signals["tamper"]["ela_score"].as_f64().unwrap();
    assert!(
        ela < 0.05,
        "synthetic gradient should not flag as tampered (got {ela})"
    );
    assert_eq!(signals["tamper"]["suspicious"], false);

    // Attestation properties
    let att = &resp["attestation"];
    assert_eq!(att["claim_type"], "document_capture_v1");
    assert!(att["disclosed_field_hashes"]["surname"].as_str().is_some());
    assert_eq!(att["disclosed_claims"]["issuing_state"], "UT");
    assert_eq!(att["disclosed_claims"]["age_over_18"], true);
}

#[tokio::test]
async fn cross_validator_catches_surname_mismatch() {
    // MRZ = ERIKSSON, AAMVA = DOE → cross-validator should emit a
    // stage error and the response should be verified=false.
    let front_jpeg = synth_jpeg(64, 64, 3);

    let state = doc_capture_server::AppState::new();
    let app = doc_capture_server::build_router_with_state(state);

    let aamva_doe = build_synth_aamva_payload(); // surname DOE
    let back_png = synthesize_pdf417_png(&aamva_doe).expect("encode pdf417");

    let body = multipart_image_body(&[
        ("template_id", b"mismatch-test".to_vec()),
        ("salt", b"test-salt".to_vec()),
        (
            "mrz_line_1",
            b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".to_vec(),
        ),
        (
            "mrz_line_2",
            b"L898902C36UTO7408122F1204159ZE184226B<<<<<10".to_vec(),
        ),
        ("front", front_jpeg),
        ("back", back_png),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        resp["verified"], false,
        "surname mismatch should fail verification"
    );
    let errs = resp["stage_errors"].as_array().unwrap();
    assert!(
        errs.iter().any(|e| e
            .as_str()
            .map(|s| s.contains("cross-validation"))
            .unwrap_or(false)),
        "expected cross-validation stage_error; got: {errs:?}"
    );
}
