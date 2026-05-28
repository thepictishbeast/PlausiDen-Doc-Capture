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
    assert!(stage_names.contains(&"mrz"));
    assert!(stage_names.contains(&"pdf417_aamva"));
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
                .header(
                    "content-type",
                    "multipart/form-data; boundary=BOUNDARY",
                )
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
        (
            "mrz_line_1",
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        ),
        (
            "mrz_line_2",
            "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        ),
    ]);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/capture")
                .header(
                    "content-type",
                    "multipart/form-data; boundary=BOUNDARY",
                )
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
    assert!(
        att["disclosed_field_hashes"]["surname"]
            .as_str()
            .map(|s| s.len() == 64)
            .unwrap_or(false)
    );
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
                .header(
                    "content-type",
                    "multipart/form-data; boundary=BOUNDARY",
                )
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
    assert_eq!(resp["attestation"]["disclosed_claims"]["issuing_state"], "UT");
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
                .header(
                    "content-type",
                    "multipart/form-data; boundary=BOUNDARY",
                )
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
    assert!(errs.iter().any(|e| e
        .as_str()
        .map(|s| s.contains("pdf417"))
        .unwrap_or(false)));
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
