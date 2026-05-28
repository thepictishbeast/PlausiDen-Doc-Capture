//! HTTP handlers.
//!
//! Each handler is a thin shell that:
//!   1. Parses the request envelope (multipart, query string, etc.)
//!   2. Delegates the actual work to `pipeline::run`
//!   3. Shapes the pipeline output back into the JSON response
//!      shape consumers expect
//!
//! All non-fatal errors are surfaced as 200 with a structured
//! `{verified: false, error, ...}` payload so the consumer's
//! decoder doesn't have to branch on status codes for the common
//! "couldn't extract claims" outcome.

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::pipeline::{self, CaptureInput};
use crate::state::AppState;

/// `GET /health` — liveness probe.
pub async fn health() -> &'static str {
    "ok"
}

/// `GET /info` — server identity + supported pipeline stages.
#[derive(Debug, Serialize)]
pub struct InfoResponse {
    /// Server name (constant — useful for operators chaining behind
    /// reverse proxies).
    pub name: &'static str,
    /// Version string from CARGO_PKG_VERSION.
    pub version: &'static str,
    /// Pipeline stages currently wired into /capture.
    pub stages_wired: Vec<&'static str>,
    /// Pipeline stages declared but not yet wired (operator
    /// visibility into the phase ladder).
    pub stages_pending: Vec<&'static str>,
    /// Active session count.
    pub active_sessions: usize,
}

/// Handler for `GET /info`.
pub async fn info(State(state): State<AppState>) -> Json<InfoResponse> {
    let active_sessions = state
        .sessions
        .lock()
        .map(|s| s.len())
        .unwrap_or(0);
    Json(InfoResponse {
        name: "PlausiDen-Doc-Capture",
        version: env!("CARGO_PKG_VERSION"),
        stages_wired: vec!["mrz", "pdf417_aamva"],
        stages_pending: vec!["ocr", "tamper", "face_match", "liveness"],
        active_sessions,
    })
}

/// `POST /capture` request shape (deserialized from multipart).
#[derive(Debug, Default)]
struct CaptureForm {
    front: Vec<u8>,
    back: Vec<u8>,
    selfie: Vec<u8>,
    template_id: String,
    mrz_lines: Vec<String>,
    salt: Vec<u8>,
}

/// `POST /capture` response shape.
#[derive(Debug, Serialize)]
pub struct CaptureResponse {
    /// Per-call session id (random).
    pub session_id: String,
    /// Overall verification verdict. `false` when no stage produced
    /// claims OR when any wired stage reports a clear failure
    /// signal. Consumers re-derive their own verdict from the
    /// detailed `signals` if their threshold differs from the
    /// orchestrator's default.
    pub verified: bool,
    /// Cryptographic attestation (hashed claims + per-stage
    /// signals). `null` when no claims were extracted.
    pub attestation: Option<doc_capture_core::Attestation>,
    /// Disclosed plaintext claims per the default disclosure mask.
    /// Always small (issuing_state + age_over_18); raw PII never
    /// appears here.
    pub disclosed_claims: serde_json::Value,
    /// Per-stage signals (also embedded in the attestation —
    /// duplicated here for convenience in the response).
    pub signals: doc_capture_core::PipelineSignals,
    /// Aggregated stage errors. Empty when verification succeeded.
    pub stage_errors: Vec<String>,
}

/// Handler for `POST /capture`.
pub async fn capture(
    State(state): State<AppState>,
    multipart: Multipart,
) -> Result<Json<CaptureResponse>, (StatusCode, String)> {
    let form = parse_multipart(multipart, state.config.max_image_bytes).await?;

    let input = CaptureInput {
        front_bytes: form.front,
        back_bytes: form.back,
        selfie_bytes: form.selfie,
        template_id: form.template_id,
        mrz_lines: form.mrz_lines,
        salt: form.salt,
    };
    let out = pipeline::run(input, &state.ocr, &state.face);

    // Cache the per-stage signals against the session id so
    // GET /session/{id} (phase 2.5) can return them later.
    if let Ok(mut store) = state.sessions.lock() {
        store.put(
            out.session_id.clone(),
            crate::state::SessionEntry {
                created_at: chrono::Utc::now(),
                signals: out.signals.clone(),
            },
        );
    }

    let verified = out.claims.is_some() && out.stage_errors.is_empty();
    let disclosed_claims = out
        .attestation
        .as_ref()
        .map(|a| serde_json::to_value(&a.disclosed_claims).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    Ok(Json(CaptureResponse {
        session_id: out.session_id,
        verified,
        attestation: out.attestation,
        disclosed_claims,
        signals: out.signals,
        stage_errors: out.stage_errors,
    }))
}

/// Parse the multipart envelope into a [`CaptureForm`].
///
/// Field names accepted:
///   - `front`, `back`, `selfie` — file uploads (max
///     `max_image_bytes` per file)
///   - `template_id` — UTF-8 text, max 64 chars
///   - `mrz_line_1`, `mrz_line_2`, `mrz_line_3` — UTF-8 text;
///     accumulated into `CaptureForm::mrz_lines` preserving order
///   - `salt` — UTF-8 text (per-subject opaque identifier); max
///     256 bytes
///
/// Any other field is silently ignored. Per-file size cap is
/// enforced by accumulating into a length-checked Vec.
async fn parse_multipart(
    mut mp: Multipart,
    max_image_bytes: usize,
) -> Result<CaptureForm, (StatusCode, String)> {
    let mut form = CaptureForm::default();
    let mut mrz: [Option<String>; 3] = [None, None, None];

    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("multipart parse: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "front" | "back" | "selfie" => {
                let bytes = read_image_bytes(field, max_image_bytes).await?;
                match name.as_str() {
                    "front" => form.front = bytes,
                    "back" => form.back = bytes,
                    "selfie" => form.selfie = bytes,
                    _ => unreachable!(),
                }
            }
            "template_id" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("template_id: {e}")))?;
                if s.len() > 64 {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "template_id too long (max 64)".into(),
                    ));
                }
                form.template_id = s;
            }
            "mrz_line_1" | "mrz_line_2" | "mrz_line_3" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("mrz_line: {e}")))?;
                if s.len() > 200 {
                    return Err((StatusCode::BAD_REQUEST, "mrz_line too long".into()));
                }
                let idx = match name.as_str() {
                    "mrz_line_1" => 0,
                    "mrz_line_2" => 1,
                    _ => 2,
                };
                mrz[idx] = Some(s);
            }
            "salt" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("salt: {e}")))?;
                if s.len() > 256 {
                    return Err((StatusCode::BAD_REQUEST, "salt too long".into()));
                }
                form.salt = s.into_bytes();
            }
            _ => {
                // Drain unknown fields so the multipart parser
                // advances; ignore content.
                let _ = field.bytes().await;
            }
        }
    }

    // Compact non-None mrz entries preserving order.
    form.mrz_lines = mrz.into_iter().flatten().collect();

    Ok(form)
}

/// Read field bytes into a Vec, enforcing the per-file cap.
async fn read_image_bytes(
    field: axum::extract::multipart::Field<'_>,
    max_bytes: usize,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = field
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("image read: {e}")))?;
    if bytes.len() > max_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("image exceeds {max_bytes} bytes"),
        ));
    }
    Ok(bytes.to_vec())
}

impl IntoResponse for crate::pipeline::CaptureOutput {
    fn into_response(self) -> axum::response::Response {
        // Not currently used; convenience for future ergonomics.
        Json(serde_json::json!({
            "session_id": self.session_id,
            "stage_errors": self.stage_errors,
        }))
        .into_response()
    }
}
