//! `doc-capture-server` binary entry point.
//!
//! Library types live in `lib.rs`; this file is just the runtime
//! launcher (CLI args via env vars, tracing init, `axum::serve`).
//!
//! ## Environment
//!
//! - `DOC_CAPTURE_LISTEN_ADDR` — bind address. Defaults to
//!   `127.0.0.1:7444`. Use `0.0.0.0:7444` only behind a trusted
//!   reverse proxy.
//! - `DOC_CAPTURE_MAX_IMAGE_BYTES` — per-file size cap in bytes
//!   (default 8 MiB).
//! - `DOC_CAPTURE_LOG_LEVEL` — tracing-subscriber env-filter
//!   (default `info`).
//! - `DOC_CAPTURE_OCR_ENGINE` — OCR backend selector. `mock`
//!   (default) returns no-recognition for any image; `tesseract`
//!   shells out to the Tesseract CLI. `tesseract` is only honored
//!   when the binary was built `--features tesseract-cli`; otherwise
//!   it logs a warning and falls back to `mock`.
//! - `DOC_CAPTURE_TESSERACT_BIN` — path to the `tesseract` binary
//!   when the `tesseract` engine is selected (default: `tesseract`,
//!   resolved on PATH).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let listen_addr: SocketAddr = std::env::var("DOC_CAPTURE_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7444".to_string())
        .parse()?;

    let state = doc_capture_server::state::AppState::new().with_ocr_engine(select_ocr_engine());
    let app = doc_capture_server::build_router_with_state(state);

    info!(addr = %listen_addr, "doc-capture-server starting");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Resolve the OCR engine backend from `DOC_CAPTURE_OCR_ENGINE`.
///
/// Defaults to the Mock engine. `tesseract` is only available when
/// the binary is built `--features tesseract-cli`; if requested
/// without that feature, this logs a warning and falls back to Mock
/// so the server still boots (it just won't OCR).
fn select_ocr_engine() -> std::sync::Arc<dyn doc_capture_ocr::OcrEngine> {
    use std::sync::Arc;
    let choice = std::env::var("DOC_CAPTURE_OCR_ENGINE").unwrap_or_else(|_| "mock".to_string());
    match choice.as_str() {
        "tesseract" => tesseract_engine(),
        other => {
            if other == "mock" {
                info!(engine = "mock", "OCR engine selected");
            } else {
                tracing::warn!(
                    requested = other,
                    "unknown DOC_CAPTURE_OCR_ENGINE; falling back to mock"
                );
            }
            Arc::new(doc_capture_ocr::MockOcrEngine::new())
        }
    }
}

/// Build the Tesseract CLI engine when compiled with the
/// `tesseract-cli` feature; otherwise warn and fall back to Mock so
/// the server still boots (it just won't OCR).
#[cfg(feature = "tesseract-cli")]
fn tesseract_engine() -> std::sync::Arc<dyn doc_capture_ocr::OcrEngine> {
    let bin =
        std::env::var("DOC_CAPTURE_TESSERACT_BIN").unwrap_or_else(|_| "tesseract".to_string());
    info!(engine = "tesseract", %bin, "OCR engine selected");
    std::sync::Arc::new(doc_capture_ocr::TesseractCliEngine::with_binary(bin))
}

/// Fallback when the `tesseract-cli` feature is not compiled in.
#[cfg(not(feature = "tesseract-cli"))]
fn tesseract_engine() -> std::sync::Arc<dyn doc_capture_ocr::OcrEngine> {
    tracing::warn!(
        "DOC_CAPTURE_OCR_ENGINE=tesseract requested but binary built without the \
         `tesseract-cli` feature; falling back to mock (no OCR)"
    );
    std::sync::Arc::new(doc_capture_ocr::MockOcrEngine::new())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("DOC_CAPTURE_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}
