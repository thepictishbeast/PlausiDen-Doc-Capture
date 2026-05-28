//! Library entry point — re-exports the Router builder so
//! integration tests can drive the server without binding a socket.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod handlers;
pub mod pipeline;
pub mod state;

use axum::{extract::DefaultBodyLimit, routing::get, routing::post, Router};

pub use state::AppState;

/// Build the application Router with default state. Mirrors what
/// `main.rs` does, exposed so integration tests can call
/// `build_router().oneshot(req)` instead of needing a real TCP
/// listener.
pub fn build_router() -> Router {
    build_router_with_state(state::AppState::new())
}

/// Build the application Router with caller-supplied state.
///
/// Production deployments use this to inject real OCR + face
/// engines via [`AppState::with_ocr_engine`] +
/// [`AppState::with_face_engine`] before binding the listener.
/// Integration tests use this to inject pre-loaded Mock engines.
pub fn build_router_with_state(state: state::AppState) -> Router {
    // axum's `Multipart` extractor honors `DefaultBodyLimit`, whose
    // framework default is 2 MiB. Without overriding it, any upload
    // larger than 2 MiB total is rejected with 413 *before* the
    // handler's per-file `max_image_bytes` check runs — making a
    // configured cap above 2 MiB silently unreachable. Derive an
    // explicit total-body limit from the per-image cap (front + back
    // + selfie, plus headroom for text fields and multipart
    // boundaries) so the configured cap is actually honored while
    // still bounding total request memory.
    let capture_body_limit = state
        .config
        .max_image_bytes
        .saturating_mul(3)
        .saturating_add(256 * 1024);
    Router::new()
        .route("/health", get(handlers::health))
        .route("/info", get(handlers::info))
        .route(
            "/capture",
            post(handlers::capture).layer(DefaultBodyLimit::max(capture_body_limit)),
        )
        .with_state(state)
}
