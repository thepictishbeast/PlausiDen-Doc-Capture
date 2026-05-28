//! Library entry point — re-exports the Router builder so
//! integration tests can drive the server without binding a socket.

pub mod handlers;
pub mod pipeline;
pub mod state;

use axum::{routing::get, routing::post, Router};

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
    Router::new()
        .route("/health", get(handlers::health))
        .route("/info", get(handlers::info))
        .route("/capture", post(handlers::capture))
        .with_state(state)
}
