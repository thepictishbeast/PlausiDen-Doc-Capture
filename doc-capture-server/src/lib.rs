//! Library entry point — re-exports the Router builder so
//! integration tests can drive the server without binding a socket.

pub mod handlers;
pub mod pipeline;
pub mod state;

use axum::{routing::get, routing::post, Router};

/// Build the application Router with default state. Mirrors what
/// `main.rs` does, exposed so integration tests can call
/// `build_router().oneshot(req)` instead of needing a real TCP
/// listener.
pub fn build_router() -> Router {
    let state = state::AppState::new();
    Router::new()
        .route("/health", get(handlers::health))
        .route("/info", get(handlers::info))
        .route("/capture", post(handlers::capture))
        .with_state(state)
}
