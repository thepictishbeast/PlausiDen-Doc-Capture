//! `doc-capture-server` binary entry point.
//!
//! Library types live in `lib.rs`; this file is just the runtime
//! launcher (CLI args via env vars, tracing init, axum::serve).
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

use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let listen_addr: SocketAddr = std::env::var("DOC_CAPTURE_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7444".to_string())
        .parse()?;

    let app = doc_capture_server::build_router();

    info!(addr = %listen_addr, "doc-capture-server starting");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("DOC_CAPTURE_LOG_LEVEL")
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().json().with_env_filter(filter).init();
}
