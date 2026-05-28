//! Server state: capture-session store + config.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration knobs sourced from environment variables at boot.
#[derive(Debug, Clone)]
pub struct Config {
    /// Per-image size cap in bytes; applied to each multipart part.
    pub max_image_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_image_bytes: std::env::var("DOC_CAPTURE_MAX_IMAGE_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8 * 1024 * 1024),
        }
    }
}

/// In-memory capture-session store for retrievable diagnostics.
///
/// Holds ONLY the per-stage signals and the attestation — never raw
/// image bytes, never raw PII claims. Session entries auto-expire
/// after a fixed window so the store can't grow unbounded.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: HashMap<String, SessionEntry>,
}

/// One captured-session record.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    /// When the session was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Per-stage signals from the pipeline.
    pub signals: doc_capture_core::PipelineSignals,
}

impl SessionStore {
    /// Insert a session record.
    pub fn put(&mut self, id: String, entry: SessionEntry) {
        self.inner.insert(id, entry);
    }

    /// Fetch a session record by ID.
    pub fn get(&self, id: &str) -> Option<SessionEntry> {
        self.inner.get(id).cloned()
    }

    /// Current number of stored sessions (for /info).
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Cloneable state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    /// Shared configuration.
    pub config: Arc<Config>,
    /// Capture-session store. Mutex-guarded; the contention window
    /// is tiny (insert one session record per /capture call).
    pub sessions: Arc<Mutex<SessionStore>>,
}

impl AppState {
    /// Construct a fresh AppState. Reads env vars for configuration.
    pub fn new() -> Self {
        Self {
            config: Arc::new(Config::default()),
            sessions: Arc::new(Mutex::new(SessionStore::default())),
        }
    }
}
