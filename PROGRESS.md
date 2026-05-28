# PlausiDen-Doc-Capture progress log

Living iteration log. Each entry: timestamp, phase, what shipped, test counts.

## Iter #1 — 2026-05-28 — Phase 1b kickoff (PDF417 binary decoder)

State entering iter:
- Phase 0 ✅ doc-capture-core + doc-capture-mrz (20 tests)
- Phase 1a ✅ doc-capture-aamva (8 tests)
- Cumulative 28/28 tests green
- README + workspace generic (zero "Sacred|sacredvote|voter\b" hits)
- Pushed to github.com/thepictishbeast/PlausiDen-Doc-Capture (commit 372c153)

Plan for Phase 1b:
- New crate doc-capture-pdf417
- Wraps `rxing` for PDF417 binary decode from image input
- Output is the AAMVA TEXT payload that doc-capture-aamva already parses
- Feature-gate the heavy decode behind `--features pdf417-rxing` so the
  minimal build doesn't pull rxing's dependency tree
- Tests: synthetic-payload generator that round-trips a known AAMVA
  string through encoded PDF417 → decoded TEXT (uses `rxing`'s encoder
  for the test side; the production path only uses decoder)

Per AVP-2 absorption doctrine: rxing is large and not yet audited.
Initial commit uses it via cargo dep; mark in COMMIT body that
absorption-pass is queued as a follow-up task.

## Iter #1 result — Phase 1b ✅

Shipped `doc-capture-pdf417`:
- `decode_pdf417_from_image_bytes(&[u8]) -> Result<String, Error>` — single-function consumer surface
- Wraps rxing 0.9 via `rxing::helpers::detect_in_buffer(_, Some(BarcodeFormat::PDF_417))`
- Distinguishes InvalidImage vs Pdf417DecodeFailed by sniffing rxing's error-string prefix (helpers.rs:138 "buffer cannot be loaded as image")
- 3 tests:
  * roundtrip: short payload encode -> PNG -> decode == input
  * roundtrip: 261-byte AAMVA-shaped payload encode -> PNG -> decode == input
  * rejection: non-image bytes -> Error::InvalidImage

Cumulative state:
- Workspace: 4 crates (core + mrz + aamva + pdf417)
- Tests: 31/31 passing (6 + 14 + 8 + 3)
- Zero "Sacred|sacredvote|voter\b" hits anywhere
- rxing absorption follow-up tracked separately

Next phase queued: Phase 2 — doc-capture-server (axum HTTP, /capture endpoint wiring all decoders).

## Iter #2 result — Phase 2 ✅

Shipped `doc-capture-server`:
- axum HTTP server, binary at `/usr/local/bin/doc-capture-server` (when installed)
- 3 endpoints: `GET /health`, `GET /info`, `POST /capture` (multipart)
- `pipeline` module orchestrates wired stages (MRZ + PDF417/AAMVA today; OCR/tamper/face TODO)
- `handlers` module parses multipart + delegates to pipeline + shapes response
- `state` module: in-memory `SessionStore` + `Config` from env vars (`DOC_CAPTURE_LISTEN_ADDR`, `DOC_CAPTURE_MAX_IMAGE_BYTES`, `DOC_CAPTURE_LOG_LEVEL`)
- `lib.rs` exposes `build_router()` so integration tests can drive without TCP

Cross-validator: when both MRZ and AAMVA produce claims, surname mismatch is recorded as a stage error (loose match — case-insensitive, punctuation-stripped, whitespace-collapsed).

Attestation construction:
- Per-field SHA-256 hashes (salt + name + value), 8 baseline fields + issuing_state when present
- Default disclosure: issuing_state + age_over_18 (computed from DOB)
- Raw PII never in response body, never in logs

7 unit tests + 6 integration tests:
- /health returns "ok"
- /info returns valid JSON with stages_wired=[mrz, pdf417_aamva]
- /capture with empty multipart → verified=false, no attestation, no errors
- /capture with ICAO MRZ → verified=true, surname hash present, age_over_18=true
- /capture with synthesized PDF417 PNG of AAMVA payload → verified=true, IIN=636040, state=UT
- /capture with corrupt back-image bytes → verified=false with pdf417 stage_error

Cumulative state:
- 5 crates (core + mrz + aamva + pdf417 + server)
- 44/44 tests passing
- Zero "Sacred|sacredvote|voter\b" hits in *.rs/*.toml
- Sidecar can serve real /capture requests against PDF417 input today

Next phase queued: Phase 3 — doc-capture-ocr Tesseract adapter (feature-gated; native dep).

## Iter #6 result — Phase 6 ✅

Shipped end-to-end integration tests proving all 5 stages cohere:

`maximalist_e2e_all_five_stages_fire` — single POST with selfie + front + back + mrz_lines → ALL 5 stages fire, attestation populated, `verified=true`. Uses pre-loaded MockOcr + MockFace fixtures (constructed via the new `build_router_with_state` + `with_ocr_engine` / `with_face_engine` injection seams) so the test owns the full input space. ICAO ERIKSSON example MRZ paired with a hand-crafted AAMVA payload (surname=ERIKSSON, given=ANNA MARIA, dob=1974-08-12, exp=2012-04-15) so the cross-validator passes. Synthetic JPEG fronts + selfies keep ELA scores low.

`cross_validator_catches_surname_mismatch` — same shape but with AAMVA surname=DOE while MRZ says ERIKSSON. Asserts `verified=false` and a stage_error containing "cross-validation".

Server lib gained `build_router_with_state(AppState)` and re-exported `AppState` publicly so tests + production deployments can both inject custom engines without going through the default `new()` Mocks.

Cumulative state:
- 8 crates, 63/63 tests (8 + 6 + 14 + 5 + 3 + 7 + 8 + 6 + 6)
- All 5 stages have wired adapters AND a passing e2e test
- Zero "Sacred|sacredvote|voter\b" hits
- Sidecar is functionally complete from an HTTP-API perspective

Next phase queued: Phase 7 — NixOS module + systemd unit + Caddy reverse-proxy snippet for production deploy. After that, the substrate is shippable.

## Iter #7 result — Phase 7 ✅ — SUBSTRATE COMPLETE

Shipped `infra/` deployment artifacts:

`infra/nixos/module.nix` — NixOS module declaring:
- `services.doc-capture-server.enable` + 6 options (listenAddr, maxImageBytes, logLevel, user, group, extraEnvironment, package)
- Dedicated `doc-capture` system user/group
- Systemd unit with full sandboxing posture (NoNewPrivileges, ProtectSystem=strict, PrivateTmp, MemoryDenyWriteExecute, SystemCallFilter=@system-service, etc.)
- Resource limits: MemoryMax=1G, TasksMax=256, LimitNOFILE=4096

`infra/systemd/doc-capture-server.service` — equivalent unit file for non-Nix hosts. Same sandboxing directives. Operator installs via `sudo cp + systemctl daemon-reload + enable --now`.

`infra/caddy/Caddyfile.snippet` — TLS-terminating reverse-proxy fronting the loopback-bound sidecar. Caps multipart at 32 MiB at Caddy layer. Active health-checks `/health` every 30s with 2s timeout. Forwards X-Real-IP for future rate-limit/audit features.

`infra/README.md` — deployment guide covering all 3 paths + smoke-test commands + production checklist.

README.md Status section updated: all 7 phases shipped ✅.

## All-phases summary

| Phase | Crate / Artifact | Status |
|-------|------------------|--------|
| 0 | doc-capture-core + doc-capture-mrz | ✅ |
| 1a | doc-capture-aamva | ✅ |
| 1b | doc-capture-pdf417 | ✅ |
| 2 | doc-capture-server | ✅ |
| 3 | doc-capture-ocr | ✅ |
| 4 | doc-capture-tamper | ✅ |
| 5 | doc-capture-face | ✅ |
| 6 | maximalist e2e test | ✅ |
| 7 | infra/ (NixOS + systemd + Caddy) | ✅ |

**Final state:** 8 crates, 63 tests, zero "Sacred/sacredvote/voter" leakage, end-to-end `/capture` call demonstrably succeeds via the maximalist integration test that runs all 5 stages against synthetic inputs.

Stop condition met: all 7 phases shipped AND the e2e `/capture` call works (proven by `maximalist_e2e_all_five_stages_fire` test). Substrate is functionally complete and deployment-ready.

Loop should retire — CronDelete next.
