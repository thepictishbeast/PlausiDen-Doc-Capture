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
