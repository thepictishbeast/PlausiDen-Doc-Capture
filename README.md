# PlausiDen-Doc-Capture

> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept: no warranty of any kind, no fitness
> for any particular purpose, no guarantee of correctness or safety,
> zero liability on the maintainer for any damages.
>
> Engineering doctrine per [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> No commit in this repository has reached `SHIP-DECISION:` status.

<!-- repo-label: substrate -->
<!-- repo-class: identity-verification-substrate -->
<!-- repo-consumes: PlausiDen-Obs, PlausiDen-AVP-Doctrine -->
<!-- repo-consumed-by: any application that needs to verify a person holds a government-issued identity document -->
<!-- repo-tier: tbd -->
<!-- repo-status: experimental -->
<!-- repo-avp-subject: yes -->
<!-- repo-reference-impl-language: rust -->
<!-- repo-target-stack-scope: linux-x86_64 -->

Generic substrate for document-capture identity verification. A user
photographs their government-issued ID and a selfie; this substrate
runs OCR, MRZ checksum verification, PDF417 + AAMVA barcode parsing,
tamper detection, and face matching, then returns a cryptographic
attestation that the user holds the document. The substrate is
consumer-agnostic — any application that needs "this person holds
this document" verification can adopt it.

**Privacy posture, load-bearing:** captured images live in process
memory only. They are NEVER written to disk and NEVER returned to the
caller. The attestation contains hashed claims (name, DOB, document
ID truncated) — never the raw image, never raw PII.

## Why this exists

Identity verification of "this person holds this document" is a
recurring need across civic-tech, fintech, and high-trust
applications. Existing solutions force a choice between:

- **Commercial vendors** (Onfido, Persona, Veriff, Jumio): per-check
  cost, vendor lock-in, document images retained on vendor
  infrastructure for fraud-network analysis. Breaks any
  privacy-first claim downstream applications want to make.
- **Mobile Driver's License / OID4VP**: cryptographically strong but
  not all jurisdictions support remote verification flows, and the
  ecosystem is uneven (Apple Wallet, Google Wallet, GET Mobile ID,
  IDEMIA — each with different remote-verify constraints).
- **Roll-your-own**: most projects can't afford the engineering time
  for OCR + MRZ + PDF417 + liveness + tamper detection.

This substrate provides the roll-your-own option as a maintained
public good. Apache-2.0 / MIT dual-licensed, FOSS components only,
no native deps in the core kernel, and a feature-gated heavier
stack (Tesseract, face-match models) for the production build.

## Pipeline stages

1. **OCR** — extract text fields (name, DOB, address, ID number,
   expiration) from the front of the document via Tesseract.
2. **MRZ** — for documents with a Machine Readable Zone (passports,
   newer state IDs), parse the MRZ lines and verify per-field
   checksums. MRZ check-digit verification is the single strongest
   tamper-resistance signal because the checksums are computed at
   issuance and any modification of name/DOB/document-number breaks
   them.
3. **PDF417 + AAMVA** — for US driver licenses + state IDs, parse
   the back-of-card PDF417 barcode and decode the AAMVA Card Design
   Standard fields. Cross-check the parsed AAMVA fields against the
   front-of-card OCR.
4. **Tamper detection** — Error-Level Analysis (ELA) on the
   captured image flags regions with anomalous JPEG compression
   artifacts that correlate with digital tampering of a captured
   image.
5. **Face match** — compare the user's selfie against the document
   portrait via face-embedding distance. Threshold is configurable;
   default is 0.5 cosine distance.
6. **Liveness** — challenge-response (blink, head turn) during
   capture; passive liveness deferred for the MVP.

Each stage emits structured signals into the final attestation. A
verification is `verified: true` only when all required stages pass
the consumer-configured thresholds.

## API surface

```
POST /capture        multipart: front (image), back (image, optional),
                                 selfie (image), template_id (string)
                     → 200 { session_id, claims, attestation, ...signals }
                     → 422 { error: "document_not_recognized: ...", ... }
                     → 502 { error: "ocr_unavailable: ..." }

GET  /health         → 200 "ok"
GET  /info           → 200 { public_key, name, templates, ... }
GET  /session/{id}   → 200 NotarySession  (proof retrievability for audit)
```

The shape parallels other identity-attestation substrates in the
PlausiDen ecosystem so consumers can mix-and-match.

## Crate layout

| Crate | Status | Responsibility |
|-------|--------|----------------|
| `doc-capture-core` | ✅ Phase 0 | Typed surface: claims, attestation, errors, per-stage signals |
| `doc-capture-mrz` | ✅ Phase 0 | ICAO 9303 Part 3 MRZ parser + check-digit verification |
| `doc-capture-aamva` | ✅ Phase 1a | AAMVA Card Design Standard decoder for US DL / state ID |
| `doc-capture-pdf417` | 📋 Phase 1b | PDF417 binary decoder (image → AAMVA text) |
| `doc-capture-ocr` | 📋 Phase 3 | Tesseract adapter (feature-gated, optional) |
| `doc-capture-tamper` | 📋 Phase 4 | Error-Level Analysis tamper detector |
| `doc-capture-face` | 📋 Phase 5 | Face match + liveness (feature-gated) |
| `doc-capture-server` | 📋 Phase 2 | axum HTTP server — the binary consumers run |

## Consumer integration shape

Consumers run `doc-capture-server` as a sidecar on a private port and
talk to it over JSON. The substrate is application-agnostic: a civic
voting platform, a regulated fintech app, a research-data marketplace
and a private community forum all use the same API. The consumer
provides per-verification context (a stable opaque user identifier
to bind the attestation to, a salt for the per-field claim hashes,
and any custom disclosure mask), receives the attestation, and
decides what to do with it.

The substrate makes no assumptions about:
- What downstream the attestation gates (a vote, a withdrawal, a
  forum post, etc.)
- How the consumer stores attestations (their schema, their database)
- How the consumer surfaces success or failure to the end user
- What additional verification the consumer layers on top (KBA, OTP,
  hardware token, etc.)

That separation of concerns is intentional — the goal is to be the
clean reusable identity-document-verification piece that consumers
compose into whatever broader trust pipeline they need.

## Status

- **Phase 0** ✅ workspace scaffold + ICAO 9303 MRZ parser
- **Phase 1a** ✅ AAMVA Card Design Standard decoder
- **Phase 1b** ✅ PDF417 binary decoder (rxing wrapper)
- **Phase 2** ✅ axum HTTP server + `/health`, `/info`, `/capture`
- **Phase 3** ✅ OCR adapter (trait + Mock; Tesseract CLI feature-gated)
- **Phase 4** ✅ tamper detection (Error-Level Analysis)
- **Phase 5** ✅ face match + liveness (trait + Mock)
- **Phase 6** ✅ end-to-end integration test (all 5 stages, one POST)
- **Phase 7** ✅ NixOS module + systemd unit + Caddy snippet (`infra/`)

**63/63 tests across 8 crates.** Substrate is functionally complete:
- HTTP API serves real `/capture` requests end-to-end
- All 5 pipeline stages wired with adapter traits + Mock impls
- One feature-gated real engine (`tesseract-cli`) + reserved feature
  names for future engines (`insightface-onnx`, `dlib-rs`)
- Deployment-ready via NixOS module, systemd unit, or Caddy reverse-
  proxy snippet (see `infra/README.md`)

## License

Dual-licensed under Apache-2.0 OR MIT. Pick whichever fits your
downstream consumption.
