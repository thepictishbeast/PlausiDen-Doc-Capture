# sacredvote-doc-capture

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
<!-- repo-class: identity-verification-sidecar -->
<!-- repo-consumes: PlausiDen-Obs, PlausiDen-AVP-Doctrine -->
<!-- repo-consumed-by: Sacred.Vote -->
<!-- repo-tier: tbd -->
<!-- repo-status: experimental -->
<!-- repo-avp-subject: yes -->
<!-- repo-reference-impl-language: rust -->
<!-- repo-target-stack-scope: linux-x86_64 -->

Rust sidecar that performs document-capture identity verification for
[Sacred.Vote](https://github.com/thepictishbeast/Sacred.Vote). Voter
takes a photo of their government-issued ID and a selfie; the sidecar
runs OCR, MRZ checksum verification, PDF417 barcode parsing,
tamper detection, and face matching, then returns a cryptographic
attestation of "this voter holds this document."

**Privacy posture, load-bearing:** captured images live in process
memory only. They are NEVER written to disk and NEVER returned to the
caller. The attestation contains hashed claims (name, DOB, document
ID truncated) — never the raw image, never raw PII.

## Why this exists

Sacred.Vote's primary identity verification path is the zkTLS state
voter-search lookup (`votesearch.utah.gov` and equivalents). That
works when the voter is already in a state voter file. It does NOT
work for voters who are:

- Not registered yet (using Sacred.Vote to verify eligibility before
  registration)
- In states whose voter file isn't publicly queryable
- In states where the API shape isn't yet wrapped by a notary template

Mobile Driver's License (mDL) was the planned alternative but Utah's
mDL implementation (GET Mobile ID) does not support remote
verification. The OID4VP cross-device flow requires same-device or QR
proximity, neither of which work for an at-home voter on a phone.

Document capture fills that gap. Voter photographs their ID; the
result is comparable cryptographic strength to mDL for a "this voter
holds this document" claim, with the trade-off that the document is
photographed rather than wallet-attested.

## Pipeline stages

1. **OCR** — extract text fields (name, DOB, address, ID number,
   expiration) from the front of the document via Tesseract.
2. **MRZ** — for documents with a Machine Readable Zone (passports,
   newer state IDs), parse the MRZ lines and verify the per-field
   checksums. MRZ check-digit verification is the single strongest
   tamper-resistance signal because the checksums are computed at
   issuance and any modification of name/DOB/document-number breaks
   them.
3. **PDF417** — for US driver licenses, parse the back-of-card
   PDF417 barcode per the AAMVA standard. Cross-check the parsed
   AAMVA fields against the front-of-card OCR.
4. **Tamper detection** — Error-Level Analysis (ELA) on the captured
   image flags regions with anomalous JPEG compression artifacts,
   which correlate with digital tampering of a captured image.
5. **Face match** — compare the voter's selfie against the document
   portrait via face-embedding distance. Threshold is configurable;
   default is 0.5 cosine distance.
6. **Liveness** — challenge-response (blink, head turn) during
   capture; passive liveness deferred for MVP.

Each stage emits structured signals into the final attestation. A
verification is `verified: true` only when all required stages pass.

## API surface

```
POST /capture        multipart: front (image), back (image, optional),
                                 selfie (image), template_id (string)
                     → 200 { session_id, claims, attestation, ...signals }
                     → 422 { error: "voter_not_found: ...", ... }
                     → 502 { error: "ocr_unavailable: ..." }

GET  /health         → 200 "ok"
GET  /info           → 200 { public_key, name, templates, ... }
GET  /session/{id}   → 200 NotarySession  (proof retrievability for audit)
```

The shape mirrors `sacredvote-zktls-notary` so Sacred.Vote can talk to
both sidecars through a uniform `/identity/*` route surface.

## Status

- **Phase 0 (today, this commit):** workspace scaffold, MRZ parser
  + checksum verification with property-tests, README + AGENTS.md
- **Phase 1:** PDF417 + AAMVA parser
- **Phase 2:** server skeleton + `/health`, `/info`, `/capture` stubs
- **Phase 3:** Tesseract integration (feature-gated)
- **Phase 4:** tamper detection (ELA)
- **Phase 5:** face-match stub → real model
- **Phase 6:** Sacred.Vote integration (Express + axum-poc routes)

## License

MIT OR Apache-2.0.
