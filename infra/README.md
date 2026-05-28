# Deployment

PlausiDen-Doc-Capture ships as a single Rust binary (`doc-capture-server`)
that runs as a sidecar on the consumer's host. This directory
contains three deployment paths, all functionally equivalent:

| Path | When to use |
|------|-------------|
| `nixos/module.nix` | NixOS hosts. Declarative configuration via the host's `configuration.nix`. |
| `systemd/doc-capture-server.service` | Debian / Ubuntu / RHEL / any host with systemd. Manual install. |
| `caddy/Caddyfile.snippet` | Both paths above benefit from this when fronting the sidecar with TLS-terminating Caddy. |

## Build the binary

From the workspace root:

```sh
cargo build --release -p doc-capture-server
```

Output lands at `target/release/doc-capture-server`. With the
default-feature build the binary embeds the Mock OCR + Mock face
engines (suitable for development and "OCR disabled" deployments).
For production with real Tesseract OCR:

```sh
cargo build --release -p doc-capture-server -p doc-capture-ocr \
    --features doc-capture-ocr/tesseract-cli
```

…and ensure `tesseract` is on the deployed host's PATH. Real face-
match engines (InsightFace / dlib) are reserved feature names; the
implementations land in a follow-up phase.

## Path 1 — NixOS

```nix
# /etc/nixos/configuration.nix
{ config, pkgs, ... }: {
  imports = [ /path/to/PlausiDen-Doc-Capture/infra/nixos/module.nix ];

  services.doc-capture-server = {
    enable = true;
    listenAddr = "127.0.0.1:7444";
    maxImageBytes = 8388608;       # 8 MiB
    logLevel = "info";
    package = pkgs.callPackage ./doc-capture-server.nix { };
    # or: pkgs.runCommand "doc-capture-server" { } ''
    #   mkdir -p $out/bin
    #   cp ${./bin/doc-capture-server} $out/bin/
    #   chmod +x $out/bin/doc-capture-server
    # '';
  };
}
```

Then `sudo nixos-rebuild switch`. The module creates the
`doc-capture` user/group, sets up the systemd unit with sandboxing
directives, and wires environment-driven configuration.

## Path 2 — systemd on a non-Nix host

```sh
# Build + install the binary
cargo build --release -p doc-capture-server
sudo install -m 755 target/release/doc-capture-server /usr/local/bin/

# Create the dedicated user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin doc-capture

# Install the unit
sudo cp infra/systemd/doc-capture-server.service \
    /etc/systemd/system/doc-capture-server.service

# Reload + start
sudo systemctl daemon-reload
sudo systemctl enable --now doc-capture-server

# Verify
curl -fsS http://127.0.0.1:7444/health
sudo systemctl status doc-capture-server
sudo journalctl -u doc-capture-server -f
```

## Path 3 — Caddy reverse-proxy fronting

Both paths above bind the sidecar to `127.0.0.1` by default. To
expose the sidecar through a TLS-terminating Caddy:

```sh
sudo cp infra/caddy/Caddyfile.snippet /etc/caddy/snippets/doc-capture.caddy
# Edit /etc/caddy/Caddyfile to add:
#   import /etc/caddy/snippets/doc-capture.caddy
# Replace {EXTERNAL_HOST} and {INTERNAL_PORT} placeholders.
sudo systemctl reload caddy
```

The snippet:
- Caps multipart body at 32 MiB at the Caddy layer (defense in
  depth on top of the sidecar's per-image 8 MiB cap).
- Forwards client IP via `X-Real-IP` + `X-Forwarded-For`.
- Active health-checks the upstream every 30s with a 2s timeout
  via `/health`.
- Strips a `/doc-capture/*` prefix so the sidecar's bare routes
  (`/health`, `/info`, `/capture`) sit under a namespaced URL.

## Smoke test after deploy

```sh
# Health
curl -fsS http://127.0.0.1:7444/health   # → "ok"

# Info
curl -fsS http://127.0.0.1:7444/info | jq

# Capture (empty multipart — expect verified=false with empty claims)
curl -fsS -X POST http://127.0.0.1:7444/capture \
    -F template_id=smoke-test | jq

# Real capture with synthetic inputs (see
# doc-capture-server/tests/server_integration.rs for the full
# multipart shape including PDF417-encoded AAMVA payloads).
```

## Production checklist

- Binary built with `--release` and stripped (`strip
  target/release/doc-capture-server`)
- Tesseract installed on the host if OCR is enabled
- Caddy in front for TLS termination if exposing externally
- Log shipper consuming `journalctl -u doc-capture-server` (JSON
  output is parser-friendly)
- Resource limits sane for the host (MemoryMax=1G is the unit's
  default; tune if processing larger or higher-volume images)
- Backups: there is NOTHING to back up — the sidecar holds no
  persistent state. Captured images are processed in memory and
  dropped; attestations are returned to the caller, not stored
  here.
