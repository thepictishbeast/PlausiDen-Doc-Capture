# PlausiDen-Doc-Capture NixOS module.
#
# Declares a systemd-managed instance of the doc-capture-server
# binary, with environment-driven configuration mirroring what the
# binary reads at boot (see doc-capture-server/src/main.rs).
#
# Usage from a host configuration:
#
#   { config, pkgs, ... }: {
#     imports = [ ./module.nix ];
#     services.doc-capture-server = {
#       enable = true;
#       listenAddr = "127.0.0.1:7444";
#       maxImageBytes = 8388608; # 8 MiB
#       logLevel = "info";
#       package = pkgs.doc-capture-server;  # bring your own build
#     };
#   }
#
# The binary itself is NOT built by this module — operators
# either pull it from their own nixpkgs overlay, build it from
# source via the workspace `cargo build --release -p
# doc-capture-server`, or ship a static binary into
# /usr/local/bin/. Pointing `package` at the resulting derivation
# (or `pkgs.runCommand` wrapping a fetched binary) wires it up.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.doc-capture-server;
in
{
  options.services.doc-capture-server = {
    enable = lib.mkEnableOption "PlausiDen document-capture identity-verification sidecar";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Package that provides the `doc-capture-server` binary under
        `$out/bin/`. Typically built from the workspace via
        `cargo build --release -p doc-capture-server`. Operators
        without a Nix-native build can wrap a fetched binary via
        `pkgs.runCommand` or set this to `null` and override
        ExecStart in `systemd.services.doc-capture-server`.
      '';
    };

    listenAddr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:7444";
      description = ''
        Bind address. The default 127.0.0.1 keeps the sidecar
        reachable only from loopback; expose via the Caddy
        reverse-proxy snippet rather than binding directly to
        0.0.0.0.
      '';
    };

    maxImageBytes = lib.mkOption {
      type = lib.types.int;
      default = 8 * 1024 * 1024;
      description = ''
        Per-image upload size cap in bytes. Default 8 MiB. Phone
        cameras commonly produce 3-6 MiB JPEGs at full resolution;
        8 MiB gives slack without inviting abusive uploads.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      description = ''
        Tracing-subscriber env-filter. Values: `error`, `warn`,
        `info`, `debug`, `trace`. Production deployments stay at
        `info`. The default subscriber emits JSON lines suitable
        for structured-log shippers (Loki / Vector / Elastic).
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "doc-capture";
      description = "Dedicated user the daemon runs as.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "doc-capture";
      description = "Dedicated group the daemon runs as.";
    };

    extraEnvironment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Extra Environment= entries to forward into the systemd
        unit. Useful for engine-specific knobs (e.g. setting
        `DOC_CAPTURE_OCR=tesseract-cli` once the OCR adapter is
        runtime-configurable) without re-importing the whole
        module.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "PlausiDen document-capture sidecar daemon";
    };
    users.groups.${cfg.group} = { };

    systemd.services.doc-capture-server = {
      description = "PlausiDen document-capture identity-verification sidecar";
      documentation = [ "https://github.com/thepictishbeast/PlausiDen-Doc-Capture" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        DOC_CAPTURE_LISTEN_ADDR = cfg.listenAddr;
        DOC_CAPTURE_MAX_IMAGE_BYTES = toString cfg.maxImageBytes;
        DOC_CAPTURE_LOG_LEVEL = cfg.logLevel;
      } // cfg.extraEnvironment;

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/doc-capture-server";
        Restart = "on-failure";
        RestartSec = "5s";

        User = cfg.user;
        Group = cfg.group;

        # ── Sandboxing ────────────────────────────────────────
        # The daemon needs to bind to a loopback port, read its
        # own binary, write tempfiles (when OCR is enabled), and
        # talk to other localhost sidecars. Everything else is
        # locked down per systemd hardening defaults.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged @resources"
        ];

        # The daemon binds to a TCP port. Capability granted at
        # the systemd level so the dedicated user account doesn't
        # need raw CAP_NET_BIND privileges in /etc.
        CapabilityBoundingSet = [ ];
        AmbientCapabilities = [ ];

        # Resource limits — keep one stuck request from consuming
        # the whole host. The 8MiB image cap caps individual
        # uploads; this sets a process-wide ceiling.
        LimitNOFILE = 4096;
        MemoryMax = "1G";
        TasksMax = 256;
      };
    };
  };
}
