#!/usr/bin/env bash
#
# OpenClaw gateway bring-up for Sage E2E (Layer 2). Runs inside the pinned OpenClaw
# image; the host vitest suite starts this via `docker compose up -d openclaw`, polls
# GET /health, drives the gateway over the published HTTP port, then tears it down.
#
# The Sage connector is NOT installed or copied: compose bind-mounts the host-built
# plugin read-only into the gateway's auto-discovery dir
# ($OPENCLAW_STATE_DIR/extensions/sage), exactly like a local compose override would.
# OpenClaw loads it on startup. This entrypoint only
# configures the gateway and launches it.
set -eux

# Enable the OpenAI-compatible endpoint + full tool profile, set an auth token
# (required for a non-loopback bind), and pin the model. `models set` selects the
# google-vertex Gemini model; Vertex ADC is provided via the environment.
openclaw config set gateway.http.endpoints.chatCompletions.enabled true
openclaw config set tools.profile full
openclaw config set gateway.auth.token "${OPENCLAW_GATEWAY_TOKEN:?token required}"
# Bind beyond loopback so the published Docker port reaches the gateway. A non-
# loopback bind also guards the Control UI on the Host header; this is a throwaway
# localhost test gateway, so allow the Host-header origin fallback.
openclaw config set gateway.bind lan
openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true
openclaw models set "${OPENCLAW_E2E_MODEL:?model required}"

# OpenClaw's auth gate (2026.7.x) won't use Vertex ADC until a provider auth profile
# is registered — metadata-server ADC is intentionally NOT auto-detected (see the
# image's extensions/google/vertex-adc.ts: "Metadata-server ADC is intentionally not
# detected here"). So register the keyless Vertex ADC *marker* profile: the value
# below is OpenClaw's public sentinel GCP_VERTEX_CREDENTIALS_MARKER, NOT a secret.
# With the profile present the gate passes and the transport resolves credentials via
# google-auth-library at request time — the GCE metadata server on CI, or the ADC file
# mounted locally (SAGE_E2E_GCP_ADC). `paste-api-key` is OpenClaw's documented
# non-interactive auth path (`models auth login` is TTY-only). Only meaningful for the
# google-vertex provider; a non-vertex OPENCLAW_E2E_MODEL override would supply its own.
case "${OPENCLAW_E2E_MODEL%%/*}" in
  google-vertex)
    printf 'gcp-vertex-credentials\n' | openclaw models auth paste-api-key --provider google-vertex
    ;;
esac

# Foreground so the container stays up for the host suite to drive.
exec openclaw gateway --allow-unconfigured
