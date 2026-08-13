# OpenClaw gateway agent image for Sage E2E.
#
# Unlike the CLI agents, OpenClaw ships as a Docker image, so this is FROM the official
# OpenClaw image (OPENCLAW_IMAGE from e2e/.env keeps the registry host out of version
# control), pinned via OPENCLAW_VERSION from
# e2e/agents.json. Updates are proposed via PR, never auto-applied.
#
# OpenClaw is a long-lived gateway (not a one-shot CLI): the entrypoint configures
# the gateway and runs it in the foreground. The host-built Sage connector is NOT
# baked in or installed — compose bind-mounts it read-only into the gateway's
# auto-discovery dir (see compose.yml), so the container always runs current-branch
# Sage. The host vitest suite brings the service up (`compose up -d`), polls /health,
# drives it over the published HTTP port, and tears it down.
ARG OPENCLAW_IMAGE
ARG OPENCLAW_VERSION
FROM ${OPENCLAW_IMAGE}:${OPENCLAW_VERSION}

# Build as root so the entrypoint lands on PATH; the runtime user is set by compose.
USER root

COPY agents/openclaw/entrypoint.sh /usr/local/bin/sage-openclaw-entrypoint.sh
RUN chmod +x /usr/local/bin/sage-openclaw-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/sage-openclaw-entrypoint.sh"]
