# GitHub Copilot CLI agent image for Sage E2E.
#
# FROM the shared base (built first by e2e/run.sh). The copilot CLI version is
# pinned via the COPILOT_VERSION build arg, sourced from e2e/agents.json. Updates
# are proposed via PR, never auto-applied.
FROM sage-e2e-base:latest

# A hardened base image may default to a non-root user; global npm install needs
# root to write under /usr/local. The runtime cwd/HOME (/work) is a world-writable
# tmpfs, so running as root at runtime is harmless for this ephemeral sandbox.
USER root

# NPM_REGISTRY routes the build through an npm proxy, for networks where
# registry.npmjs.org isn't reachable directly. Empty (the default, e.g. local dev)
# leaves npm on its default public registry.
ARG NPM_REGISTRY
ARG COPILOT_VERSION
RUN if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi \
 && test -n "$COPILOT_VERSION" \
 && npm install -g "@github/copilot@${COPILOT_VERSION}" \
 && copilot --version

# Sage is bind-mounted at /sage (read-only) at runtime — see compose.yml. Copilot
# loads Sage as a hook via a generated --plugin-dir whose hooks.json points at
# /sage/packages/extension/dist/sage-hook.cjs. The host vitest suite passes the
# copilot flags straight through this entrypoint.
ENTRYPOINT ["copilot"]
