# OpenCode CLI agent image for Sage E2E.
#
# FROM the shared base (built first by e2e/run.sh). The opencode CLI version is
# pinned via the OPENCODE_VERSION build arg, sourced from e2e/agents.json. Updates
# are proposed via PR, never auto-applied.
FROM sage-e2e-base:latest

# A hardened base image may default to a non-root user; global npm install needs root
# to write under /usr/local. The runtime cwd/HOME (/work) is a bind-mounted host dir
# (see compose.yml), so running as root at runtime is harmless for this sandbox.
USER root

# The `opencode-ai` npm package ships a thin launcher that downloads a
# platform-native binary into HOME on first run (like the copilot CLI). Pre-warm it
# at build time with `opencode --version` so the runtime start is fast. HOME is a
# host bind mount at runtime (exec-able, unlike a `noexec` tmpfs) — see compose.yml.
# NPM_REGISTRY routes the build through an npm proxy, for networks where
# registry.npmjs.org isn't reachable directly. Empty (the default, e.g. local dev)
# leaves npm on its default public registry.
ARG NPM_REGISTRY
ARG OPENCODE_VERSION
RUN if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi \
 && test -n "$OPENCODE_VERSION" \
 && npm install -g "opencode-ai@${OPENCODE_VERSION}" \
 && opencode --version

# Sage is bind-mounted at /sage (read-only) at runtime. OpenCode loads Sage as an
# in-process plugin via ~/.config/opencode/opencode.json `{ plugin: ["/sage/packages/opencode"] }`
# (the host vitest suite writes that config into the bind-mounted HOME before driving
# opencode). The host passes the opencode flags straight through this entrypoint.
ENTRYPOINT ["opencode"]
