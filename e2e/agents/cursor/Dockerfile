# Cursor `agent` CLI image for Sage E2E.
#
# FROM the shared base (built first by e2e/run.sh). The cursor-agent CLI version is
# pinned via the CURSOR_VERSION build arg, sourced from e2e/agents.json. Updates are
# proposed via PR, never auto-applied.
FROM sage-e2e-base:latest

# A hardened base image may default to a non-root user; writing the CLI under
# /usr/local needs root. The runtime cwd/HOME (/work) is a bind-mounted host dir
# (see compose.yml), so running as root at runtime is harmless for this sandbox.
USER root

# The Cursor CLI is NOT an npm package. Its generic installer
# (`curl https://cursor.com/install | bash`) is regenerated per release and is
# latest-only — it cannot pin a version. So we fetch the versioned tarball the
# installer downloads internally (curl | tar — no remote script execution), pinned to
# CURSOR_VERSION, giving a reproducible image. URL scheme:
#   https://downloads.cursor.com/lab/<version>/<os>/<arch>/agent-cli-package.tar.gz
# The binary lives OUTSIDE /work (which is a runtime bind mount that would shadow it);
# the host suite resolves it via SAGE_AGENT_PATH (see compose.yml).
ARG CURSOR_VERSION
RUN test -n "$CURSOR_VERSION" \
 && arch="$(uname -m)" \
 && case "$arch" in \
      x86_64 | amd64) arch="x64" ;; \
      arm64 | aarch64) arch="arm64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac \
 && mkdir -p /opt/cursor-agent \
 && curl -fSL "https://downloads.cursor.com/lab/${CURSOR_VERSION}/linux/${arch}/agent-cli-package.tar.gz" \
    | tar --strip-components=1 -xzf - -C /opt/cursor-agent \
 && ln -s /opt/cursor-agent/cursor-agent /usr/local/bin/cursor-agent \
 && cursor-agent --version

# Sage is bind-mounted at /sage (read-only) at runtime. Cursor loads Sage via a
# project-level .cursor/hooks.json the host suite writes into the bind-mounted /work,
# pointing at /sage/packages/extension/dist/sage-hook.cjs (cursor mode). The host
# passes the cursor-agent flags straight through this entrypoint.
ENTRYPOINT ["cursor-agent"]
