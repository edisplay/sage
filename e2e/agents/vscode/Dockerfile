# VS Code (Extension Host under Xvfb) image for Sage E2E — Layer 2 (wiring-only).
#
# Runs the Sage extension inside a real VS Code Electron Extension Host under a virtual
# display, to verify the wiring a contract test can't: the extension activates, its
# enableProtection command writes a real ~/.copilot/hooks/hooks.json, and the managed
# hook denies the canary tool matrix. Sage is bind-mounted at /sage:ro (never baked).
#
# NOTE: this does NOT drive Copilot Chat with a model — authenticated Copilot Chat can't
# run headless in a container (it's the product.json defaultChatAgent, gated behind an
# interactive GitHub sign-in + a Copilot entitlement check, with no supported token-env
# path). Real-Chat tool-vocabulary/payload drift validation therefore lives in Layer 3
# (desktop, signed-in) — see e2e/README.md. So no Copilot extension is installed
# here; the image is just VS Code + Xvfb + @vscode/test-electron.
FROM sage-e2e-base:latest

# A hardened base image may default to a non-root user; apt + writing under /opt need
# root. The runtime sandbox is ephemeral (HOME bind mount + --rm), so root is fine here.
USER root

# Xvfb (headless X server) + the shared libraries a VS Code/Electron build needs to
# start without a real display.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      xvfb \
      xauth \
      ca-certificates \
      libnss3 libnspr4 libgbm1 libasound2 libgtk-3-0 libxkbcommon0 \
      libdrm2 libxshmfence1 libx11-xcb1 libxcomposite1 libxdamage1 \
      libxfixes3 libxrandr2 libxcb-dri3-0 libcups2 libatk1.0-0 \
      libatk-bridge2.0-0 libatspi2.0-0 libpango-1.0-0 libcairo2 libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/*

# @vscode/test-electron drives runTests() + downloadAndUnzipVSCode, installed OUTSIDE
# /work (a runtime bind mount that would shadow it).
# NPM_REGISTRY routes the install through an npm proxy, for networks where
# registry.npmjs.org isn't reachable directly. Empty (the default, e.g. local dev)
# leaves npm on its default public registry.
ARG NPM_REGISTRY
ARG VSCODE_TEST_ELECTRON_VERSION=2.5.2
WORKDIR /opt/vscode-test
RUN if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi \
 && npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "@vscode/test-electron@${VSCODE_TEST_ELECTRON_VERSION}"

# Provision the VS Code build the Extension Host runs against, writing its executable
# path to vscode-exe.txt (read by run-host-suite.cjs). Two paths:
#   - VSCODE_APT_MIRROR set (CI): the VS Code download CDN (update.code.visualstudio.com →
#     *.vo.msecnd.net / vscode.download.prss.microsoft.com) may not be reachable from a
#     restricted CI network, so `downloadAndUnzipVSCode()` ECONNRESETs. Install from an
#     apt mirror of packages.microsoft.com/repos/code instead (apt itself already
#     works here — see the xvfb install above). The registry host stays in .env, like
#     NPM_REGISTRY/BASE_IMAGE. NOTE: this path installs the mirror's current `code` build, so
#     the pinned VSCODE_VERSION is not honored — acceptable for this wiring-only layer.
#   - VSCODE_APT_MIRROR empty (local dev): download the pinned build via @vscode/test-electron
#     from the public CDN.
ARG VSCODE_APT_MIRROR
ARG VSCODE_VERSION=stable
ENV VSCODE_VERSION=${VSCODE_VERSION}
COPY agents/vscode/download-vscode.mjs /opt/vscode-test/download-vscode.mjs
RUN if [ -n "$VSCODE_APT_MIRROR" ]; then \
      echo "deb [arch=amd64 trusted=yes] ${VSCODE_APT_MIRROR} stable main" > /etc/apt/sources.list.d/vscode.list \
       && apt-get update \
       && apt-get install -y --no-install-recommends code \
       && rm -rf /var/lib/apt/lists/* \
       && test -x /usr/share/code/code \
       && printf '%s\n' /usr/share/code/code > /opt/vscode-test/vscode-exe.txt \
       && echo "VS Code installed via apt mirror (version not pinned)"; \
    else \
      node /opt/vscode-test/download-vscode.mjs \
       && echo "VS Code ${VSCODE_VERSION} downloaded via CDN"; \
    fi

COPY agents/vscode/entrypoint.sh /usr/local/bin/sage-vscode-entrypoint.sh
RUN chmod +x /usr/local/bin/sage-vscode-entrypoint.sh

WORKDIR /work

# Start a virtual display, then exec the supplied command (the host suite's node runner
# that calls @vscode/test-electron runTests()). A manual Xvfb start is used instead of
# xvfb-run, which hangs as a container PID 1.
ENTRYPOINT ["/usr/local/bin/sage-vscode-entrypoint.sh"]
