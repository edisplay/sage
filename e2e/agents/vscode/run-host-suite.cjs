// Container entry for the VS Code Layer-2 (wiring-only) suite. The compose `vscode`
// service runs this under the Xvfb entrypoint; it drives the bind-mounted, current-branch
// Sage extension inside the pinned VS Code Extension Host and writes per-case outcomes to
// the bind-mounted /work so the host vitest reads them back and asserts.
//
// Resolution: NODE_PATH=/opt/vscode-test/node_modules lets the shared runner require
// @vscode/test-electron; the shared module + Sage both live under the read-only /sage bind.
const fs = require("node:fs");

const { runExtensionHostSuite, VSCODE_HOST } = require(
  "/sage/packages/extension/src/__tests__/vscode-host-runner.js",
);

(async () => {
  // HOME lives on the container's LOCAL fs, not the /work bind mount: enableProtection
  // writes ~/.copilot/hooks/hooks.json and the suite reads it back synchronously — over a
  // Docker Desktop bind mount that write-then-read races (the read can catch a 0-byte file
  // mid-flush). Only the results file needs the bind mount (the host reads it after exit).
  const home = "/tmp/sage-vscode-home";
  const resultsFile = "/work/vscode-results.json";
  const workspaceFolder = "/tmp/sage-vscode-workspace";
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(workspaceFolder, { recursive: true });
  // resultsFile is on the persistent /work bind mount, so clear any prior run's copy.
  // (home is a fresh dir in a --rm container, so no stale hooks.json can exist there.)
  fs.rmSync(resultsFile, { force: true });

  const exe = fs.readFileSync("/opt/vscode-test/vscode-exe.txt", "utf8").trim();

  const { runError } = await runExtensionHostSuite({
    host: "vscode",
    vscodeExecutablePath: exe,
    extensionRoot: "/sage/packages/extension",
    extensionTestsPath: "/sage/packages/extension/src/__tests__/e2e-suite/index.js",
    hookRunnerPath: "/sage/packages/extension/dist/sage-hook.cjs",
    workspaceFolder,
    resultsFile,
    home,
    extensionId: VSCODE_HOST.extensionId,
    managedMarker: VSCODE_HOST.managedMarker,
    hookMode: VSCODE_HOST.hookMode,
    hooksRelativePath: VSCODE_HOST.hooksRelativePath,
    verbose: process.env.SAGE_E2E_VERBOSE === "1",
    // Electron as root in a container needs --no-sandbox; --password-store=basic avoids a
    // missing OS keyring (no real auth/secret storage is exercised in the wiring suite).
    extraLaunchArgs: ["--no-sandbox", "--password-store=basic"],
  });

  if (runError) {
    console.error(`[vscode-e2e] runTests reported: ${runError}`);
  }
  // Exit 0 regardless — the host vitest reads resultsFile and asserts per case.
})();
