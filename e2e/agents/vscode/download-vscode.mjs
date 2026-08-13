// Build-time pre-download of the pinned VS Code (Electron) build so the runtime
// container needs no network for the editor itself. Mirrors the cursor image's
// "fetch the pinned artifact at build" approach, but VS Code is fetched through
// @vscode/test-electron's downloader (the same one the host E2E suite uses), so the
// in-container runTests() resolves the identical build.
//
// Writes the resolved executable path to vscode-exe.txt; the container runner
// (run-host-suite.cjs) reads it to launch this exact build via runTests().
import { writeFileSync } from "node:fs";
import { downloadAndUnzipVSCode } from "@vscode/test-electron";

const version = process.env.VSCODE_VERSION || "stable";
const exe = await downloadAndUnzipVSCode(version);
writeFileSync("/opt/vscode-test/vscode-exe.txt", `${exe}\n`, "utf8");
// Build-time diagnostic via stdout.write (not console.log — repo lint reserves that for
// __tests__/) so the resolved build shows in the image build log.
process.stdout.write(`Downloaded VS Code (${version}): ${exe}\n`);
