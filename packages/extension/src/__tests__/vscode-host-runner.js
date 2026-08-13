// Shared driver for the VS Code / Cursor Extension Host E2E suite, used by BOTH the
// host-local path (e2e.test.ts, against an installed editor) and the containerized
// Layer-2 path (e2e/agents/vscode/run-host-suite.cjs, against the pinned VS Code under
// Xvfb). One source of truth for the staged-manifest shape + the runTests() invocation,
// so the two paths can't drift.
//
// CommonJS (not the .ts test) so the container can require() it directly with
// NODE_PATH=/opt/vscode-test/node_modules resolving @vscode/test-electron. See the
// sibling .d.ts for the host-side TypeScript types.
const { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { runTests } = require("@vscode/test-electron");

// Per-host wiring constants for the VS Code Extension Host suite, shared between the host
// vitest (HOST_METADATA.vscode) and the container entry (run-host-suite.cjs) so the two
// can't disagree on the hook path/mode/marker.
const VSCODE_HOST = {
	extensionId: "Gen.sage-vscode",
	managedMarker: "--managed-by sage-vscode",
	hookMode: "vscode",
	hooksRelativePath: ".copilot/hooks/hooks.json",
};

function asObject(value) {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return {};
	}
	return value;
}

function buildVsCodeManifest(baseManifest) {
	const baseContributes = asObject(baseManifest.contributes);
	return {
		...baseManifest,
		name: "sage-vscode",
		displayName: "Sage for VS Code",
		description: "Safety for Agents — ADR layer for VS Code Claude hooks",
		main: "./dist/vscode_extension.js",
		files: [
			"dist/vscode_extension.js",
			"dist/vscode_extension.js.map",
			"dist/sage-hook.cjs",
			"dist/sage-hook.cjs.map",
			"resources/**",
			"package.json",
			"README.md",
			"LICENSE",
		],
		contributes: {
			...baseContributes,
			configuration: {
				title: "Sage",
				properties: {
					"sage.hookRunnerPath": {
						type: "string",
						scope: "application",
						default: "",
						description: "Optional absolute path to a sage-hook runner script.",
					},
				},
			},
		},
	};
}

// VS Code's package.json declares main = cursor_extension.js; the VS Code Extension Host
// needs vscode_extension.js. Stage a copy of the built extension with a patched manifest.
function createVsCodeExtensionDevelopmentPath(extensionRoot) {
	const stageDir = mkdtempSync(path.join(tmpdir(), "sage-vscode-e2e-"));
	const baseManifest = JSON.parse(readFileSync(path.join(extensionRoot, "package.json"), "utf8"));
	cpSync(path.join(extensionRoot, "dist"), path.join(stageDir, "dist"), {
		recursive: true,
		force: true,
	});
	cpSync(path.join(extensionRoot, "resources"), path.join(stageDir, "resources"), {
		recursive: true,
		force: true,
	});
	cpSync(path.join(extensionRoot, "README.md"), path.join(stageDir, "README.md"), { force: true });
	cpSync(path.join(extensionRoot, "LICENSE"), path.join(stageDir, "LICENSE"), { force: true });
	writeFileSync(
		path.join(stageDir, "package.json"),
		`${JSON.stringify(buildVsCodeManifest(baseManifest), null, 2)}\n`,
		"utf8",
	);
	return stageDir;
}

// Launch the editor once and run the Extension Host suite (extensionTestsPath), which
// writes per-case outcomes to opts.resultsFile. Returns the run error as a string (or
// undefined); per-case assertions are the caller's job (it reads resultsFile).
async function runExtensionHostSuite(opts) {
	const {
		host,
		vscodeExecutablePath,
		extensionRoot,
		extensionTestsPath,
		hookRunnerPath,
		workspaceFolder,
		resultsFile,
		home,
		extensionId,
		managedMarker,
		hookMode,
		hooksRelativePath,
		verbose = false,
		extraLaunchArgs = [],
	} = opts;

	let extensionDevelopmentPath = extensionRoot;
	let stagedPath;
	let runError;
	try {
		if (host === "vscode") {
			stagedPath = createVsCodeExtensionDevelopmentPath(extensionRoot);
			extensionDevelopmentPath = stagedPath;
		}

		const launchArgs = [
			workspaceFolder,
			"--disable-extensions",
			"--disable-workspace-trust",
			"--skip-welcome",
			"--skip-release-notes",
			...extraLaunchArgs,
		];
		if (!verbose) {
			launchArgs.push("--log", "off");
		}

		try {
			await runTests({
				vscodeExecutablePath,
				extensionDevelopmentPath,
				extensionTestsPath,
				launchArgs,
				extensionTestsEnv: {
					SAGE_E2E_HOST: host,
					SAGE_E2E_EXTENSION_ID: extensionId,
					SAGE_E2E_MANAGED_MARKER: managedMarker,
					SAGE_E2E_HOOK_MODE: hookMode,
					SAGE_E2E_HOOKS_RELATIVE_PATH: hooksRelativePath,
					SAGE_E2E_HOOK_RUNNER_PATH: hookRunnerPath,
					SAGE_E2E_RESULTS_FILE: resultsFile,
					SAGE_E2E_VERBOSE: verbose ? "1" : "0",
					HOME: home,
					USERPROFILE: home,
					XDG_CONFIG_HOME: path.join(home, ".config"),
					VSCODE_LOG_LEVEL: verbose ? "info" : "error",
				},
			});
		} catch (error) {
			runError = error;
		}
	} finally {
		if (stagedPath) {
			rmSync(stagedPath, { recursive: true, force: true });
		}
	}

	return { runError: runError ? (runError.stack ?? String(runError)) : undefined };
}

module.exports = {
	runExtensionHostSuite,
	VSCODE_HOST,
};
