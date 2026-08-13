/**
 * Tier 3 E2E for the Cursor / VS Code extension. Two independent blocks:
 *
 * - Block A — "Sage extension in {Cursor,VS Code}" (the Extension Host suite). This is the
 *   **desktop GUI path (Layer 3)**: it runs the dev extension inside an installed
 *   Cursor/VS Code binary (keychain, executable discovery) and has no full container
 *   equivalent — Cursor's Extension Host can't run headless in Linux. It auto-skips where no
 *   GUI binary is installed. VS Code additionally has a **Layer 2 wiring-only** container path
 *   (runVsCodeContainerSuite) that runs the same Extension Host suite under Xvfb. Native mode
 *   does not apply here — this block already runs natively, unchanged.
 * - Block B — "Cursor headless agent + Sage hooks": Layer 2 coverage of the real Cursor
 *   `agent` CLI, container (SAGE_E2E_RUNNER=container, set by run.sh) or native
 *   (SAGE_E2E_RUNNER=native, drives an installed `cursor-agent` directly, isolated temp
 *   HOME, ambient CURSOR_API_KEY/session reuse) — detection + the tool-name map are proven
 *   deterministically at Layer 1; the drift-diff check stays container-only.
 *
 * Excluded from default `pnpm test`. Run with `pnpm test:e2e:cursor` / `:vscode` (Block A,
 * local desktop), `e2e/run.sh cursor` / `e2e/run.sh vscode` (containerized), or
 * `SAGE_E2E_RUNNER=native pnpm test:e2e:cursor` (Block B, native).
 */

import { execFile, spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import {
	assertNoEnvelopeDrift,
	CANARY_MARKERS,
	composeRun,
	createNativeHome,
	driveForFreshVerdict,
	ENVELOPE_VOLATILE_FIELDS,
	e2ePaths,
	IS_CONTAINER,
	IS_NATIVE,
	E2E_MODE as MODE,
	type NativeHome,
	readLastCaptureRecord,
	resolveAuditPath,
	resolveExecutable,
	resolveNativeAuditPath,
	spawnNative,
	CONTAINER_TOOL_ATTEMPTS as TOOL_ATTEMPTS,
	tolerantRm,
} from "@gendigital/sage-core/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { runExtensionHostSuite, VSCODE_HOST } from "./vscode-host-runner.js";

const execFileAsync = promisify(execFile);

type HostName = "cursor" | "vscode";
type CaseStatus = "pass" | "fail";

interface E2ECase {
	id: string;
	title: string;
}

interface HostMetadata {
	label: string;
	extensionId: string;
	managedMarker: string;
	hookMode: "cursor" | "vscode";
	hooksRelativePath: string;
}

interface HostResolution {
	executablePath?: string;
	reason?: string;
}

interface CaseOutcome {
	id: string;
	name: string;
	status: CaseStatus;
	error?: string;
	durationMs?: number;
}

interface HostRunSummary {
	orderedOutcomes: CaseOutcome[];
	caseOutcomes: Map<string, CaseOutcome>;
	runError?: string;
}

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const WORKSPACE_FOLDER = path.resolve(EXTENSION_ROOT, "test-workspace");
const EXTENSION_TESTS_PATH = path.resolve(__dirname, "e2e-suite", "index.js");
const HOOK_RUNNER_PATH = path.resolve(EXTENSION_ROOT, "dist", "sage-hook.cjs");
const HEADLESS_AGENT_MODEL = process.env.SAGE_HEADLESS_AGENT_MODEL?.trim() || "claude-4.5-sonnet";
const E2E_VERBOSE = resolveE2EVerbose();

const E2E_CASES: readonly E2ECase[] = [
	{ id: "extension-activates", title: "extension activates" },
	{ id: "commands-registered", title: "sage commands are registered" },
	{ id: "enable-protection-writes-hooks", title: "enable protection writes managed hooks" },
	{ id: "hook-health-command", title: "hook health command runs without error" },
	{ id: "dangerous-write-blocked", title: "managed hook blocks dangerous write" },
	{
		id: "tool-coverage-deny",
		title: "hook denies canary payloads across all tool names",
	},
	{
		id: "hook-response-shape-consistent",
		title: "hook responses have consistent shape across event types",
	},
	{ id: "disable-protection-removes-hooks", title: "disable protection removes managed hooks" },
];

const HOST_METADATA: Record<HostName, HostMetadata> = {
	cursor: {
		label: "Cursor",
		extensionId: "Gen.sage-cursor",
		managedMarker: "--managed-by sage-cursor",
		hookMode: "cursor",
		hooksRelativePath: ".cursor/hooks.json",
	},
	// Wiring constants shared with the container entry (e2e/agents/vscode/run-host-suite.cjs)
	// via VSCODE_HOST, so the test and the container can't disagree on the hook path/mode.
	vscode: {
		label: "VS Code",
		...VSCODE_HOST,
	},
};

const requestedHost = resolveRequestedHost();
const hostsToRun: HostName[] = requestedHost ? [requestedHost] : ["cursor", "vscode"];

// --- Container seam (Layer 2) ---
// The container is only the agent sandbox; the test logic (parsing, audit-log + drift
// assertions) stays here on the host. Block B drives the pinned cursor-agent image via
// docker compose against the bind-mounted current-branch Sage; the VS Code container path
// in Block A drives the pinned VS Code image.
const PLUGIN_ROOT = path.resolve(EXTENSION_ROOT, "..", ".."); // repo root
const {
	composeFile: COMPOSE_FILE,
	captureDir: CAPTURE_DIR,
	proposedDir: PROPOSED_DIR,
} = e2ePaths(PLUGIN_ROOT);
// In-container path to the bind-mounted hook runner (repo root → /sage) + the host view of
// the container's HOME (/work → e2e/output/cursor-home), so the host reads the SAME
// audit.jsonl the in-container hook wrote (full parity).
const CONTAINER_HOOK_RUNNER = "/sage/packages/extension/dist/sage-hook.cjs";
const CURSOR_HOME_HOST = path.resolve(PLUGIN_ROOT, "e2e", "output", "cursor-home");
// VS Code container HOME bind mount (compose: ./output/vscode-home → /work). The
// in-container suite writes vscode-results.json here; the host reads it back.
const VSCODE_HOME_HOST = path.resolve(PLUGIN_ROOT, "e2e", "output", "vscode-home");
// Reassigned in beforeAll for native mode (resolveNativeAuditPath against the isolated temp
// HOME) — resolveAuditPath's own non-container fallback is the developer's REAL ~/.sage,
// which native mode must never touch (isolation).
let AUDIT_PATH = resolveAuditPath(PLUGIN_ROOT, "cursor-home", ".sage", "audit.jsonl");
// Cursor is NOT MCP-based: the sage-hook CJS hook (cursor mode) captures each raw +
// normalized payload to CAPTURE_DIR, namespaced cursor-*. The drift test reads the
// RAW wire payload back and diffs it against the committed Layer 1 fixture.
const CURSOR_CAPTURE_FILE = path.join(CAPTURE_DIR, "cursor-pre-tool-use.jsonl");
const CURSOR_FIXTURE_PATH = path.resolve(
	__dirname,
	"fixtures",
	"contract",
	"cursor-pre-tool-use.json",
);
// Block B (cursor headless agent) belongs to the cursor target, so it also requires that
// vscode wasn't the requested host — otherwise `test:e2e:vscode` (container or native)
// would wrongly drive the cursor binary too.
const HAS_CURSOR_AGENT = IS_CONTAINER && requestedHost !== "vscode";
const NATIVE_CURSOR_BIN =
	IS_NATIVE && requestedHost !== "vscode"
		? resolveExecutable(["SAGE_CURSOR_AGENT_PATH", "SAGE_AGENT_PATH"], ["cursor-agent"])
		: { reason: "not native mode, or vscode-only run selected" };
const CAN_RUN_CURSOR_NATIVE =
	IS_NATIVE && requestedHost !== "vscode" && Boolean(NATIVE_CURSOR_BIN.executablePath);
if (IS_NATIVE && requestedHost !== "vscode" && !CAN_RUN_CURSOR_NATIVE) {
	console.warn(`Cursor headless E2E (native) skipped: ${NATIVE_CURSOR_BIN.reason}`);
}
// Set by beforeAll in native mode: an isolated temp HOME, never the developer's real one.
let cursorNativeHome: NativeHome | undefined;
const CONTAINER_FILE_TARGET = `/work/${CANARY_MARKERS.fileDeny}.txt`;

// Block A — Extension Host suite. Desktop GUI path (Layer 3) for both editors,
// plus a Layer 2 wiring-only container path for VS Code (runVsCodeContainerSuite). Cursor
// has no container Extension Host, so its cases run only against an installed local binary
// and skip otherwise. See the file header.
for (const host of hostsToRun) {
	const metadata = HOST_METADATA[host];
	const resolved = resolveHostExecutable(host);
	// In container mode the editor lives in the pinned image (no local binary to find),
	// so the VS Code host always runs; otherwise it needs a resolved local executable.
	const isContainerVsCode = host === "vscode" && IS_CONTAINER;
	// The desktop Extension Host (Layer 3) drives a locally-installed editor binary and must
	// NOT run during a `run.sh <agent>` container run (IS_CONTAINER) — otherwise a Layer 2
	// cursor run would launch the developer's installed Cursor app. Cursor has no container
	// Extension Host, so in container mode it skips Block A entirely (Block B covers it).
	const isDesktopHost = !IS_CONTAINER && Boolean(resolved.executablePath);
	const canRun = isContainerVsCode || isDesktopHost;

	if (!canRun) {
		// In a container run only a host without a container path reaches here (VS Code takes the
		// isContainerVsCode path), so the cause is the layer, not a missing binary — host-agnostic.
		const reason = IS_CONTAINER
			? "desktop Extension Host (Layer 3) does not run in container mode"
			: resolved.reason;
		console.warn(`${metadata.label} E2E skipped: ${reason}`);
	}
	const describeHost = canRun ? describe : describe.skip;

	describeHost(`E2E: Sage extension in ${metadata.label}`, { timeout: 600_000 }, () => {
		let hostRunPromise: Promise<HostRunSummary> | undefined;

		beforeAll(() => {
			if (!canRun) {
				return;
			}
			// Container VS Code runs the whole suite in the image (no local binary);
			// every other case runs the Extension Host against a resolved local editor.
			if (isContainerVsCode) {
				hostRunPromise = runVsCodeContainerSuite();
			} else if (isDesktopHost && resolved.executablePath) {
				hostRunPromise = runHostE2E(host, resolved.executablePath);
			}
		});

		for (const testCase of E2E_CASES) {
			it(testCase.title, async () => {
				if (!hostRunPromise) {
					return;
				}

				const summary = await hostRunPromise;
				if (summary.runError && !hasFailedOutcomes(summary)) {
					throw new Error(
						`Extension host run failed before reporting case outcomes:\n${summary.runError}`,
					);
				}

				const outcome = summary.caseOutcomes.get(testCase.id);
				if (!outcome) {
					throw new Error(buildMissingOutcomeMessage(testCase, summary));
				}
				if (outcome.status === "fail") {
					throw new Error(
						outcome.error ? `${outcome.name}\n${outcome.error}` : `${outcome.name} failed`,
					);
				}
			});
		}
	});
}

const describeCursorHeadless = HAS_CURSOR_AGENT || CAN_RUN_CURSOR_NATIVE ? describe : describe.skip;

describeCursorHeadless("E2E: Cursor headless agent + Sage hooks", { timeout: 300_000 }, () => {
	// The canary matrix drives Sage through the tool names Cursor actually exposes
	// (Tool-name drift #2). Cursor has NO web-fetch tool/hook, so the URL canary is
	// delivered via Shell (`curl <url>`) — Sage's bash extractor pulls the URL — not a
	// native WebFetch. File goes through the Write tool, command through Shell.
	beforeAll(() => {
		if (IS_NATIVE) {
			cursorNativeHome = createNativeHome("cursor");
			AUDIT_PATH = resolveNativeAuditPath(cursorNativeHome.path);
			// cursor-agent touches the macOS keychain unconditionally (its own session/config
			// bookkeeping, e.g. a "cursor-user" entry) regardless of whether CURSOR_API_KEY is
			// set — with HOME isolated and no ~/Library, macOS has no keychain to use at all and
			// pops a "Keychain Not Found" GUI dialog. Symlink the real ~/Library unconditionally
			// on darwin so the keychain is reachable (mirrors the pre-container-refactor code).
			// CURSOR_API_KEY passthrough (already inherited via process.env in runCursorAgent)
			// still covers the actual model-auth path; this is a separate, always-needed fixup.
			if (process.platform === "darwin") {
				const realLibrary = path.join(homedir(), "Library");
				const homeLibrary = path.join(cursorNativeHome.path, "Library");
				if (existsSync(realLibrary) && !existsSync(homeLibrary)) {
					symlinkSync(realLibrary, homeLibrary);
				}
			}
		}
		setupCursorHeadless();
	});

	afterAll(() => {
		cursorNativeHome?.cleanup();
		cursorNativeHome = undefined;
	});

	it("blocks canary command via dummy rule", async () => {
		await expectFreshCursorDeny(
			`Use the terminal to run this exact command: echo ${CANARY_MARKERS.cmdDenyAlpha}`,
			CANARY_MARKERS.cmdDenyAlpha,
		);
	});

	it("blocks canary URL via dummy rule", async () => {
		// Imperative, explicit-command phrasing mirrors the reliable openclaw prompts so
		// the model emits the Shell tool rather than narrating a refusal.
		await expectFreshCursorDeny(
			`Use the terminal to run this exact command: curl https://${CANARY_MARKERS.urlDeny}.test/page`,
			CANARY_MARKERS.urlDeny,
		);
	});

	it("blocks canary file write via dummy rule", async () => {
		// promptTarget is the agent's view (/work in the container, or the real isolated
		// HOME in native mode); hostTarget is the host view of that same path — `/work` does
		// not exist on the host, so the absence check must use the mapped path or it passes
		// vacuously.
		const homeDir = IS_NATIVE ? (cursorNativeHome?.path ?? CURSOR_HOME_HOST) : CURSOR_HOME_HOST;
		const hostTarget = path.join(homeDir, `${CANARY_MARKERS.fileDeny}.txt`);
		const promptTarget = IS_NATIVE ? hostTarget : CONTAINER_FILE_TARGET;
		await expectFreshCursorDeny(
			`Use the Write tool to save the text hello to the file ${promptTarget}`,
			CANARY_MARKERS.fileDeny,
		);
		// Bonus: the denied write must never land.
		expect(existsSync(hostTarget), `denied write target must stay absent: ${hostTarget}`).toBe(
			false,
		);
	});

	// Re-validate the committed Layer 1 envelope fixture against the real Cursor host (the
	// drift loop), reading the bind-mounted capture sink. Container-only: the capture sink
	// is never wired up in native mode.
	it.skipIf(!IS_CONTAINER)(
		"re-validates the Cursor hook envelope against the committed fixture (drift check)",
		() => {
			// Best-effort clear so this test diffs only its own run's capture (last-wins
			// read-back tolerates staleness; tolerantRm swallows EPERM on bind-mount files).
			tolerantRm(CURSOR_CAPTURE_FILE);

			// Drive a deterministic benign shell echo → one preToolUse(Shell) capture.
			runCursorAgent("Use the terminal to run this exact command: echo sage-cursor-contract");

			// Diff the RAW wire payload (not the normalized form): normalization is
			// Sage-internal, so only the raw payload reveals host wire-format drift. The
			// capture is the authoritative "Shell ran" signal — if it's absent, the model
			// never invoked the tool (inconclusive) or the capture wiring is broken.
			const capture = readLastCaptureRecord(
				CURSOR_CAPTURE_FILE,
				(record) => record.raw?.tool_name === "Shell",
			);
			expect(
				capture,
				"no preToolUse(Shell) capture produced — model never invoked Shell, or capture wiring is broken",
			).toBeTruthy();
			if (!capture) return;
			const wire = capture.raw;

			// tool_name value-pin: we drove the Shell tool, so the host must report exactly
			// "Shell". Catches a rename here too — the structural envelope diff would not.
			expect(wire.tool_name, "captured tool_name must match the driven tool").toBe("Shell");
			expect(wire.tool_input, "preToolUse must carry tool_input").toBeDefined();

			// Diff vs the committed fixture, warn on new fields, emit a `latest`-mode candidate,
			// and fail on real drift in BOTH modes (connector-labelled).
			assertNoEnvelopeDrift({
				captured: wire,
				fixturePath: CURSOR_FIXTURE_PATH,
				label: "Cursor preToolUse",
				mode: MODE,
				volatileFields: ENVELOPE_VOLATILE_FIELDS.cursor,
				proposedPath: path.join(
					PROPOSED_DIR,
					"cursor",
					path.relative(PLUGIN_ROOT, CURSOR_FIXTURE_PATH),
				),
			});
		},
	);
});

// --- Cursor headless helpers (container + native) ---

/** Write the project hooks into the bind-mounted/native HOME + clear the audit sink. */
function setupCursorHeadless(): void {
	// Container: HOME = /work = e2e/output/cursor-home (host), hooks point at the bind-mounted
	// in-container runner. Native: HOME = the isolated temp home, hooks point at the real
	// host-absolute runner path. Clear the audit log so the count-delta starts fresh.
	const homeDir = IS_NATIVE ? (cursorNativeHome?.path ?? CURSOR_HOME_HOST) : CURSOR_HOME_HOST;
	const hookRunnerPath = IS_NATIVE ? HOOK_RUNNER_PATH : CONTAINER_HOOK_RUNNER;
	const hooksDir = path.join(homeDir, ".cursor");
	mkdirSync(hooksDir, { recursive: true });
	writeFileSync(
		path.join(hooksDir, "hooks.json"),
		cursorHooksJson(`node "${hookRunnerPath}" cursor`),
		"utf8",
	);
	tolerantRm(AUDIT_PATH);
}

/**
 * Drive the cursor-agent CLI once. Container: inside its compose service (`-T` keeps
 * stdout clean). Native: the resolved binary directly, isolated to cursorNativeHome
 * (HOME/USERPROFILE) — ambient CURSOR_API_KEY passthrough via the inherited env, or the
 * macOS keychain symlink set up in beforeAll.
 */
function runCursorAgent(prompt: string): { stream: string; status: number | null; error?: Error } {
	const args = [
		"-p",
		"--force",
		"--model",
		HEADLESS_AGENT_MODEL,
		"--output-format",
		"stream-json",
		prompt,
	];
	const result = IS_NATIVE
		? spawnNative(
				NATIVE_CURSOR_BIN.executablePath ?? "cursor-agent",
				args,
				{
					...process.env,
					HOME: cursorNativeHome?.path,
					USERPROFILE: cursorNativeHome?.path,
				},
				{ timeout: 240_000 },
			)
		: composeRun(COMPOSE_FILE, "cursor", args, { timeout: 240_000 });
	return {
		stream: `${result.stdout ?? ""}\n${result.stderr ?? ""}`,
		status: result.status,
		error: result.error ?? undefined,
	};
}

/**
 * Drive the prompt up to TOOL_ATTEMPTS times; pass only on a strict INCREASE in Sage `deny`
 * verdicts whose tool_input_summary contains the marker (via the shared driveForFreshVerdict
 * loop). "Model never invoked the tool" is inconclusive → hard-fail (block tests fail hard;
 * skip is reserved for benign/allow tests).
 */
async function expectFreshCursorDeny(prompt: string, marker: string): Promise<void> {
	const { fresh, last } = await driveForFreshVerdict({
		auditPath: AUDIT_PATH,
		decision: "deny",
		marker,
		attempts: TOOL_ATTEMPTS,
		drive: () => runCursorAgent(prompt),
	});
	if (!fresh) {
		expect.fail(
			`No new Sage 'deny' for "${marker}" after ${TOOL_ATTEMPTS} attempt(s) — the model ` +
				`never invoked the tool, or Sage failed to deny it. Audit: ${AUDIT_PATH}\n` +
				`Last agent output (tail):\n${(last?.stream ?? "").slice(-800)}`,
		);
	}
}

/** Project hooks.json registering the generic preToolUse hook for the canary tools. */
function cursorHooksJson(hookCommand: string): string {
	const hooks = {
		version: 1,
		hooks: {
			preToolUse: [{ matcher: "Shell|Write|Edit|Delete|Read", command: hookCommand, timeout: 30 }],
		},
	};
	return `${JSON.stringify(hooks, null, 2)}\n`;
}

async function runHostE2E(host: HostName, executablePath: string): Promise<HostRunSummary> {
	const metadata = HOST_METADATA[host];
	const tempHome = mkdtempSync(path.join(tmpdir(), `sage-${host}-home-`));
	const resultsFilePath = path.join(tempHome, "sage-e2e-results.json");
	try {
		const { runError } = await runExtensionHostSuite({
			host,
			vscodeExecutablePath: executablePath,
			extensionRoot: EXTENSION_ROOT,
			extensionTestsPath: EXTENSION_TESTS_PATH,
			hookRunnerPath: HOOK_RUNNER_PATH,
			workspaceFolder: WORKSPACE_FOLDER,
			resultsFile: resultsFilePath,
			home: tempHome,
			extensionId: metadata.extensionId,
			managedMarker: metadata.managedMarker,
			hookMode: metadata.hookMode,
			hooksRelativePath: metadata.hooksRelativePath,
			verbose: E2E_VERBOSE,
			// macOS reaches the real keychain otherwise; mock it so the host run is hermetic.
			extraLaunchArgs: process.platform === "darwin" ? ["--use-mock-keychain"] : [],
		});
		return summarizeOutcomes(readCaseOutcomes(resultsFilePath), runError);
	} finally {
		rmSync(tempHome, { recursive: true, force: true });
	}
}

/**
 * Container path (Layer 2, wiring-only): the pinned VS Code image runs the whole Extension
 * Host suite under Xvfb against the bind-mounted current-branch Sage and writes
 * vscode-results.json to the bind-mounted /work; the host only launches it and reads the
 * outcomes back. Real Copilot Chat is NOT driven here (it can't authenticate headless) —
 * that lives in Layer 3.
 *
 * Async (execFile, not the in-process runTests): the beforeAll hook just kicks off this
 * promise; the `it`s await it under the describe's 600s timeout. A non-zero exit / timeout
 * still leaves the in-container results file written, so we fall through to read it and
 * only surface the spawn failure if no outcomes landed.
 */
async function runVsCodeContainerSuite(): Promise<HostRunSummary> {
	const resultsFilePath = path.join(VSCODE_HOME_HOST, "vscode-results.json");
	mkdirSync(VSCODE_HOME_HOST, { recursive: true });
	rmSync(resultsFilePath, { force: true });

	let spawnError: string | undefined;
	try {
		await execFileAsync("docker", ["compose", "-f", COMPOSE_FILE, "run", "--rm", "-T", "vscode"], {
			timeout: 540_000,
			maxBuffer: 10 * 1024 * 1024,
		});
	} catch (error) {
		const e = error as { message?: string; stdout?: string; stderr?: string };
		spawnError = `${e.message ?? String(error)}\nstdout:\n${e.stdout ?? ""}\nstderr:\n${e.stderr ?? ""}`;
	}

	const orderedOutcomes = readCaseOutcomes(resultsFilePath);
	const runError =
		orderedOutcomes.length === 0
			? `vscode container produced no case outcomes.${spawnError ? `\nerror: ${spawnError}` : ""}`
			: undefined;
	return summarizeOutcomes(orderedOutcomes, runError);
}

function summarizeOutcomes(orderedOutcomes: CaseOutcome[], runError?: string): HostRunSummary {
	return {
		orderedOutcomes,
		caseOutcomes: new Map(orderedOutcomes.map((outcome) => [outcome.id, outcome])),
		runError,
	};
}

function hasFailedOutcomes(summary: HostRunSummary): boolean {
	return summary.orderedOutcomes.some((outcome) => outcome.status === "fail");
}

function buildMissingOutcomeMessage(testCase: E2ECase, summary: HostRunSummary): string {
	const recorded =
		summary.orderedOutcomes.length > 0
			? summary.orderedOutcomes.map((outcome) => `- ${outcome.id} (${outcome.status})`).join("\n")
			: "No cases were recorded.";
	const runErrorSection = summary.runError ? `\n\nExtension host error:\n${summary.runError}` : "";
	return `Missing result for case "${testCase.title}" (${testCase.id}).\n\nRecorded outcomes:\n${recorded}${runErrorSection}`;
}

function readCaseOutcomes(filePath: string): CaseOutcome[] {
	if (!existsSync(filePath)) {
		return [];
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(filePath, "utf8"));
	} catch {
		return [];
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return [];
	}
	const rawCases = (parsed as { cases?: unknown }).cases;
	if (!Array.isArray(rawCases)) {
		return [];
	}

	const outcomes: CaseOutcome[] = [];
	for (const rawCase of rawCases) {
		const outcome = parseCaseOutcome(rawCase);
		if (outcome) {
			outcomes.push(outcome);
		}
	}
	return outcomes;
}

function parseCaseOutcome(value: unknown): CaseOutcome | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}

	const record = value as Record<string, unknown>;
	const id = typeof record.id === "string" ? record.id : undefined;
	const name = typeof record.name === "string" ? record.name : undefined;
	const status =
		record.status === "pass" || record.status === "fail"
			? (record.status as CaseStatus)
			: undefined;
	if (!id || !name || !status) {
		return undefined;
	}

	const error = typeof record.error === "string" ? record.error : undefined;
	const durationMs = typeof record.durationMs === "number" ? record.durationMs : undefined;
	return { id, name, status, error, durationMs };
}

function resolveE2EVerbose(): boolean {
	const envValue = process.env.SAGE_E2E_VERBOSE?.trim().toLowerCase();
	if (envValue === "1" || envValue === "true" || envValue === "yes" || envValue === "on") {
		return true;
	}
	if (envValue === "0" || envValue === "false" || envValue === "no" || envValue === "off") {
		return false;
	}

	for (let i = 0; i < process.argv.length; i += 1) {
		const arg = process.argv[i];
		if (arg === "--reporter" && process.argv[i + 1] === "verbose") {
			return true;
		}
		if (
			typeof arg === "string" &&
			arg.startsWith("--reporter=") &&
			arg.slice("--reporter=".length) === "verbose"
		) {
			return true;
		}
	}

	return false;
}

function resolveRequestedHost(): HostName | undefined {
	const envHost = parseHostName(process.env.SAGE_E2E_HOST ?? process.env.SAGE_E2E_TARGET);
	if (envHost) {
		return envHost;
	}

	const lifecycleEvent = process.env.npm_lifecycle_event?.toLowerCase();
	if (lifecycleEvent?.endsWith(":cursor")) {
		return "cursor";
	}
	if (lifecycleEvent?.endsWith(":vscode")) {
		return "vscode";
	}

	const hostArg = readFlagValue("--host");
	if (hostArg) {
		const parsed = parseHostName(hostArg);
		if (!parsed) {
			throw new Error(`Unsupported --host value: "${hostArg}". Expected "cursor" or "vscode".`);
		}
		return parsed;
	}

	return undefined;
}

function readFlagValue(flag: string): string | undefined {
	const index = process.argv.indexOf(flag);
	if (index < 0) {
		return undefined;
	}
	const value = process.argv[index + 1];
	return value?.trim() || undefined;
}

function parseHostName(value: string | undefined): HostName | undefined {
	const normalized = value?.trim().toLowerCase();
	if (normalized === "cursor" || normalized === "vscode") {
		return normalized;
	}
	return undefined;
}

function resolveHostExecutable(host: HostName): HostResolution {
	const envCandidates =
		host === "cursor"
			? readEnvCandidates(["SAGE_CURSOR_PATH"])
			: readEnvCandidates(["SAGE_VSCODE_PATH", "VSCODE_EXECUTABLE_PATH"]);
	const candidates = [...envCandidates, ...defaultExecutableCandidates(host)];

	for (const rawCandidate of dedupe(candidates)) {
		const candidate = normalizeExecutableCandidate(host, rawCandidate);
		if (!candidate) {
			continue;
		}
		if (isPathLike(candidate) && existsSync(candidate)) {
			return { executablePath: candidate };
		}
		if (canExecute(candidate)) {
			return { executablePath: candidate };
		}
	}

	const reason =
		envCandidates.length > 0
			? `none of the configured executables were runnable: ${envCandidates.join(", ")}`
			: "no runnable executable found in PATH or common install locations";
	return { reason };
}

function readEnvCandidates(names: string[]): string[] {
	const values: string[] = [];
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) {
			values.push(value);
		}
	}
	return values;
}

function defaultExecutableCandidates(host: HostName): string[] {
	const candidates: string[] = [];
	if (host === "cursor") {
		if (process.platform === "win32") {
			pushIfDefined(
				candidates,
				process.env.LOCALAPPDATA &&
					path.join(process.env.LOCALAPPDATA, "Programs", "Cursor", "Cursor.exe"),
			);
			pushIfDefined(
				candidates,
				process.env.ProgramFiles && path.join(process.env.ProgramFiles, "Cursor", "Cursor.exe"),
			);
			candidates.push(
				...resolveWindowsWhereCandidates(["cursor"]).filter((candidate) =>
					isWindowsExecutablePath(candidate),
				),
			);
		}
		if (process.platform === "darwin") {
			candidates.push("/Applications/Cursor.app/Contents/MacOS/Cursor");
		}
		if (process.platform === "linux") {
			candidates.push("/usr/bin/cursor", "/usr/local/bin/cursor", "cursor");
		}
		return candidates;
	}

	if (process.platform === "win32") {
		pushIfDefined(
			candidates,
			process.env.LOCALAPPDATA &&
				path.join(process.env.LOCALAPPDATA, "Programs", "Microsoft VS Code", "Code.exe"),
		);
		pushIfDefined(
			candidates,
			process.env.LOCALAPPDATA &&
				path.join(
					process.env.LOCALAPPDATA,
					"Programs",
					"Microsoft VS Code Insiders",
					"Code - Insiders.exe",
				),
		);
		pushIfDefined(
			candidates,
			process.env.ProgramFiles &&
				path.join(process.env.ProgramFiles, "Microsoft VS Code", "Code.exe"),
		);
		pushIfDefined(
			candidates,
			process.env["ProgramFiles(x86)"] &&
				path.join(process.env["ProgramFiles(x86)"], "Microsoft VS Code", "Code.exe"),
		);
		candidates.push(...resolveWindowsVsCodeExecutablesFromWhere());
	}
	if (process.platform === "darwin") {
		candidates.push(
			"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
			"/Applications/Visual Studio Code - Insiders.app/Contents/MacOS/Electron",
		);
	}
	if (process.platform === "linux") {
		candidates.push(
			"/usr/bin/code",
			"/usr/local/bin/code",
			"/snap/bin/code",
			"code",
			"code-insiders",
		);
	}
	return candidates;
}

function canExecute(executablePath: string): boolean {
	const baseOptions = {
		encoding: "utf8",
		timeout: 20_000,
		windowsHide: true,
	} as const;
	const direct = spawnSync(executablePath, ["--version"], baseOptions);
	if (!direct.error && direct.status === 0) {
		return true;
	}

	if (process.platform !== "win32") {
		return false;
	}

	const command =
		executablePath.includes("\\") || executablePath.includes("/") || executablePath.includes(" ")
			? `"${executablePath.replace(/"/g, '""')}" --version`
			: `${executablePath} --version`;
	const viaCmd = spawnSync("cmd.exe", ["/d", "/s", "/c", command], baseOptions);
	return !viaCmd.error && viaCmd.status === 0;
}

function normalizeExecutableCandidate(host: HostName, candidate: string): string | undefined {
	const value = candidate.trim();
	if (!value) {
		return undefined;
	}
	if (host !== "vscode" || process.platform !== "win32") {
		return value;
	}

	const normalized = value.toLowerCase();
	if (normalized.endsWith("\\bin\\code") || normalized.endsWith("\\bin\\code.cmd")) {
		return path.resolve(value, "..", "..", "Code.exe");
	}
	if (
		normalized.endsWith("\\bin\\code-insiders") ||
		normalized.endsWith("\\bin\\code-insiders.cmd")
	) {
		return path.resolve(value, "..", "..", "Code - Insiders.exe");
	}
	return value;
}

function isPathLike(value: string): boolean {
	return value.includes("\\") || value.includes("/") || path.isAbsolute(value);
}

function resolveWindowsWhereCandidates(commands: string[]): string[] {
	if (process.platform !== "win32") {
		return [];
	}
	const discovered: string[] = [];
	for (const command of commands) {
		const result = spawnSync("where.exe", [command], {
			encoding: "utf8",
			timeout: 10_000,
			windowsHide: true,
		});
		if (result.error || result.status !== 0 || !result.stdout) {
			continue;
		}
		for (const line of result.stdout.split(/\r?\n/)) {
			const candidate = line.trim();
			if (candidate) {
				discovered.push(candidate);
			}
		}
	}
	return discovered;
}

function resolveWindowsVsCodeExecutablesFromWhere(): string[] {
	if (process.platform !== "win32") {
		return [];
	}
	const paths: string[] = [];
	for (const candidate of resolveWindowsWhereCandidates(["code", "code-insiders"])) {
		const normalized = candidate.toLowerCase();
		if (normalized.endsWith("\\code.exe") || normalized.endsWith("\\code - insiders.exe")) {
			paths.push(candidate);
			continue;
		}
		if (normalized.endsWith("\\bin\\code") || normalized.endsWith("\\bin\\code.cmd")) {
			paths.push(path.resolve(candidate, "..", "..", "Code.exe"));
			continue;
		}
		if (
			normalized.endsWith("\\bin\\code-insiders") ||
			normalized.endsWith("\\bin\\code-insiders.cmd")
		) {
			paths.push(path.resolve(candidate, "..", "..", "Code - Insiders.exe"));
		}
	}
	return paths.filter((candidate) => isWindowsExecutablePath(candidate));
}

function isWindowsExecutablePath(candidate: string): boolean {
	return candidate.toLowerCase().endsWith(".exe");
}

function pushIfDefined(values: string[], value: string | undefined): void {
	if (value) {
		values.push(value);
	}
}

function dedupe(values: string[]): string[] {
	return [...new Set(values)];
}

// VS Code extension-development staging + the runTests() invocation live in the shared
// ./vscode-host-runner.js (one source of truth with the container path).
