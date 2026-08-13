/**
 * Tier 3 E2E (Layer 2): Sage hooks running inside the real GitHub Copilot CLI, in a
 * container or (SAGE_E2E_RUNNER=native) directly against a locally-installed `copilot`
 * binary.
 *
 * The VS Code extension installs managed hooks into ~/.copilot/hooks/hooks.json. Copilot CLI
 * reads from the same path, so these tests verify that Sage protection works end-to-end when
 * Copilot CLI triggers tool calls. The suite loads hooks via `--plugin-dir` from a scratch
 * plugin directory (no changes to the real ~/.copilot/ config in either mode).
 *
 * Excluded from `pnpm test`. Run with:
 *
 *   e2e/run.sh copilot                                  # builds the agent image, drives it via docker compose
 *   SAGE_E2E_RUNNER=native pnpm test:e2e:copilot-cli    # drives an installed `copilot` binary directly
 *
 * Container mode: the container is only the agent sandbox; the test logic (parsing,
 * assertions) stays here on the host. Native mode: copilot runs directly, isolated to a
 * temp HOME, reusing the developer's own already-authenticated session (its config.json is
 * copied into the isolated HOME, never the whole real HOME) plus ambient
 * GITHUB_TOKEN/GH_TOKEN/COPILOT_GITHUB_TOKEN. Both share the same assertions; the drift-diff
 * check stays container-only (detection + the tool-name map are proven deterministically at
 * Layer 1's integration.test.ts / tool-names-contract.test.ts; this layer proves the live
 * wiring + payload drift).
 *
 * Prerequisites: container mode needs Docker + e2e/.env (Copilot-entitled GitHub token).
 * Native mode needs `copilot` installed and already authenticated.
 */

import { copyFileSync, existsSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import {
	assertNoEnvelopeDrift,
	CANARY_MARKERS,
	composeRun,
	countSageVerdict,
	createNativeHome,
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
	tolerantRm,
} from "@gendigital/sage-core/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const PLUGIN_ROOT = path.resolve(EXTENSION_ROOT, "..", ".."); // repo root
const HOOK_RUNNER_PATH = path.resolve(EXTENSION_ROOT, "dist", "sage-hook.cjs");

// --- Invocation ---
// The copilot CLI runs through docker compose against the bind-mounted current-branch Sage.
const {
	composeFile: COMPOSE_FILE,
	captureDir: CAPTURE_DIR,
	proposedDir: PROPOSED_DIR,
} = e2ePaths(PLUGIN_ROOT);
// The container's --plugin-dir (compose mounts e2e/output/copilot-plugin here) and the
// in-container path to the bind-mounted hook runner (repo root → /sage).
const CONTAINER_PLUGIN_DIR = "/plugin";
const CONTAINER_HOOK_RUNNER = "/sage/packages/extension/dist/sage-hook.cjs";

// Host side of the bind-mounted scratch plugin dir (compose mounts it to /plugin).
const COPILOT_PLUGIN_HOST = path.resolve(PLUGIN_ROOT, "e2e", "output", "copilot-plugin");
// Reassigned in beforeAll for native mode (resolveNativeAuditPath against the isolated temp
// HOME) — resolveAuditPath's own non-container fallback is the developer's REAL ~/.sage,
// which native mode must never touch (isolation). Container mode: the in-container ~/.sage
// (= /work/.sage) is bind-mounted to e2e/output/copilot-sage, so the host reads the SAME
// audit.jsonl the hook wrote — the audit assertion runs for real (full parity).
let AUDIT_PATH = resolveAuditPath(PLUGIN_ROOT, "copilot-sage", "audit.jsonl");

// --- Native mode (SAGE_E2E_RUNNER=native) ---
const NATIVE_BIN = IS_NATIVE
	? resolveExecutable(["SAGE_COPILOT_PATH"], ["copilot"])
	: { reason: "not native mode" };
const CAN_RUN_NATIVE = IS_NATIVE && Boolean(NATIVE_BIN.executablePath);
if (IS_NATIVE && !CAN_RUN_NATIVE) {
	console.warn(`Copilot CLI E2E (native) skipped: ${NATIVE_BIN.reason}`);
}
// Set by beforeAll in native mode: an isolated temp HOME, never the developer's real one.
let nativeHome: NativeHome | undefined;
// The standard Copilot CLI login config file, copied forward into the isolated temp HOME
// so native mode reuses the developer's ambient session without touching their real
// ~/.copilot. GITHUB_TOKEN/GH_TOKEN/COPILOT_GITHUB_TOKEN pass through automatically since
// native mode inherits the full parent env.
const COPILOT_CONFIG_FILE = "config.json";

// --- Drift loop ---
// Copilot is NOT MCP-based: the sage-hook CJS hook captures each raw + normalized
// payload to CAPTURE_DIR (bind-mounted from e2e/output/capture, namespaced
// vscode-*). The drift test reads the RAW wire payload back and diffs it against
// the committed Layer 1 fixture. `pinned` fails on drift; `latest` also writes the
// regenerated candidate to e2e/output/proposed/ (bump-PR step is CI-only).
const VSCODE_CAPTURE_FILE = path.join(CAPTURE_DIR, "vscode-pre-tool-use.jsonl");
const COPILOT_FIXTURE_PATH = path.resolve(
	__dirname,
	"fixtures",
	"contract",
	"copilot-pre-tool-use.json",
);

/**
 * Model to use for Copilot CLI E2E tests.
 * Override via COPILOT_E2E_MODEL env var. Defaults to claude-haiku-4.5
 * for reliable tool-calling behavior and lower cost.
 */
const COPILOT_MODEL = process.env.COPILOT_E2E_MODEL ?? "claude-haiku-4.5";

const BASH_PREFIX =
	"You are a CLI assistant. When given a command, run it using the bash tool. " +
	"Reply only with the tool call, no commentary.\n\n" +
	"Run this command: ";

const FILE_PREFIX =
	"You are a CLI assistant. When given a file task, use a file tool (create or edit). " +
	"Reply only with the tool call, no commentary.\n\n";

const FETCH_PREFIX =
	"You are a CLI assistant. When given a URL, fetch it using web_fetch or bash curl. " +
	"Reply only with the tool call, no commentary.\n\n";

// --- Types ---

interface CopilotEvent {
	type: string;
	data?: Record<string, unknown>;
	[key: string]: unknown;
}

interface ToolResult {
	toolCallId: string;
	toolName: string;
	success: boolean;
	errorCode?: string;
	errorMessage?: string;
	resultContent?: string;
}

// --- Helpers ---

function runCopilot(
	prompt: string,
	opts: { pluginDir: string; timeout?: number; promptPrefix?: string },
): { events: CopilotEvent[]; raw: string; exitCode: number | null } {
	const prefix = opts.promptPrefix ?? BASH_PREFIX;
	const fullPrompt = `${prefix}${prompt}`;

	const copilotArgs = [
		"-p",
		fullPrompt,
		"--model",
		COPILOT_MODEL,
		"--allow-all",
		"--output-format",
		"json",
		"--no-auto-update",
		"--no-custom-instructions",
		"--plugin-dir",
		opts.pluginDir,
	];

	// Container: drive copilot inside the pinned image via docker compose (`-T` keeps
	// stdout clean for JSON parsing). Native: the resolved binary directly, isolated to
	// nativeHome (HOME/USERPROFILE) — ambient GITHUB_TOKEN/GH_TOKEN/COPILOT_GITHUB_TOKEN
	// passthrough via the inherited env, or the copied-forward config.json session.
	const result = IS_NATIVE
		? spawnNative(
				NATIVE_BIN.executablePath ?? "copilot",
				copilotArgs,
				{ ...process.env, HOME: nativeHome?.path, USERPROFILE: nativeHome?.path },
				{ timeout: opts.timeout ?? 200_000 },
			)
		: composeRun(COMPOSE_FILE, "copilot", copilotArgs, {
				timeout: opts.timeout ?? 200_000,
			});

	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	if (result.error) {
		console.error("copilot spawn error:", result.error);
	}
	if (stderr.trim()) {
		console.error("copilot stderr:", stderr);
	}

	const events: CopilotEvent[] = [];
	for (const line of stdout.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			events.push(JSON.parse(trimmed) as CopilotEvent);
		} catch {
			// Skip non-JSON lines.
		}
	}

	return { events, raw: `${stdout}\n${stderr}`, exitCode: result.status };
}

/** Log event types and errors for debugging failed tests. */
function dumpDiagnostics(events: CopilotEvent[], raw: string): void {
	const types = events.map((e) => e.type);
	console.error(`[copilot-e2e] ${events.length} events: ${types.join(", ")}`);

	const errors = events.filter((e) => e.type === "session.error");
	for (const err of errors) {
		console.error("[copilot-e2e] session.error:", JSON.stringify(err.data));
	}

	// Show assistant messages (the model may have responded with text instead of tools).
	const messages = events.filter((e) => e.type === "assistant.message");
	for (const msg of messages) {
		const content = (msg.data as Record<string, unknown>)?.content;
		if (content) console.error("[copilot-e2e] assistant.message:", String(content).slice(0, 300));
	}

	if (events.length === 0) {
		console.error("[copilot-e2e] raw output (first 500 chars):", raw.slice(0, 500));
	}
}

function findToolResults(events: CopilotEvent[]): ToolResult[] {
	// toolName is only present on tool.execution_start events.
	// Correlate via toolCallId to get the name for completion events.
	const toolNameById = new Map<string, string>();
	for (const event of events) {
		if (event.type !== "tool.execution_start") continue;
		const data = event.data;
		if (!data) continue;
		const id = data.toolCallId as string;
		const name = data.toolName as string;
		if (id && name) toolNameById.set(id, name);
	}

	const results: ToolResult[] = [];
	for (const event of events) {
		if (event.type !== "tool.execution_complete") continue;
		const data = event.data;
		if (!data) continue;

		const toolCallId = (data.toolCallId as string) ?? "";
		const toolName = (data.toolName as string) ?? toolNameById.get(toolCallId) ?? "";
		const success = (data.success as boolean) ?? false;

		const error = data.error as Record<string, unknown> | undefined;
		const errorCode = (error?.code as string) ?? undefined;
		const errorMessage = (error?.message as string) ?? undefined;

		const resultObj = data.result as Record<string, unknown> | undefined;
		const resultContent = (resultObj?.content as string) ?? undefined;

		// Skip internal tools like report_intent.
		if (toolName === "report_intent") continue;

		results.push({ toolCallId, toolName, success, errorCode, errorMessage, resultContent });
	}
	return results;
}

/**
 * Assert the audit log recorded a FRESH verdict — a strict increase over `before` (the
 * count captured just before driving this run). AUDIT_PATH is a persistent file (container
 * mode bind-mounts it, never cleared between runs), so an absolute count > 0 would let a
 * stale entry from a prior run mask a real regression where Sage failed to act this run.
 * Runs in both modes: locally against ~/.sage/audit.jsonl, and in container against the
 * bind-mounted copy at e2e/output/copilot-sage/audit.jsonl (AUDIT_PATH resolves per mode
 * above).
 */
function expectFreshAuditVerdict(
	before: number,
	verdict: string,
	marker: string,
	message: string,
): void {
	expect(countSageVerdict(AUDIT_PATH, verdict, marker) > before, message).toBe(true);
}

// --- Fixture setup ---

/**
 * Container mode: the hook runner + resources are already inside the bind-mounted repo at
 * /sage, so we only generate the plugin scaffold (plugin.json + hooks.json) into the
 * bind-mounted scratch dir (e2e/output/copilot-plugin → /plugin) with hooks.json pointing
 * at the in-container hook path. No copying. Native mode: the scaffold goes into a
 * subdirectory of the isolated temp HOME, with hooks.json pointing at the real
 * host-absolute hook runner path.
 */
function createCopilotFixture(): { pluginDir: string } {
	const pluginHost = IS_NATIVE
		? path.join(nativeHome?.path ?? COPILOT_PLUGIN_HOST, "plugin")
		: COPILOT_PLUGIN_HOST;
	const hookRunnerPath = IS_NATIVE ? HOOK_RUNNER_PATH : CONTAINER_HOOK_RUNNER;

	mkdirSync(pluginHost, { recursive: true });
	writeFileSync(
		path.join(pluginHost, "plugin.json"),
		JSON.stringify({ name: "sage-e2e", version: "0.0.0", description: "Sage E2E test plugin" }),
		"utf8",
	);
	const hooksDir = path.join(pluginHost, "hooks");
	mkdirSync(hooksDir, { recursive: true });
	const hookCommand = `ELECTRON_RUN_AS_NODE=1 node "${hookRunnerPath}" vscode`;
	writeFileSync(
		path.join(hooksDir, "hooks.json"),
		`${JSON.stringify(
			{ hooks: { PreToolUse: [{ type: "command", command: hookCommand, timeout: 30 }] } },
			null,
			2,
		)}\n`,
		"utf8",
	);
	// Container mode reads the scaffold at the mount point, not the host path; native mode
	// reads it directly (same real filesystem).
	return { pluginDir: IS_NATIVE ? pluginHost : CONTAINER_PLUGIN_DIR };
}

function cleanupFixture(): void {
	// Native mode's scaffold lives inside nativeHome, cleaned up by nativeHome.cleanup() in
	// the outer afterAll. Container mode: the fixture's pluginDir is the in-container mount
	// (/plugin); the host-side scratch is COPILOT_PLUGIN_HOST. Never rm a container path on
	// the host. tolerantRm swallows EPERM on any root-owned bind-mount leftovers.
	if (!IS_NATIVE) {
		tolerantRm(COPILOT_PLUGIN_HOST);
	}
}

// --- Tests ---

describe.skipIf(!IS_CONTAINER && !CAN_RUN_NATIVE)(
	"E2E: Copilot CLI + Sage hooks",
	{ timeout: 300_000 },
	() => {
		let fixture: { pluginDir: string };

		beforeAll(() => {
			if (IS_NATIVE) {
				nativeHome = createNativeHome("copilot");
				AUDIT_PATH = resolveNativeAuditPath(nativeHome.path);
				// Ambient auth: reuse the developer's own Copilot CLI login by copying its config
				// into the isolated HOME (never the whole real HOME).
				const realConfig = path.join(homedir(), ".copilot", COPILOT_CONFIG_FILE);
				if (existsSync(realConfig)) {
					const destDir = path.join(nativeHome.path, ".copilot");
					mkdirSync(destDir, { recursive: true });
					copyFileSync(realConfig, path.join(destDir, COPILOT_CONFIG_FILE));
				}
				// copilot touches the macOS keychain unconditionally (same as cursor-agent) to
				// resolve the token behind the copied config's logged-in-user reference. Without
				// ~/Library, that lookup fails, and copilot falls back to inferring the GitHub
				// host from the repo's git remote — which for an internally-mirrored repo is the
				// enterprise host, not github.com, and validating against that fails outright.
				// Symlink the real ~/Library unconditionally on darwin so the keychain is
				// reachable (mirrors the pre-container-refactor code and the cursor fix above).
				if (process.platform === "darwin") {
					const realLibrary = path.join(homedir(), "Library");
					const homeLibrary = path.join(nativeHome.path, "Library");
					if (existsSync(realLibrary) && !existsSync(homeLibrary)) {
						symlinkSync(realLibrary, homeLibrary);
					}
				}
			}
			fixture = createCopilotFixture();
		});

		afterAll(() => {
			cleanupFixture();
			nativeHome?.cleanup();
			nativeHome = undefined;
		});

		it("hooks load and allow benign shell command", () => {
			const { events, raw } = runCopilot("echo hello_copilot_e2e_test", {
				pluginDir: fixture.pluginDir,
			});
			const results = findToolResults(events);
			const bash = results.filter((r) => r.toolName === "bash");

			if (bash.length === 0) dumpDiagnostics(events, raw);
			expect(bash.length, "Model must use bash tool at least once").toBeGreaterThanOrEqual(1);
			const match = bash.find(
				(b) => b.success && b.resultContent?.includes("hello_copilot_e2e_test"),
			);
			expect(match, "At least one bash result must contain hello_copilot_e2e_test").toBeTruthy();
		});

		it("blocks canary command via dummy rule", () => {
			const before = countSageVerdict(AUDIT_PATH, "deny", CANARY_MARKERS.cmdDenyAlpha);
			const { events, raw } = runCopilot(`echo ${CANARY_MARKERS.cmdDenyAlpha}`, {
				pluginDir: fixture.pluginDir,
			});
			const results = findToolResults(events);
			const bash = results.filter((r) => r.toolName === "bash");

			if (bash.length === 0) dumpDiagnostics(events, raw);
			expect(bash.length, "Model must attempt bash tool").toBeGreaterThanOrEqual(1);
			const denied = bash.find((b) => !b.success && b.errorCode === "denied");
			expect(denied, "bash tool must be denied by hook").toBeTruthy();
			expectFreshAuditVerdict(
				before,
				"deny",
				CANARY_MARKERS.cmdDenyAlpha,
				"Audit log must contain a fresh deny verdict for canary command",
			);
		});

		it("blocks canary URL via dummy rule", () => {
			const { events, raw } = runCopilot(`echo visit https://${CANARY_MARKERS.urlDeny}.test/page`, {
				pluginDir: fixture.pluginDir,
			});
			const results = findToolResults(events);
			const bash = results.filter((r) => r.toolName === "bash");

			if (bash.length === 0) dumpDiagnostics(events, raw);
			expect(bash.length, "Model must attempt bash tool").toBeGreaterThanOrEqual(1);
			const denied = bash.find((b) => !b.success && b.errorCode === "denied");
			expect(denied, "bash tool must be denied by hook (canary URL)").toBeTruthy();
		});

		it("blocks second canary command via dummy rule", () => {
			const { events, raw } = runCopilot(
				`echo ${CANARY_MARKERS.cmdAskAlpha} && echo ${CANARY_MARKERS.cmdDenyAlpha}`,
				{ pluginDir: fixture.pluginDir },
			);
			const results = findToolResults(events);
			const bash = results.filter((r) => r.toolName === "bash");

			if (bash.length === 0) dumpDiagnostics(events, raw);
			expect(bash.length, "Model must attempt bash tool").toBeGreaterThanOrEqual(1);
			const denied = bash.find((b) => !b.success && b.errorCode === "denied");
			expect(denied, "bash tool must be denied by hook").toBeTruthy();
		});

		it("ask verdict fires for canary ask command", () => {
			const before = countSageVerdict(AUDIT_PATH, "ask", CANARY_MARKERS.cmdAskAlpha);
			const { events, raw } = runCopilot(`echo ${CANARY_MARKERS.cmdAskAlpha}`, {
				pluginDir: fixture.pluginDir,
			});
			const results = findToolResults(events);
			const bash = results.filter((r) => r.toolName === "bash");

			if (bash.length === 0) dumpDiagnostics(events, raw);
			expect(bash.length, "Model must attempt bash tool").toBeGreaterThanOrEqual(1);
			// ask verdict is also denied in non-interactive mode.
			const denied = bash.find((b) => !b.success && b.errorCode === "denied");
			expect(denied, "bash tool must be denied by hook (canary ask)").toBeTruthy();
			expectFreshAuditVerdict(
				before,
				"ask",
				CANARY_MARKERS.cmdAskAlpha,
				"Audit log must contain a fresh ask verdict for canary ask command",
			);
		});

		it("blocks canary file path via file tool", () => {
			const before = countSageVerdict(AUDIT_PATH, "deny", CANARY_MARKERS.fileDeny);
			const { events, raw } = runCopilot(
				`Create a file at /tmp/${CANARY_MARKERS.fileDeny}.txt with the exact content: hello`,
				{ pluginDir: fixture.pluginDir, promptPrefix: FILE_PREFIX },
			);
			const results = findToolResults(events);

			// Model may use create, edit, or bash — any tool that triggers the canary is valid.
			const denied = results.find((r) => !r.success && r.errorCode === "denied");
			if (!denied) {
				dumpDiagnostics(events, raw);
				if (results.length === 0) {
					expect.fail("Model did not use any tool");
				}
				expect.fail(
					`Model used tool(s) [${results.map((r) => r.toolName).join(", ")}] but none were denied`,
				);
			}

			expectFreshAuditVerdict(
				before,
				"deny",
				CANARY_MARKERS.fileDeny,
				"Audit log must contain a fresh deny verdict for canary file path",
			);
		});

		it("blocks canary URL via fetch tool", () => {
			const before = countSageVerdict(AUDIT_PATH, "deny", CANARY_MARKERS.urlDeny);
			const { events, raw } = runCopilot(
				`Fetch the content at https://${CANARY_MARKERS.urlDeny}.test/page and show me the response`,
				{ pluginDir: fixture.pluginDir, promptPrefix: FETCH_PREFIX },
			);
			const results = findToolResults(events);

			// Model may use web_fetch or bash+curl — any tool that triggers the canary is valid.
			const denied = results.find((r) => !r.success && r.errorCode === "denied");
			if (!denied) {
				dumpDiagnostics(events, raw);
				if (results.length === 0) {
					expect.fail("Model did not use any tool");
				}
				expect.fail(
					`Model used tool(s) [${results.map((r) => r.toolName).join(", ")}] but none were denied`,
				);
			}

			expectFreshAuditVerdict(
				before,
				"deny",
				CANARY_MARKERS.urlDeny,
				"Audit log must contain a fresh deny verdict for canary URL",
			);
		});

		// Re-validate the committed Layer 1 envelope fixture against the real Copilot host
		// (the drift loop), reading the bind-mounted capture sink. Container-only: the capture
		// sink is never wired up in native mode.
		it.skipIf(!IS_CONTAINER)(
			"re-validates the Copilot hook envelope against the committed fixture (drift check)",
			() => {
				// Best-effort clear so this test diffs only its own run's capture (last-wins
				// read-back tolerates staleness; tolerantRm swallows EPERM on bind-mount files).
				tolerantRm(VSCODE_CAPTURE_FILE);

				// Drive a deterministic benign bash echo → one PreToolUse capture.
				const { events, raw: stdoutRaw } = runCopilot("echo sage-copilot-contract", {
					pluginDir: fixture.pluginDir,
				});
				// Copilot CLI 1.0.63 reports the bash tool as "bash" in its event stream but
				// "Bash" in the hook payload (the names we actually depend on differ by surface).
				const ranBash = findToolResults(events).some((r) => r.toolName.toLowerCase() === "bash");
				if (!ranBash) dumpDiagnostics(events, stdoutRaw);
				expect(ranBash, "model must invoke bash so a payload is captured (else inconclusive)").toBe(
					true,
				);

				// Diff the RAW wire payload (not the normalized form): normalization is
				// Sage-internal, so only the raw payload reveals host wire-format drift.
				const capture = readLastCaptureRecord(
					VSCODE_CAPTURE_FILE,
					(record) => record.raw?.tool_name === "Bash",
				);
				expect(
					capture,
					"no PreToolUse(Bash) capture produced — capture wiring is broken",
				).toBeTruthy();
				if (!capture) return;
				const wire = capture.raw;

				// tool_name value-pin: we drove the bash tool, so the host must report exactly
				// "Bash" (Copilot CLI 1.0.63's hook name). Catches a rename here too — the
				// envelope diff alone, being structural, would not (by design).
				expect(wire.tool_name, "captured tool_name must match the driven tool").toBe("Bash");
				expect(wire.tool_input, "PreToolUse must carry tool_input").toBeDefined();

				// Shared drift loop: diff vs the committed fixture, warn on new fields, emit a
				// `latest`-mode candidate, and fail on real drift in BOTH modes (connector-labelled).
				assertNoEnvelopeDrift({
					captured: wire,
					fixturePath: COPILOT_FIXTURE_PATH,
					label: "Copilot PreToolUse",
					mode: MODE,
					volatileFields: ENVELOPE_VOLATILE_FIELDS.copilot,
					proposedPath: path.join(
						PROPOSED_DIR,
						"copilot",
						path.relative(PLUGIN_ROOT, COPILOT_FIXTURE_PATH),
					),
				});
			},
		);
	},
);
