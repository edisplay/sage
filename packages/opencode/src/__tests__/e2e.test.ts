/**
 * Tier 3 E2E (Layer 2): Sage OpenCode plugin in the real OpenCode CLI, in a container or
 * (SAGE_E2E_RUNNER=native) directly against a locally-installed `opencode` binary.
 *
 * Excluded from `pnpm test` via vitest config. Run with:
 *
 *   e2e/run.sh opencode                            # builds the agent image, drives it via docker compose
 *   SAGE_E2E_RUNNER=native pnpm test:e2e:opencode  # drives an installed `opencode` binary directly
 *
 * Container mode: HOME is bind-mounted to e2e/output/opencode-home, so the host writes the
 * opencode + Sage config IN and reads ~/.sage (audit log, plugin-scan cache) BACK — every
 * assertion runs against the in-container Sage (full parity). Native mode: opencode runs
 * directly against an isolated temp HOME, reusing the developer's own already-configured
 * model/auth (ambient — its `model.json` is copied into the isolated HOME, never the whole
 * real HOME). OpenCode is an in-process ESM plugin, so the capture sink writes
 * opencode-*.jsonl to the shared /capture mount — container-only; the drift-diff test stays
 * container-gated (detection, benign-allow, sage_approve registration and scan-injection are
 * all proven deterministically at Layer 1's integration.test.ts; this layer proves the live
 * wiring, plugin scanning, and payload drift).
 *
 * Prerequisites: container mode needs Docker + e2e/.env (Vertex ADC, NO API key). Native
 * mode needs `opencode` installed and already configured (any provider/model).
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	assertNoEnvelopeDrift,
	CANARY_MARKERS,
	composeRun,
	createNativeHome,
	ENVELOPE_VOLATILE_FIELDS,
	e2ePaths,
	IS_CONTAINER,
	IS_NATIVE,
	E2E_MODE as MODE,
	type NativeHome,
	readLastCaptureRecord,
	resolveExecutable,
	spawnNative,
	tolerantRm,
} from "@gendigital/sage-core/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

// Smaller than CONTAINER_TOOL_ATTEMPTS (4): 2 attempts × 90 s × 3 retry tests
// + drift 2 × 120 s + 5 simple × 90 s + ~1.5 min setup ≈ 23 min worst-case,
// inside TC's 25-min budget. Internal retry is enough; vitest retry: 0 on the
// describe block removes the 3× vitest-retry multiplier.
const TOOL_ATTEMPTS = 2;

const TEST_DIR = dirname(fileURLToPath(import.meta.url));

// --- Invocation ---
const REPO_ROOT = resolve(TEST_DIR, "..", "..", "..", "..");
const {
	composeFile: COMPOSE_FILE,
	captureDir: CAPTURE_DIR,
	proposedDir: PROPOSED_DIR,
} = e2ePaths(REPO_ROOT);
// The plugin path written into opencode.json: the in-container bind mount, or (native
// mode) the real host path to this package.
const PLUGIN_CONFIG_PATH = IS_NATIVE
	? resolve(REPO_ROOT, "packages", "opencode")
	: "/sage/packages/opencode";
// Host side of the container's HOME bind mount (compose maps it to /work).
const CONTAINER_HOME_HOST = resolve(REPO_ROOT, "e2e", "output", "opencode-home");
// The in-container HOME (compose.yml sets `HOME: /work` and bind-mounts CONTAINER_HOME_HOST
// there). Config values Sage resolves at runtime must use this path, not the host path —
// kept here so it can't silently drift from compose.yml.
const CONTAINER_HOME = "/work";

// --- Native mode (SAGE_E2E_RUNNER=native) ---
const NATIVE_BIN = IS_NATIVE
	? resolveExecutable(["SAGE_OPENCODE_PATH", "OPENCODE_E2E_BIN"], ["opencode"])
	: { reason: "not native mode" };
const CAN_RUN_NATIVE = IS_NATIVE && Boolean(NATIVE_BIN.executablePath);
if (IS_NATIVE && !CAN_RUN_NATIVE) {
	console.warn(`OpenCode E2E (native) skipped: ${NATIVE_BIN.reason}`);
}

// --- Drift loop ---
// The plugin captures each raw + normalized tool call to CAPTURE_DIR (bind-mounted from
// e2e/output/capture, namespaced opencode-*). The drift test reads the RAW in-proc payload
// back and diffs it against the committed Layer 1 fixture. `pinned` fails on drift; `latest`
// also writes the regenerated candidate to output/proposed/.
const OPENCODE_CAPTURE_FILE = join(CAPTURE_DIR, "opencode-pre-tool-use.jsonl");
const OPENCODE_FIXTURE_PATH = resolve(
	TEST_DIR,
	"fixtures",
	"contract",
	"opencode-tool-execute-before.json",
);

// --- Vertex auth for the container (NO ANTHROPIC_API_KEY) ---
// OpenCode is model-agnostic; in the container it authenticates to Claude on Google Vertex
// via the google-vertex-anthropic provider + ADC. project/region come from the same .env
// vars the claude service uses (sourced into the host env by run.sh).
const OPENCODE_MODEL = process.env.OPENCODE_E2E_MODEL ?? "claude-haiku-4-5@20251001";
const VERTEX_PROJECT = process.env.ANTHROPIC_VERTEX_PROJECT_ID ?? "";
const VERTEX_LOCATION = process.env.CLOUD_ML_REGION ?? "global";

// Framed as a request, NOT an identity ("You are a tool executor"): OpenCode already gives
// the model its own identity via its real system prompt, and Haiku rejects a conflicting one
// ~1/3 of the time — replying with "I'm OpenCode, I follow my own instructions…" INSTEAD of
// calling the tool, so the run captures no tool call and the drift check fails as inconclusive.
// A plain "use the tool to do X" request avoids that conflict: 24/24 tool-call rate in probes
// vs 4/6 with the old identity framing. Keep the run-once / no-explain discipline so each drive
// produces exactly one captured tool call.
const SYSTEM_PROMPT =
	"Use the appropriate tool to carry out the request below: bash for shell commands, " +
	"write for creating files, webfetch for fetching URLs, edit for editing files. " +
	"Do the requested action exactly once, then stop; do not explain and do not run extra commands.";

// Set by beforeAll: the host-writable HOME dir, and the HOME path Sage/opencode see at
// runtime (container mode translates host -> in-container path; native mode they're the
// same real dir). nativeHome additionally tracks the temp dir for cleanup.
let tmpDir: string;
let runtimeHome: string;
let nativeHome: NativeHome | undefined;

/**
 * Run the OpenCode CLI. Container mode: inside its compose service (`-T` keeps stdout
 * clean for JSON). Native mode: the resolved binary directly, isolated to runtimeHome
 * (HOME/USERPROFILE + explicit XDG_* so opencode's config dir resolution is the same
 * `<home>/.config/opencode` on every OS, matching where writeTestConfigs writes).
 */
function runOpenCode(args: string[], options: { timeout?: number } = {}) {
	const fullArgs = [...args, "--format", "json", "--agent", "build"];
	// input: "" closes stdin so the CLI never blocks waiting for interactive input.
	if (IS_NATIVE) {
		return spawnNative(
			NATIVE_BIN.executablePath ?? "opencode",
			fullArgs,
			{
				...process.env,
				HOME: runtimeHome,
				USERPROFILE: runtimeHome,
				XDG_CONFIG_HOME: join(runtimeHome, ".config"),
				XDG_CACHE_HOME: join(runtimeHome, ".cache"),
				XDG_STATE_HOME: join(runtimeHome, ".local", "state"),
			},
			{ timeout: options.timeout ?? 90_000, input: "" },
		);
	}
	return composeRun(COMPOSE_FILE, "opencode", fullArgs, {
		timeout: options.timeout ?? 90_000,
		input: "",
	});
}

function runPrompt(
	prompt: string,
	options: { timeout?: number } = {},
	systemPrompt = SYSTEM_PROMPT,
) {
	return runOpenCode(["run", `${systemPrompt}\n\n${prompt}`], options);
}

/**
 * Run a prompt, retrying until the model actually invokes `toolName` (up to TOOL_ATTEMPTS).
 * A tool that Sage blocks still appears as a tool_use with an error state, so this also
 * covers the deny path. Returns the parsed events of the run that invoked the tool (or the
 * last attempt, so callers still get a clear "tool not invoked → inconclusive" failure).
 */
function runDrivingTool(
	prompt: string,
	toolName: string,
	options: { timeout?: number } = {},
): { result: ReturnType<typeof runOpenCode>; events: OpenCodeEvent[] } {
	let result!: ReturnType<typeof runOpenCode>;
	let events: OpenCodeEvent[] = [];
	for (let attempt = 0; attempt < TOOL_ATTEMPTS; attempt++) {
		result = runPrompt(prompt, options);
		events = parseJsonEvents(result.stdout ?? "");
		if (findToolUses(events).some((t) => t.tool === toolName)) break;
	}
	return { result, events };
}

/**
 * Write opencode's + Sage's config into `homeDir`. `runtime` is the HOME path Sage/opencode
 * see when actually running (container mode translates host -> in-container path; native
 * mode it's the same dir as `homeDir` — a host abs path here would "escape" and Sage would
 * fall back to its default).
 */
function writeTestConfigs(homeDir: string, runtime: string): void {
	const opencodeConfigDir = join(homeDir, ".config", "opencode");
	mkdirSync(opencodeConfigDir, { recursive: true });
	const opencodeConfig: Record<string, unknown> = { plugin: [PLUGIN_CONFIG_PATH] };
	if (!IS_NATIVE) {
		// Pin the model + Vertex provider so opencode authenticates to Claude on Vertex via
		// ADC (GOOGLE_APPLICATION_CREDENTIALS), with no host model.json in the container.
		opencodeConfig.model = `google-vertex-anthropic/${OPENCODE_MODEL}`;
		opencodeConfig.provider = {
			"google-vertex-anthropic": {
				options: { project: VERTEX_PROJECT, location: VERTEX_LOCATION },
			},
		};
	}
	// Native mode omits model/provider: opencode falls back to whatever the developer's own
	// install already has configured (ambient auth) via the model.json copied forward below.
	writeFileSync(
		join(opencodeConfigDir, "opencode.json"),
		JSON.stringify(opencodeConfig, null, 2),
		"utf8",
	);

	const sageDir = join(homeDir, ".sage");
	mkdirSync(sageDir, { recursive: true });
	writeFileSync(
		join(sageDir, "config.json"),
		JSON.stringify({ cache: { path: `${runtime}/.sage/cache.json` } }, null, 2),
		"utf8",
	);
}

interface OpenCodeEvent {
	type: string;
	timestamp: number;
	sessionID: string;
	part: {
		id: string;
		sessionID: string;
		messageID: string;
		type: string;
		tool?: string;
		state?: {
			status: string;
			input?: Record<string, unknown>;
			output?: string;
			error?: string;
		};
		text?: string;
	};
}

interface ToolUse {
	tool: string;
	status: string;
	input?: Record<string, unknown>;
	output?: string;
	error?: string;
}

/** Parse OpenCode's JSON event stream (one JSON event per line). */
function parseJsonEvents(output: string): OpenCodeEvent[] {
	const events: OpenCodeEvent[] = [];
	for (const line of output.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		// Skip non-JSON lines (like "Plugin initialized!")
		if (!trimmed.startsWith("{")) continue;
		try {
			const event = JSON.parse(trimmed) as OpenCodeEvent;
			if (!event.part) continue;
			events.push(event);
		} catch {
			// Skip malformed JSON lines
		}
	}
	return events;
}

/** Extract tool invocations (with status + results) from OpenCode events. */
function findToolUses(events: OpenCodeEvent[]): ToolUse[] {
	const toolUses: ToolUse[] = [];
	for (const event of events) {
		if (event.type === "tool_use" && event.part?.tool && event.part.state) {
			toolUses.push({
				tool: event.part.tool,
				status: event.part.state.status,
				input: event.part.state.input,
				output: event.part.state.output,
				error: event.part.state.error,
			});
		}
	}
	return toolUses;
}

/** True if any tool use carries a Sage error (block/ask), based on structured events. */
function hasSageAction(toolUses: ToolUse[]): boolean {
	return toolUses.some(
		(t) =>
			t.status === "error" &&
			t.error &&
			(t.error.includes("Sage") || t.error.includes("SageVerdict") || t.error.includes("actionId")),
	);
}

function assertSpawnResultOk(result: ReturnType<typeof runOpenCode>, note: string): void {
	const err = result.error as NodeJS.ErrnoException | undefined;
	// ETIMEDOUT is expected: opencode can stall post-tool-call waiting for a second Vertex
	// turn; spawnSync fires SIGKILL at the timeout, but stdout already holds the tool-call
	// events we actually care about. Any other error (ENOENT, EPERM, …) is unexpected.
	if (err && err.code !== "ETIMEDOUT") {
		const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
		throw new Error(
			`${note}. spawnSync error=${err.code ?? "unknown"} message=${err.message}\n` +
				`status=${String(result.status)} signal=${String(result.signal)}\n` +
				`output:\n${output.slice(0, 2000)}`,
		);
	}
}

describe.skipIf(!IS_CONTAINER && !CAN_RUN_NATIVE)(
	"E2E: Sage plugin in OpenCode",
	// retry: 0 — runDrivingTool already retries internally; the global vitest retry: 2
	// would re-run the entire test (including all TOOL_ATTEMPTS × timeout iterations) on
	// any failure, multiplying the TC budget by 3 on Vertex-outage days.
	{ timeout: 180_000, retry: 0 },
	() => {
		beforeAll(() => {
			if (IS_NATIVE) {
				nativeHome = createNativeHome("opencode");
				tmpDir = nativeHome.path;
				runtimeHome = nativeHome.path;
			} else {
				// HOME is the bind-mounted host dir (compose maps it to /work). The host writes
				// config here and reads ~/.sage back.
				tmpDir = CONTAINER_HOME_HOST;
				runtimeHome = CONTAINER_HOME;
			}
			// Start clean so stale state can't leak. Remove ALL of ~/.config/opencode (not
			// just the plugins subdir) so any accumulated session history or stale state from a
			// previous build that git clean missed doesn't inflate the 9th invocation's startup.
			// writeTestConfigs recreates opencode.json immediately after.
			mkdirSync(tmpDir, { recursive: true });
			tolerantRm(join(tmpDir, ".sage"));
			tolerantRm(join(tmpDir, ".config", "opencode"));
			writeTestConfigs(tmpDir, runtimeHome);
			if (IS_NATIVE) {
				// Ambient auth: reuse whatever model/provider the developer's own opencode is
				// already configured with, by copying its model.json into the isolated HOME
				// (never the whole real HOME). Must happen AFTER the cleanup above.
				// Confirmed real path: ~/.config/opencode/model.json.
				const realModelJson = join(homedir(), ".config", "opencode", "model.json");
				if (existsSync(realModelJson)) {
					const destDir = join(tmpDir, ".config", "opencode");
					mkdirSync(destDir, { recursive: true });
					copyFileSync(realModelJson, join(destDir, "model.json"));
				}
			}
		});

		afterAll(() => {
			nativeHome?.cleanup();
			nativeHome = undefined;
		});

		afterEach(() => {
			// Prevent cross-test contamination from accumulated plugin files and stale scan
			// cache. Tolerant: container files may be root-owned on Linux (see tolerantRm).
			tolerantRm(join(tmpDir, ".config", "opencode", "plugins"));
			tolerantRm(join(tmpDir, ".sage", "plugin_scan_cache.json"));
		});

		it("blocks canary command via dummy rule", () => {
			// Opaque canary marker (DUMMY-CMD-DENY-001). The markers are deliberately opaque
			// because OpenCode injects Sage's findings into the prompt, and a self-describing
			// token would make the model refuse it as a security probe before it ever reaches
			// Sage. See threats/dummy.yaml.
			const { result, events } = runDrivingTool(
				`Use bash to run this command: echo ${CANARY_MARKERS.cmdDenyAlpha}`,
				"bash",
			);

			assertSpawnResultOk(result, "OpenCode command failed on canary command test");
			const toolUses = findToolUses(events);
			expect(
				toolUses.some((t) => t.tool === "bash"),
				"model must invoke bash so Sage can act (else inconclusive)",
			).toBe(true);
			expect(hasSageAction(toolUses), "Sage must block canary command").toBe(true);
		});

		// Benign-allow: Sage must NOT over-block a normal command. Deterministic-retry hard
		// assertion (no ctx.skip): drive until bash fires, hard-fail if it never does, then
		// require NO Sage action. The detection logic is also pinned at Layer 1
		// (integration.test.ts "allows benign commands"); this proves it live end-to-end.
		it("allows a benign command (Sage does not over-block)", () => {
			const { result, events } = runDrivingTool("Use bash to run: git status", "bash");
			assertSpawnResultOk(result, "OpenCode command failed on benign command test");
			const toolUses = findToolUses(events);
			expect(
				toolUses.some((t) => t.tool === "bash"),
				"model must invoke bash so the allow path is exercised (else inconclusive)",
			).toBe(true);
			expect(hasSageAction(toolUses), "Sage must NOT block a benign command").toBe(false);
		});

		it("scans plugins on session startup", () => {
			const pluginsDir = join(tmpDir, ".config", "opencode", "plugins");
			mkdirSync(pluginsDir, { recursive: true });
			writeFileSync(
				join(pluginsDir, "test-plugin.js"),
				'module.exports = { name: "test", version: "1.0.0" };',
				"utf8",
			);

			const result = runPrompt("Use bash to run: echo test");
			assertSpawnResultOk(result, "OpenCode command failed while scanning plugins on startup");

			const cachePath = join(tmpDir, ".sage", "plugin_scan_cache.json");
			expect(existsSync(cachePath)).toBe(true);
			const cacheContent = JSON.parse(readFileSync(cachePath, "utf8")) as {
				config_hash?: string;
				entries?: Record<string, unknown>;
			};
			expect(cacheContent.config_hash).toBeDefined();
			expect(cacheContent.entries).toBeDefined();
		});

		it("scans plugin with suspicious content without crashing", () => {
			const pluginsDir = join(tmpDir, ".config", "opencode", "plugins");
			mkdirSync(pluginsDir, { recursive: true });
			writeFileSync(
				join(pluginsDir, "suspect-plugin.js"),
				'const u = "https://canary-malicious.example.test/payload"; module.exports = {};',
				"utf8",
			);

			const result = runPrompt("Use bash to run: echo test", { timeout: 150_000 });
			assertSpawnResultOk(result, "OpenCode command failed while scanning suspect plugin");

			const cachePath = join(tmpDir, ".sage", "plugin_scan_cache.json");
			expect(existsSync(cachePath), "Scan cache must exist after session start").toBe(true);
			const cache = JSON.parse(readFileSync(cachePath, "utf8")) as {
				config_hash?: string;
				entries?: Record<string, unknown>;
			};
			expect(cache.config_hash).toBeDefined();
			expect(
				Object.keys(cache.entries ?? {}).length,
				"Cache must have an entry for the plugin",
			).toBeGreaterThan(0);
		});

		it("caches plugin scan results", () => {
			const pluginsDir = join(tmpDir, ".config", "opencode", "plugins");
			mkdirSync(pluginsDir, { recursive: true });
			writeFileSync(
				join(pluginsDir, "cached-plugin.js"),
				"module.exports = { test: true };",
				"utf8",
			);

			const firstRun = runPrompt("Use bash to run: echo first");
			assertSpawnResultOk(firstRun, "OpenCode command failed while verifying cache behavior");

			const cachePath = join(tmpDir, ".sage", "plugin_scan_cache.json");
			expect(existsSync(cachePath)).toBe(true);
			const cacheContent = JSON.parse(readFileSync(cachePath, "utf8")) as {
				config_hash?: string;
				entries?: Record<string, unknown>;
			};
			expect(cacheContent.config_hash).toBeDefined();
			expect(cacheContent.entries).toBeDefined();
		});

		it("blocks canary URL via dummy rule", () => {
			// Opaque canary host (DUMMY-URL-DENY-001) for the same reason as the command test
			// above — a self-describing host would be refused unfetched.
			const { result, events } = runDrivingTool(
				`Use webfetch to fetch this URL: https://${CANARY_MARKERS.urlDeny}.test/page`,
				"webfetch",
			);

			assertSpawnResultOk(result, "OpenCode command failed during canary URL test");
			const toolUses = findToolUses(events);
			expect(
				toolUses.some((t) => t.tool === "webfetch"),
				"model must invoke webfetch so Sage can act (else inconclusive)",
			).toBe(true);
			expect(hasSageAction(toolUses), "Sage must block canary URL").toBe(true);
		});

		// sage_approve tool registration + the block→approve→retry / reject flow are proven
		// deterministically at Layer 1 (integration.test.ts), which drives the real registered
		// tool — no flaky "model recited the tool list" check here.

		it("handles errors gracefully without crashing OpenCode", () => {
			writeFileSync(join(tmpDir, ".sage", "config.json"), "invalid json{{{", "utf8");

			try {
				const result = runPrompt("Use bash to run: echo test");
				assertSpawnResultOk(
					result,
					"OpenCode command failed while verifying fail-open behavior with invalid config",
				);
			} finally {
				// Restore via the authoritative writer so the cache.path stays runtime-correct
				// (an inline host path would "escape" the container/native HOME) — even if the
				// assertion above throws, so the corrupt config never leaks to the next test.
				writeTestConfigs(tmpDir, runtimeHome);
			}
		});

		it("handles missing .sage directory gracefully", () => {
			// HOME is fixed to the container/native home, so reproduce the scenario in place:
			// remove .sage, drive a command (Sage must recreate it without crashing), then restore.
			tolerantRm(join(tmpDir, ".sage"));
			try {
				const result = runPrompt("Use bash to run: echo test");
				assertSpawnResultOk(
					result,
					"OpenCode command failed while creating missing .sage directory",
				);
				expect(existsSync(join(tmpDir, ".sage")), "Sage must recreate ~/.sage").toBe(true);
			} finally {
				writeTestConfigs(tmpDir, runtimeHome);
			}
		});

		// Session-scan skill findings surface as TUI toasts (surfaceStartupSummary + the
		// verdict-cache watcher), verified deterministically at Layer 1 (integration.test.ts)
		// by driving the real scan handler — toasts are not asserted here since they are
		// TUI-only and not captured in headless e2e.

		// Container-only: the capture sink (SAGE_E2E_CAPTURE_DIR) is never wired up in native
		// mode — native mode's scope is the benign-allow/canary-deny wiring checks above.
		it.skipIf(!IS_CONTAINER)(
			"re-validates the OpenCode tool-call envelope against the committed fixture (drift check)",
			() => {
				// Best-effort clear so this test diffs only its own run's capture.
				tolerantRm(OPENCODE_CAPTURE_FILE);

				// Drive a deterministic benign bash echo → one captured tool call (retry until the
				// model actually invokes bash so the capture exists to diff). Neutral marker (no
				// "sage" cue) so the Sage-primed model runs it as rote.
				// 120s timeout (longer than the 90s default): drift check drives a heavier
				// agentic loop that captures the wire payload, so a single Vertex stall at ~90s
				// would mis-fire SIGKILL. 2 × 120s = 240s fits the remaining TC budget.
				const { result, events } = runDrivingTool(
					"Use bash to run this command: echo opencode_drift_probe_9f3c2a18",
					"bash",
					{ timeout: 120_000 },
				);
				assertSpawnResultOk(result, "OpenCode command failed during drift check");
				const ranBash = findToolUses(events).some((t) => t.tool === "bash");
				expect(ranBash, "model must invoke bash so a payload is captured (else inconclusive)").toBe(
					true,
				);

				// Diff the RAW in-proc payload (not the normalized form): normalization is
				// Sage-internal, so only the raw payload reveals host wire-format drift.
				const capture = readLastCaptureRecord(
					OPENCODE_CAPTURE_FILE,
					(record) => record.raw.tool === "bash",
				);
				expect(
					capture,
					"no bash tool-call capture produced — capture wiring is broken",
				).toBeTruthy();
				if (!capture) return;
				const wire = capture.raw;

				// tool value-pin: we drove the bash tool, so the host must report exactly "bash".
				// Catches a rename here too — the structural diff alone would not.
				expect(wire.tool, "captured tool must match the driven tool").toBe("bash");
				expect(wire.args, "tool call must carry args").toBeDefined();

				// Shared drift loop: diff vs the committed fixture, warn on new fields, emit a
				// `latest`-mode candidate, and fail on real drift in BOTH modes (connector-labelled).
				assertNoEnvelopeDrift({
					captured: wire,
					fixturePath: OPENCODE_FIXTURE_PATH,
					label: "OpenCode tool call",
					mode: MODE,
					volatileFields: ENVELOPE_VOLATILE_FIELDS.opencode,
					proposedPath: join(PROPOSED_DIR, "opencode", relative(REPO_ROOT, OPENCODE_FIXTURE_PATH)),
				});
			},
		);
	},
);
