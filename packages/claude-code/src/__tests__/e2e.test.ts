/**
 * Tier 3 E2E (Layer 2): Sage plugin running inside the real Claude CLI, in a container
 * or (SAGE_E2E_RUNNER=native) directly against a locally-installed `claude` binary.
 *
 * Excluded from `pnpm test` via vitest config. Run with:
 *
 *   e2e/run.sh claude                          # builds the agent image, drives it via docker compose
 *   SAGE_E2E_RUNNER=native pnpm test:e2e:claude  # drives an installed `claude` binary directly
 *
 * Container mode: `claude` runs inside the pinned agent image against the bind-mounted
 * current-branch Sage. Native mode: `claude` runs directly against the current-branch
 * Sage repo, in an isolated temp HOME, reusing whatever auth the developer's own `claude`
 * install already has (ambient — no Vertex/.env needed). Both modes share the same
 * assertions; the drift-diff and tool-catalog checks stay container-only (never existed
 * natively, no capture sink is wired up outside a container). See e2e/README.md.
 *
 * Prerequisites: container mode needs Docker + e2e/.env; native mode needs `claude`
 * installed and already authenticated. ~$0.03 per test (Haiku model).
 */

import { copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve } from "node:path";
import {
	assertNoEnvelopeDrift,
	CANARY_MARKERS,
	type CaptureRecord,
	composeRun,
	createNativeHome,
	type EnvelopeDiffOptions,
	e2ePaths,
	IS_CONTAINER,
	IS_NATIVE,
	E2E_MODE as MODE,
	type NativeHome,
	readLastCaptureRecord,
	resolveExecutable,
	spawnNative,
} from "@gendigital/sage-core/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { envelopePath, loadToolNames, VOLATILE_ENVELOPE_FIELDS } from "./contract-fixtures.js";

const PLUGIN_ROOT = resolve(__dirname, "..", "..", "..", "..");

// --- Invocation ---
// The container is only the agent sandbox; the test logic (parsing, assertions,
// JUnit) stays here on the host. claude runs through docker compose against the
// bind-mounted Sage; paths are the container-side mounts.
const {
	composeFile: COMPOSE_FILE,
	captureDir: CAPTURE_DIR,
	proposedDir: PROPOSED_DIR,
} = e2ePaths(PLUGIN_ROOT);
const CONTAINER_PLUGIN_DIR = "/sage"; // repo root, bind-mounted ro (see e2e/compose.yml)
const CONTAINER_ADD_DIR = "/work"; // tmpfs workspace + HOME inside the container

// --- Native mode (SAGE_E2E_RUNNER=native) ---
// Headless CLIs self-register on PATH via their installers, so resolution is just an
// env override or the bare command name (no LOCALAPPDATA-style guessing needed).
const NATIVE_BIN = IS_NATIVE
	? resolveExecutable(["SAGE_CLAUDE_PATH"], ["claude"])
	: { reason: "not native mode" };
const CAN_RUN_NATIVE = IS_NATIVE && Boolean(NATIVE_BIN.executablePath);
if (IS_NATIVE && !CAN_RUN_NATIVE) {
	console.warn(`Claude Code E2E (native) skipped: ${NATIVE_BIN.reason}`);
}
// The standard Claude Code OAuth-login credential file location. Copied forward into the
// isolated temp HOME (never the whole real HOME) so native mode reuses the developer's
// ambient login without touching their real ~/.claude. If this file doesn't exist, auth
// almost certainly lives in the OS keychain, keyed in a way that does NOT survive a HOME
// override — in that case runClaude falls back to the real HOME (below), trading
// isolation for a working login, same as the pre-container-refactor native behavior.
const CLAUDE_CREDENTIALS_FILE = ".credentials.json";

// Model selection. We pass the friendly "haiku" alias; on Vertex AI (where the public
// API is unreachable) the aliases don't resolve on their own, so e2e/.env overrides
// what they map to via ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL (mirroring the CI
// config). The backend and auth are chosen entirely by claude's own env vars
// passed through compose env_file (CLAUDE_CODE_USE_VERTEX + project/region; ADC from the
// metadata server on GCE, or a mounted ADC file locally). SAGE_E2E_MODEL remains an
// optional override (e.g. to pin a full Vertex model id directly).
const MODEL = process.env.SAGE_E2E_MODEL ?? "haiku";

// --- Payload capture + fixture drift diff ---
// In container mode the in-container Sage MCP server captures each raw + normalized
// hook payload to CAPTURE_DIR (bind-mounted from e2e/output/capture). The drift
// test reads those back and diffs them against the committed Layer 1 fixtures.
// `pinned` (default) fails on drift; `latest` also writes the regenerated fixture
// to e2e/output/proposed/ for review (the bump-PR step itself is CI-only).

// Deterministic benign Bash invocation reused by the allow-path and drift tests.
const BENIGN_BASH_PROMPT = "Use the Bash tool to run this command: echo hello_e2e_test";

// --- Helpers ---

interface ToolResult {
	toolName: string;
	toolInput: Record<string, unknown>;
	isError: boolean;
	resultContent: string;
}

const DEFAULT_SYSTEM_PROMPT =
	"You are a CLI tool executor. Always use the appropriate tool to fulfill requests. " +
	"Use Bash for shell commands, Write for creating/writing files, WebFetch for fetching " +
	"URLs, Edit for editing files. Execute immediately without explaining or asking for " +
	"confirmation. Never respond with plain text when a tool can be used instead.";

interface RunOpts {
	systemPrompt?: string;
	maxTurns?: number;
	/** Tool permission allowlist; `null` omits the flag. Default: "WebFetch,Read". */
	allowedTools?: string | null;
	/** Tool permission denylist; `null` omits the flag. Default: "mcp__*". */
	disallowedTools?: string | null;
	/** Advertised tool set (`--tools`); `null` omits the flag (host default). */
	tools?: string | null;
}

// Set by beforeAll in native mode: an isolated temp HOME (only when a copyable credentials
// file was found — otherwise cleanup has nothing to do), and the HOME path actually used
// for the spawn — isolated temp dir when isolation is possible, else the real homedir()
// (keychain-based sessions can't be relocated; see CLAUDE_CREDENTIALS_FILE above).
let nativeHome: NativeHome | undefined;
let nativeHomePath: string | undefined;

function runClaude(prompt: string, opts: RunOpts = {}): { messages: Record<string, unknown>[] } {
	const systemPrompt = opts.systemPrompt ?? DEFAULT_SYSTEM_PROMPT;
	const maxTurns = opts.maxTurns ?? 3;
	const allowedTools = opts.allowedTools === undefined ? "WebFetch,Read" : opts.allowedTools;
	const disallowedTools = opts.disallowedTools === undefined ? "mcp__*" : opts.disallowedTools;
	// Native mode points at the real repo root / the effective HOME instead of the
	// container's bind-mount paths.
	const pluginDir = IS_NATIVE ? PLUGIN_ROOT : CONTAINER_PLUGIN_DIR;
	const addDir = IS_NATIVE ? (nativeHomePath ?? PLUGIN_ROOT) : CONTAINER_ADD_DIR;

	const claudeArgs = [
		"--print",
		"--output-format",
		"stream-json",
		"--verbose",
		"--no-session-persistence",
		"--max-turns",
		String(maxTurns),
		"--model",
		MODEL,
		"--plugin-dir",
		pluginDir,
		...(allowedTools ? ["--allowedTools", allowedTools] : []),
		...(disallowedTools ? ["--disallowedTools", disallowedTools] : []),
		...(opts.tools ? ["--tools", opts.tools] : []),
		"--add-dir",
		addDir,
		"--system-prompt",
		systemPrompt,
		"-p",
		prompt,
	];

	// Container mode: the entrypoint is `claude`, so the flags pass straight through.
	// Native mode: spawn the resolved binary directly, HOME/USERPROFILE set to
	// nativeHomePath (isolated temp dir, or the real HOME as a keychain-auth fallback).
	const result = IS_NATIVE
		? spawnNative(
				NATIVE_BIN.executablePath ?? "claude",
				claudeArgs,
				{ ...process.env, HOME: nativeHomePath, USERPROFILE: nativeHomePath },
				{ timeout: 170_000 },
			)
		: composeRun(COMPOSE_FILE, "claude", claudeArgs, { timeout: 170_000 });
	const stdout = result.stdout ?? "";
	if (result.status !== 0) {
		console.error("claude error:", stdout, result.stderr ?? "", result.error ?? "");
	}

	const messages: Record<string, unknown>[] = [];
	for (const line of stdout.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			messages.push(JSON.parse(trimmed) as Record<string, unknown>);
		} catch {
			// skip non-JSON lines
		}
	}

	if (IS_NATIVE) {
		assertPluginDirNotLockedByManagedSettings(messages);
	}

	return { messages };
}

/**
 * Native mode only: if `claude` already has a "sage" plugin installed from the
 * marketplace (very likely on a Sage developer's own machine) AND managed/enterprise
 * settings pin the plugin list, `--plugin-dir` is silently ignored — the run loads the
 * cached marketplace version instead of the current branch. That would make every
 * assertion below meaningless (or worse, falsely reassuring on the allow-path tests), so
 * fail loudly here rather than let a stale-plugin run pass or fail for the wrong reason.
 */
function assertPluginDirNotLockedByManagedSettings(messages: Record<string, unknown>[]): void {
	const init = messages.find((m) => m.type === "system" && m.subtype === "init");
	const pluginErrors = (init as Record<string, unknown> | undefined)?.plugin_errors as
		| Array<Record<string, unknown>>
		| undefined;
	const locked = pluginErrors?.find(
		(e) =>
			String(e.plugin ?? "").includes("sage") &&
			String(e.message ?? "").includes("locked by managed settings"),
	);
	if (locked) {
		throw new Error(
			"claude ignored --plugin-dir for Sage: it's already installed from the marketplace " +
				"and managed/enterprise settings pin the plugin list, so this run loaded the cached " +
				`marketplace version instead of the current branch (${JSON.stringify(locked)}). This ` +
				"is a Claude Code enterprise-policy limitation, not something native-mode E2E can " +
				"work around — see e2e/README.md's native-mode section.",
		);
	}
}

function findToolResults(messages: Record<string, unknown>[]): ToolResult[] {
	const results: ToolResult[] = [];

	// Build map of tool_use_id -> (name, input) from assistant messages
	const toolCalls = new Map<string, { name: string; input: Record<string, unknown> }>();
	for (const msg of messages) {
		if (msg.type !== "assistant") continue;
		const inner = (msg.message ?? msg) as Record<string, unknown>;
		const content = inner.content as Array<Record<string, unknown>> | undefined;
		if (!content) continue;
		for (const block of content) {
			if (block.type === "tool_use") {
				toolCalls.set(block.id as string, {
					name: block.name as string,
					input: (block.input as Record<string, unknown>) ?? {},
				});
			}
		}
	}

	// Match tool_results from user messages
	for (const msg of messages) {
		if (msg.type !== "user") continue;
		const inner = (msg.message ?? msg) as Record<string, unknown>;
		const content = inner.content as Array<Record<string, unknown>> | undefined;
		if (!content) continue;
		for (const block of content) {
			if (block.type !== "tool_result") continue;
			const toolUseId = block.tool_use_id as string;
			const call = toolCalls.get(toolUseId);
			if (!call) continue;

			const isError = (block.is_error as boolean) ?? false;
			let resultContent = "";
			const blockContent = block.content;
			if (typeof blockContent === "string") {
				resultContent = blockContent;
			} else if (Array.isArray(blockContent)) {
				const parts: string[] = [];
				for (const part of blockContent) {
					if (typeof part === "string") parts.push(part);
					else if (
						typeof part === "object" &&
						part !== null &&
						(part as Record<string, unknown>).type === "text"
					) {
						parts.push((part as Record<string, unknown>).text as string);
					}
				}
				resultContent = parts.join("\n");
			}

			results.push({
				toolName: call.name,
				toolInput: call.input,
				isError,
				resultContent,
			});
		}
	}

	return results;
}

// --- Capture-diff helpers ---

// Claude Code normalizes a plain-string tool_response to `tool_output`; both are
// the one host "response slot", whose type is tool-dependent (Read→object,
// Bash→string), so compare its presence not its type. The structural envelope
// diff itself is shared across connectors in core.
const CLAUDE_DIFF_OPTIONS: EnvelopeDiffOptions = {
	foldKeys: { tool_output: "tool_response" },
	presenceOnlyKeys: ["tool_response"],
};

/** Last captured record for an event whose normalized tool_name matches, or null. */
function lastCapture(event: "pre" | "post", toolName: string): CaptureRecord | null {
	return readLastCaptureRecord(
		join(CAPTURE_DIR, `${event}-tool-use.jsonl`),
		(record) => record.normalized?.tool_name === toolName,
	);
}

// --- Tests ---

describe.skipIf(!IS_CONTAINER && !CAN_RUN_NATIVE)(
	"E2E: Sage plugin in Claude CLI",
	{ timeout: 180_000 },
	() => {
		beforeAll(() => {
			if (!IS_NATIVE) return;
			const realCredentials = join(homedir(), ".claude", CLAUDE_CREDENTIALS_FILE);
			if (existsSync(realCredentials)) {
				nativeHome = createNativeHome("claude");
				nativeHomePath = nativeHome.path;
				const destDir = join(nativeHomePath, ".claude");
				mkdirSync(destDir, { recursive: true });
				copyFileSync(realCredentials, join(destDir, CLAUDE_CREDENTIALS_FILE));
			} else {
				// No portable credentials file — auth is almost certainly in the OS keychain,
				// which isolating HOME would break. Run against the real HOME instead of
				// failing to authenticate.
				console.warn(
					"Claude Code E2E (native): no ~/.claude/.credentials.json found — running " +
						"against the real HOME instead of an isolated one (keychain-based sessions " +
						"can't be relocated). Prefer env-var auth (ANTHROPIC_API_KEY/Vertex) for " +
						"full isolation.",
				);
				nativeHomePath = homedir();
			}
		});

		afterAll(() => {
			nativeHome?.cleanup();
			nativeHome = undefined;
			nativeHomePath = undefined;
		});

		it("loads plugin and allows benign command", (_ctx) => {
			const { messages } = runClaude(BENIGN_BASH_PROMPT);
			const results = findToolResults(messages);
			const bash = results.filter((r) => r.toolName === "Bash");

			expect(bash.length, "Model must use Bash tool at least once").toBeGreaterThanOrEqual(1);
			const match = bash.find((b) => !b.isError && b.resultContent?.includes("hello_e2e_test"));
			expect(match, "At least one Bash result must contain hello_e2e_test").toBeTruthy();
		});

		it("session-start hook fires without crashing", () => {
			const { messages } = runClaude("Say 'hello'");
			expect(messages.length).toBeGreaterThan(0);
		});

		// Note: there is deliberately no "model recites the security-awareness skill" E2E
		// case. That the skill is shipped + registered with valid frontmatter is covered
		// deterministically at Layer 1 (skill-registration.test.ts, skill-loading.test.ts);
		// that Sage is loaded and functioning live is covered by the deny tests below (they
		// can't pass unless the hooks + plugin:sage:sage MCP server are active). Asserting on
		// the model's free-text reply only added flakiness, not coverage.

		it("blocks canary command via dummy rule", () => {
			const { messages } = runClaude(
				`Use the Bash tool to run this command: echo ${CANARY_MARKERS.cmdDenyAlpha}`,
			);
			const results = findToolResults(messages);
			const bash = results.filter((r) => r.toolName === "Bash");
			expect(bash.length, "Model must attempt Bash tool").toBe(1);
			expect(bash[0].isError).toBe(true);
			expect(bash[0].resultContent).toMatch(/denied|Blocked/i);
		});

		it("blocks canary URL via dummy rule", () => {
			const { messages } = runClaude(
				`Use the WebFetch tool to fetch this URL: https://${CANARY_MARKERS.urlDeny}.test/page and summarize the content`,
			);
			const results = findToolResults(messages);
			const fetches = results.filter((r) => r.toolName === "WebFetch");
			expect(fetches.length, "Model must attempt WebFetch tool").toBe(1);
			expect(fetches[0].isError).toBe(true);
			expect(fetches[0].resultContent).toMatch(/denied|Blocked/i);
		});

		it("blocks canary file path via dummy rule", () => {
			const { messages } = runClaude(
				`Use the Write tool to create a file called ${CANARY_MARKERS.fileDeny}.txt with content 'hello'`,
			);
			const results = findToolResults(messages);
			const writes = results.filter((r) => r.toolName === "Write");
			expect(writes.length, "Model must attempt Write tool").toBe(1);
			expect(writes[0].isError).toBe(true);
			expect(writes[0].resultContent).toMatch(/denied|Blocked/i);
		});

		it("allows benign WebFetch", () => {
			const { messages } = runClaude(
				"Use the WebFetch tool to fetch https://www.google.com and return the page title",
			);
			const results = findToolResults(messages);
			const fetches = results.filter((r) => r.toolName === "WebFetch");

			expect(fetches.length, "Model must use WebFetch tool once").toBe(1);
			// This layer proves Sage's ALLOW path lets a benign fetch through — NOT that the
			// network fetch itself succeeds. The E2E agent runs on a locked-down CI network
			// where arbitrary egress (e.g. google.com) may be firewalled, so a network failure
			// is not a Sage signal and must not fail this test. Assert only that Sage did not
			// block it by checking for the Sage-specific block marker — corporate proxies/firewalls
			// can also return generic "Blocked" text, which would cause false failures with a
			// broad regex.
			expect(fetches[0].resultContent, "Sage must not block a benign WebFetch").not.toMatch(
				/Blocked by Sage/i,
			);
		});

		// Tool-name drift catch (see docs/developer-guide.md — E2E architecture, tool-name drift). Claude
		// Code emits its advertised tool catalog in the system/init message — without
		// the model needing to invoke anything — so this is deterministic given a
		// session start. Every tool name Sage guards (tool-names.json) MUST appear, or
		// Sage has gone blind for it (e.g. a Read -> read rename). The full catalog is
		// intentionally broader than Sage's surface, so unguarded tools only warn.
		// Container-only: never existed natively, and native mode's scope is the
		// benign-allow/canary-deny wiring checks, not drift detection.
		it.skipIf(!IS_CONTAINER)(
			"advertises every guarded tool name in its catalog (drift check)",
			() => {
				const { messages } = runClaude("hi", {
					maxTurns: 1,
					allowedTools: null,
					disallowedTools: null,
					tools: "default", // do not restrict the advertised list
				});

				const init = messages.find((m) => m.type === "system" && m.subtype === "init");
				expect(
					init,
					"claude must emit a system/init message carrying the tool catalog",
				).toBeTruthy();
				const advertised = ((init as Record<string, unknown>)?.tools as string[]) ?? [];
				expect(advertised.length, "init.tools must be a non-empty catalog").toBeGreaterThan(0);

				const { guarded } = loadToolNames();
				const missing = guarded.filter((t) => !advertised.includes(t));
				expect(
					missing,
					`Guarded tool names missing from Claude Code's catalog (drift — Sage is blind for these): ${missing.join(", ")}`,
				).toEqual([]);

				// Informational only: advertised tools Sage does not guard. New entries are
				// candidates to guard, but the catalog is broader by design — do not fail.
				const unguarded = advertised.filter((t) => !guarded.includes(t));
				if (unguarded.length) {
					console.warn(
						`[tool-catalog] advertised but unguarded (triage for new guards): ${unguarded.sort().join(", ")}`,
					);
				}
			},
		);

		// Live drift loop (see e2e/README.md). The in-container Sage MCP
		// server captures the real hook payload it receives; here we diff the captured
		// envelope STRUCTURE against the committed Layer 1 fixture. tool_input contents
		// are model-driven, so we compare the top-level envelope (keys + types) and the
		// encoding contract (tool_input still decodes to an object) — not literal values.
		// A missing/renamed host field or broken encoding fails; a new field warns. We
		// also value-pin tool_name for the driven tool (a complementary tool-name-rename
		// signal alongside the catalog check). Container-only: the capture sink
		// (SAGE_E2E_CAPTURE_DIR) is never wired up in native mode.
		it.skipIf(!IS_CONTAINER)(
			"re-validates the hook envelope against the committed fixture (drift check)",
			() => {
				// Best-effort clear so this test diffs its own run. Read-back is by
				// tool_name + last-wins, so stale entries are harmless — and on Linux the
				// container writes root-owned files a non-root host can't unlink (EPERM,
				// which `force` does NOT suppress), so swallow any failure.
				mkdirSync(CAPTURE_DIR, { recursive: true });
				for (const f of ["pre-tool-use.jsonl", "post-tool-use.jsonl"]) {
					try {
						rmSync(join(CAPTURE_DIR, f), { force: true });
					} catch {
						// stale entries are tolerated by the last-wins read-back below
					}
				}

				// Drive a deterministic benign Bash call → one PreToolUse + PostToolUse.
				const { messages } = runClaude(BENIGN_BASH_PROMPT);
				const ranBash = findToolResults(messages).some((r) => r.toolName === "Bash");
				expect(ranBash, "model must invoke Bash so a payload is captured (else inconclusive)").toBe(
					true,
				);

				const pre = lastCapture("pre", "Bash");
				const post = lastCapture("post", "Bash");
				expect(pre, "no PreToolUse(Bash) capture produced — capture wiring is broken").toBeTruthy();
				expect(
					post,
					"no PostToolUse(Bash) capture produced — capture wiring is broken",
				).toBeTruthy();
				if (!pre || !post) return;

				// Encoding contract: the JSON-string tool_input must still decode to an object.
				expect(
					typeof pre.normalized.tool_input === "object" && pre.normalized.tool_input !== null,
					"PreToolUse tool_input must decode to an object",
				).toBe(true);

				// tool_name value-pin: we asked for Bash, so the host must report Bash, and
				// Bash must be in the guarded set. Catches a Bash -> bash style rename here too.
				const { guarded } = loadToolNames();
				expect(pre.normalized.tool_name, "captured tool_name must match the driven tool").toBe(
					"Bash",
				);
				expect(guarded, "the driven tool must be a guarded name").toContain("Bash");

				// Shared drift loop, run per envelope: diff vs the committed fixture, warn on
				// new fields, emit a `latest`-mode candidate for whatever drifted, and fail on
				// real drift in BOTH modes. Claude folds tool_response→tool_output and treats
				// that slot presence-only, hence CLAUDE_DIFF_OPTIONS.
				assertNoEnvelopeDrift({
					captured: pre.normalized,
					fixturePath: envelopePath("pre-tool-use"),
					label: "PreToolUse",
					mode: MODE,
					volatileFields: VOLATILE_ENVELOPE_FIELDS,
					proposedPath: join(
						PROPOSED_DIR,
						"claude",
						relative(PLUGIN_ROOT, envelopePath("pre-tool-use")),
					),
					diffOptions: CLAUDE_DIFF_OPTIONS,
				});
				assertNoEnvelopeDrift({
					captured: post.normalized,
					fixturePath: envelopePath("post-tool-use"),
					label: "PostToolUse",
					mode: MODE,
					volatileFields: VOLATILE_ENVELOPE_FIELDS,
					proposedPath: join(
						PROPOSED_DIR,
						"claude",
						relative(PLUGIN_ROOT, envelopePath("post-tool-use")),
					),
					diffOptions: CLAUDE_DIFF_OPTIONS,
				});
			},
		);
	},
);
