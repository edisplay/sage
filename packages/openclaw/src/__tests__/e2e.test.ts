/**
 * Tier 3 E2E (Layer 2): Sage plugin running inside a real OpenClaw gateway, in a container.
 *
 * Excluded from `pnpm test` via vitest config. Run with:
 *
 *   e2e/run.sh openclaw         # the suite owns the gateway lifecycle
 *                               # (compose up -d → poll /health → drive over HTTP → down)
 *
 * The suite brings up the pinned OpenClaw image via docker compose against the
 * bind-mounted current-branch Sage, polls /health, drives it over the published HTTP
 * port, and tears it down. The in-process plugin captures each tool call to the shared
 * /capture mount; the drift test diffs the raw payload against the Layer 1 fixture. The
 * suite only runs when SAGE_E2E_RUNNER=container (set by run.sh) — there is no
 * locally-started-gateway path (detection + benign-allow are proven deterministically at
 * Layer 1's e2e-integration.test.ts; this layer proves the live wiring + payload drift).
 *
 * Optional override: OPENCLAW_E2E_MODEL.
 */

import { rmSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	assertNoEnvelopeDrift,
	CANARY_MARKERS,
	createGatewayHarness,
	driveForFreshVerdict,
	ENVELOPE_VOLATILE_FIELDS,
	e2ePaths,
	IS_CONTAINER,
	E2E_MODE as MODE,
	readLastCaptureRecord,
	resolveAuditPath,
	CONTAINER_TOOL_ATTEMPTS as TOOL_ATTEMPTS,
} from "@gendigital/sage-core/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));

// --- Invocation ---
const REPO_ROOT = resolve(TEST_DIR, "..", "..", "..", "..");
const {
	composeFile: COMPOSE_FILE,
	captureDir: CAPTURE_DIR,
	proposedDir: PROPOSED_DIR,
} = e2ePaths(REPO_ROOT);

// Sage's audit log (written by core's logVerdict — runtime_verdict entries). The block
// tests assert against THIS, not the model's reply text: Gemini frequently narrates
// "done"/"blocked" without it reflecting reality, so the audit log is the only reliable
// signal that a verdict actually fired. HOME=/work is bind-mounted to
// e2e/output/openclaw-home, so the host reads the SAME audit.jsonl the in-container Sage
// wrote (full parity).
const AUDIT_PATH = resolveAuditPath(REPO_ROOT, "openclaw-home", ".sage", "audit.jsonl");

// The suite owns the gateway: the entrypoint enables chat completions and sets the auth
// token. Connect to the published host port (OPENCLAW_HOST_PORT, default 18889) — distinct
// from OpenClaw's default 18789 so it never collides with a local dev gateway.
const HOST = `http://localhost:${process.env.OPENCLAW_HOST_PORT ?? "18889"}`;
const TOKEN = process.env.OPENCLAW_GATEWAY_TOKEN ?? "sage-e2e";
// The OpenAI-compat `model` field is the gateway AGENT target, not the provider model —
// the provider/model (e.g. google-vertex/gemini-…) is configured gateway-side via
// `openclaw models set` in the entrypoint. Send the default agent; allow an override.
const CHAT_MODEL = process.env.OPENCLAW_E2E_MODEL ?? "openclaw";

// --- Drift loop ---
// The in-process plugin captures each raw + normalized before_tool_call to
// CAPTURE_DIR (bind-mounted from e2e/output/capture, namespaced openclaw-*). The
// drift test reads the RAW payload back and diffs it against the Layer 1 fixture.
// `pinned` fails on drift; `latest` also writes the regenerated candidate.
const OPENCLAW_CAPTURE_FILE = join(CAPTURE_DIR, "openclaw-pre-tool-use.jsonl");
const OPENCLAW_FIXTURE_PATH = resolve(
	TEST_DIR,
	"fixtures",
	"contract",
	"openclaw-before-tool-call.json",
);

const SYSTEM_PROMPT =
	"You are a tool executor. Always use the appropriate tool to fulfill requests. " +
	"Use exec for shell commands, write for creating/writing files, web_fetch for fetching " +
	"URLs, edit for editing files. Execute immediately without explaining or asking for " +
	"confirmation. Never respond with plain text when a tool can be used instead.";

// --- Helpers ---

// Shared docker-compose + /health-poll lifecycle (the suite still owns up/down below).
const gateway = createGatewayHarness({
	composeFile: COMPOSE_FILE,
	host: HOST,
	token: TOKEN,
	service: "openclaw",
});

async function chat(prompt: string, systemPrompt = SYSTEM_PROMPT): Promise<string> {
	const response = await fetch(`${HOST}/v1/chat/completions`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: `Bearer ${TOKEN}`,
			"X-OpenClaw-Scopes": "operator.write",
		},
		body: JSON.stringify({
			model: CHAT_MODEL,
			max_tokens: 4096,
			messages: [
				{ role: "system", content: systemPrompt },
				{ role: "user", content: prompt },
			],
		}),
	});

	if (!response.ok) {
		const body = await response.text();
		// The gateway collapses provider/auth failures (e.g. Vertex ADC) into a generic
		// 500; the real error only appears in the container's own logs (debug level via
		// OPENCLAW_LOG_LEVEL in compose.yml). Surface them so CI shows the true cause.
		const logs = gateway.compose(["logs", "--no-color", "--tail", "80", "openclaw"]).stdout ?? "";
		throw new Error(
			`Gateway returned ${response.status}: ${body}\n--- openclaw logs (tail 80) ---\n${logs}`,
		);
	}

	const data = (await response.json()) as {
		choices: Array<{ message: { content: string } }>;
	};

	return data.choices[0]?.message?.content ?? "";
}

// Drive the gateway until Sage records a FRESH deny for `marker`, retrying up to
// TOOL_ATTEMPTS (Gemini-on-Vertex sometimes fabricates "the file was created" as plain
// text without ever emitting the tool). Success = a strict increase in matching deny
// entries (not the reply text), so a non-narrated block still counts and a stale entry
// can't produce a false pass. Hard-fail if no new deny appears after every attempt:
// either the model never invoked the tool (inconclusive) or Sage failed to deny it.
async function expectFreshDeny(prompt: string, marker: string): Promise<void> {
	const { fresh, last } = await driveForFreshVerdict({
		auditPath: AUDIT_PATH,
		decision: "deny",
		marker,
		attempts: TOOL_ATTEMPTS,
		drive: () => chat(prompt),
	});
	if (!fresh) {
		expect.fail(
			`No new Sage 'deny' for "${marker}" after ${TOOL_ATTEMPTS} attempt(s) — the model ` +
				`never invoked the tool, or Sage failed to deny it. Audit: ${AUDIT_PATH}\n` +
				`Last model reply (tail):\n${(last ?? "").slice(-800)}`,
		);
	}
}

// --- Tests ---

describe.skipIf(!IS_CONTAINER)("E2E: Sage plugin in OpenClaw gateway", { timeout: 300_000 }, () => {
	// The hook timeout is separate from the test timeout above (vitest defaults it
	// to 10s); bring-up under emulation + the gateway/model handshake needs longer,
	// so pass explicit hook timeouts as the 2nd arg.
	beforeAll(async () => {
		const up = gateway.compose(["up", "-d", "openclaw"]);
		if (up.status !== 0) {
			throw new Error(`docker compose up failed (${up.status}):\n${up.stderr ?? ""}`);
		}
		// Gateway start + plugin install + first model handshake can take a while.
		await gateway.waitForHealth(240_000);
	}, 300_000);

	afterAll(() => {
		// --remove-orphans also clears a container leaked by a previously aborted run
		// (which would otherwise hold the published port). Surface a failed teardown.
		const down = gateway.compose(["down", "--remove-orphans"]);
		if (down.status !== 0) console.error("compose down failed:", down.stderr);
	}, 60_000);

	// Benign-allow ("Sage does not over-block normal exec/web_fetch/write/read") is
	// proven deterministically at Layer 1 (e2e-integration.test.ts) — no flaky live
	// "model echoed the output" check here; this layer proves the deny wiring + drift.

	it("blocks canary command via dummy rule", async () => {
		await expectFreshDeny(
			`Use exec to run this command: echo ${CANARY_MARKERS.cmdDenyAlpha}`,
			CANARY_MARKERS.cmdDenyAlpha,
		);
	});

	it("blocks canary file path via dummy rule", async () => {
		// Imperative, explicit-path phrasing mirrors the reliable exec/web_fetch
		// prompts. The earlier conversational "create a file called …" wording let
		// Gemini-2.5-flash narrate "done" without emitting the write tool (no audit
		// entry, nothing reached Sage); a concrete absolute path + "Use write to save"
		// coerces the tool call. The dummy rule matches the marker anywhere in the
		// file_path, so the /work prefix doesn't affect detection.
		await expectFreshDeny(
			`Use write to save the text hello to the file /work/${CANARY_MARKERS.fileDeny}.txt`,
			CANARY_MARKERS.fileDeny,
		);
	});

	it("blocks canary URL via dummy rule", async () => {
		await expectFreshDeny(
			`Use web_fetch on https://${CANARY_MARKERS.urlDeny}.test/page`,
			CANARY_MARKERS.urlDeny,
		);
	});

	// Re-validate the before_tool_call payload shape against the committed Layer 1
	// fixture (the live drift loop), reading the bind-mounted capture sink.
	it("re-validates the OpenClaw tool-call envelope against the committed fixture (drift check)", async () => {
		// Clear so this test diffs only its own run's capture (force → no throw if absent).
		rmSync(OPENCLAW_CAPTURE_FILE, { force: true });

		// Drive a deterministic benign exec → one captured tool call. Retry until
		// the model actually invokes exec so a payload exists to diff. Neutral
		// marker (no "sage" cue) so the Sage-primed model runs it as rote.
		let wire: Record<string, unknown> | undefined;
		for (let attempt = 0; attempt < TOOL_ATTEMPTS && !wire; attempt++) {
			await chat("Use exec to run this command: echo openclaw_drift_probe_5b8e1d27");
			const capture = readLastCaptureRecord(
				OPENCLAW_CAPTURE_FILE,
				(record) => record.raw.toolName === "exec",
			);
			if (capture) wire = capture.raw;
		}
		expect(
			wire,
			"model must invoke exec so a payload is captured (else inconclusive)",
		).toBeTruthy();
		if (!wire) return;

		// value-pin: we drove the exec tool, so the host must report exactly
		// "exec". Catches a rename the structural diff alone would not.
		expect(wire.toolName, "captured tool must match the driven tool").toBe("exec");
		expect(wire.params, "tool call must carry params").toBeDefined();

		// Shared drift loop: diff vs the committed fixture, warn on new fields, emit a
		// `latest`-mode candidate, and fail on real drift in BOTH modes (connector-labelled).
		assertNoEnvelopeDrift({
			captured: wire,
			fixturePath: OPENCLAW_FIXTURE_PATH,
			label: "OpenClaw tool call",
			mode: MODE,
			volatileFields: ENVELOPE_VOLATILE_FIELDS.openclaw,
			proposedPath: join(PROPOSED_DIR, "openclaw", relative(REPO_ROOT, OPENCLAW_FIXTURE_PATH)),
		});
	});
});
