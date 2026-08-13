/**
 * Shared loader for the committed host-payload contract fixtures.
 *
 * The fixtures under `fixtures/contract/` are the single source of truth for the
 * canonical Claude Code hook payload (the wire format Claude Code sends to Sage's
 * mcp_tool hooks). Both the wire-format contract test (hooks-config-contract) and
 * the detection integration tests build their inputs from these envelopes, so the
 * canonical shape is defined exactly once. They are also the baseline a future
 * live-capture run diffs against to detect host drift (see e2e/README.md).
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export type HookEnvelope = Record<string, unknown>;

const FIXTURE_DIR = resolve(__dirname, "fixtures", "contract");

/** Absolute path to a committed hook envelope fixture (e.g. for the drift loop). */
export function envelopePath(name: "pre-tool-use" | "post-tool-use"): string {
	return resolve(FIXTURE_DIR, `${name}.json`);
}

/** Load a fresh copy of a committed hook envelope fixture. */
export function loadEnvelope(name: "pre-tool-use" | "post-tool-use"): HookEnvelope {
	return JSON.parse(readFileSync(envelopePath(name), "utf-8")) as HookEnvelope;
}

/**
 * Envelope fields the host populates per-call (session/transcript ids, cwd,
 * tool_use id, timing). They carry placeholder values in the committed fixtures,
 * so a live-capture drift run resets them to those placeholders when proposing a
 * fixture update — leaving only genuine structural changes to review.
 */
export const VOLATILE_ENVELOPE_FIELDS = [
	"session_id",
	"transcript_path",
	"cwd",
	"tool_use_id",
	"duration_ms",
] as const;

/**
 * The committed set of Claude Code tool names Sage guards — its tool-name
 * dependency surface. Pinned by tool-names-contract.test.ts against both the
 * hooks.json matcher and the PreToolUse handler switch, and used as the
 * per-tool-name matrix the live drift layer verifies the agent still emits.
 */
export function loadToolNames(): { guarded: string[] } {
	return JSON.parse(readFileSync(resolve(FIXTURE_DIR, "tool-names.json"), "utf-8")) as {
		guarded: string[];
	};
}

/** Return a shallow copy of an envelope with the given top-level fields overridden. */
export function withOverrides(envelope: HookEnvelope, overrides: HookEnvelope): HookEnvelope {
	return { ...envelope, ...overrides };
}
