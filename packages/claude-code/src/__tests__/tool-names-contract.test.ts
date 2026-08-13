/**
 * Tool-name drift contract for Claude Code.
 *
 * Claude Code has no agent->canonical lookup map (unlike the other connectors);
 * its tool-name dependency surface is two things that must stay in lockstep with
 * each other AND with Claude Code's actual tool names:
 *   1. the PreToolUse/PostToolUse matcher in hooks/hooks.json (decides whether
 *      Claude Code even calls our hook), and
 *   2. the PreToolUse handler switch in hook-handlers.ts (decides whether we
 *      extract artifacts or skip as unsupported).
 *
 * If Claude Code ever renames a tool (e.g. Read -> read) or adds one we should
 * guard, this internal set silently stops matching and Sage goes blind for that
 * tool. These tests pin the committed set (fixtures/contract/tool-names.json)
 * against both surfaces. The live drift layer (see e2e/README.md)
 * then verifies Claude Code still emits exactly these names — driving one canary
 * per name, with "model didn't invoke the tool" treated as inconclusive.
 */

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ConfigSchema, defaultBranding } from "@gendigital/sage-core";
import { describe, expect, it } from "vitest";
import { handlePreToolUseHook } from "../hook-handlers.js";
import { loadToolNames } from "./contract-fixtures.js";

const HOOKS_JSON_PATH = resolve(__dirname, "..", "..", "..", "..", "hooks", "hooks.json");
const PLUGIN_ROOT = resolve(__dirname, "..", "..", "..", "..");
const TEST_SAGE_DIR = join(mkdtempSync(join(tmpdir(), "sage-toolnames-")), ".sage");

const DIRECT_HOOK_CONFIG = ConfigSchema.parse({
	amsi_check: { enabled: false },
	url_check: { enabled: false },
	file_check: { enabled: false },
	package_check: { enabled: false },
	cache: { enabled: false },
	exceptions: { path: join(TEST_SAGE_DIR, "exceptions.json") },
	logging: { enabled: false },
});

/** Representative benign input per guarded tool (content doesn't matter; only that the tool is handled). */
const BENIGN_INPUT: Record<string, Record<string, unknown>> = {
	Bash: { command: "ls -la" },
	WebFetch: { url: "https://example.com" },
	Write: { file_path: "/tmp/ok.txt", content: "ok" },
	Edit: { file_path: "/tmp/ok.txt", old_string: "a", new_string: "b" },
	Read: { file_path: "/tmp/ok.txt" },
};

function readMatcher(event: "PreToolUse" | "PostToolUse"): string[] {
	const hooksJson = JSON.parse(readFileSync(HOOKS_JSON_PATH, "utf-8")) as {
		hooks: Record<string, Array<{ matcher: string }>>;
	};
	const groups = hooksJson.hooks[event];
	expect(groups, `${event} must have exactly one matcher group`).toHaveLength(1);
	return (groups[0]?.matcher ?? "").split("|");
}

/** Returns the skip reason from the PreToolUse handler, or undefined if the tool was evaluated. */
async function preToolUseSkipReason(
	toolName: string,
	toolInput: Record<string, unknown>,
): Promise<string | undefined> {
	let reason: string | undefined;
	await handlePreToolUseHook(
		{ tool_name: toolName, tool_input: toolInput, session_id: "s", tool_use_id: "t" },
		{
			config: DIRECT_HOOK_CONFIG,
			branding: defaultBranding,
			pluginRoot: PLUGIN_ROOT,
			acquireAmsiClientLease: async () => null,
			completeHook: async (result, data) => {
				if (result === "skipped") reason = data?.skippedReason as string | undefined;
			},
		},
	);
	return reason;
}

describe("Claude Code tool-name drift contract", () => {
	const guarded = [...loadToolNames().guarded].sort();

	it("hooks.json matcher guards exactly the committed tool-name set", () => {
		expect([...readMatcher("PreToolUse")].sort()).toEqual(guarded);
		expect([...readMatcher("PostToolUse")].sort()).toEqual(guarded);
	});

	it("PreToolUse handler switch handles exactly the committed tool-name set", async () => {
		for (const name of guarded) {
			const reason = await preToolUseSkipReason(name, BENIGN_INPUT[name] ?? {});
			expect(reason, `${name} must be handled, not skipped as unsupported`).not.toBe(
				"unsupported_tool",
			);
		}

		// Tools Claude Code does not expose / Sage does not guard must skip as unsupported,
		// proving the switch is scoped to the committed set and not a catch-all.
		for (const name of ["Glob", "Grep", "NotebookEdit"]) {
			expect(await preToolUseSkipReason(name, {}), `${name} must be unsupported`).toBe(
				"unsupported_tool",
			);
		}
	});
});
