/**
 * Tool-name drift contract for the OpenClaw connector (Layer 1).
 *
 * OpenClaw names its tools (`exec`, `write`, `web_fetch`, …); `tool-handler.ts`
 * maps those raw names to Sage's canonical tool types via OPENCLAW_TOOL_MAP. Those
 * map keys ARE Sage's tool-name dependency surface: if OpenClaw renames a tool
 * (e.g. `exec` -> `shell`), drops one, or adds one we should guard, the map
 * silently stops matching and Sage goes blind for that tool.
 *
 * This pins the map against a committed snapshot (fixtures/contract/tool-names.json)
 * so any add/remove/rename is a conscious fixture update. The snapshot is also the
 * matrix the live drift layer iterates (docs/developer-guide.md — E2E architecture, tool-name drift) —
 * enumerating OpenClaw's advertised tools and diffing them against these keys.
 * Mirrors packages/opencode/src/__tests__/tool-names-contract.test.ts.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { OPENCLAW_TOOL_MAP } from "../tool-handler.js";

const FIXTURE = JSON.parse(
	readFileSync(resolve(__dirname, "fixtures", "contract", "tool-names.json"), "utf-8"),
) as {
	openclaw: Record<string, string>;
	openclawToolNames: string[];
};

describe("openclaw tool-name contract", () => {
	it("OPENCLAW_TOOL_MAP matches the committed snapshot", () => {
		expect(OPENCLAW_TOOL_MAP).toEqual(FIXTURE.openclaw);
	});

	it("every pinned OpenClaw tool name is a key in OPENCLAW_TOOL_MAP", () => {
		// These are the tool names the live drift layer drives a canary for; each
		// must be mapped or Sage is blind to it.
		for (const name of FIXTURE.openclawToolNames) {
			expect(Object.keys(OPENCLAW_TOOL_MAP)).toContain(name);
		}
	});
});
