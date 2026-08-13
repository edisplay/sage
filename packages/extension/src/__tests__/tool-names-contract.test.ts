/**
 * Tool-name drift contract for the extension connectors (Cursor + VS Code/Copilot).
 *
 * Each host names its tools differently; `sage-hook.ts` maps those raw names to
 * Sage's canonical tool types via CURSOR_TOOL_MAP / VSCODE_TOOL_MAP. Those map
 * keys ARE Sage's tool-name dependency surface: if a host renames a tool
 * (e.g. `bash` -> `shell`), drops one, or adds one we should guard, the map
 * silently stops matching and Sage goes blind for that tool.
 *
 * This pins both maps against a committed snapshot (fixtures/contract/tool-names.json)
 * so any add/remove/rename is a conscious fixture update. The snapshot is also the
 * matrix the live drift layer iterates (docs/developer-guide.md — E2E architecture, tool-name drift) —
 * enumerating the host's advertised catalog and diffing it against these keys.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { CURSOR_TOOL_MAP, VSCODE_TOOL_MAP } from "../sage-hook.js";

const FIXTURE = JSON.parse(
	readFileSync(resolve(__dirname, "fixtures", "contract", "tool-names.json"), "utf-8"),
) as {
	vscode: Record<string, string>;
	cursor: Record<string, string>;
	copilotCliToolNames: string[];
};

describe("extension tool-name contract", () => {
	it("VSCODE_TOOL_MAP matches the committed snapshot", () => {
		expect(VSCODE_TOOL_MAP).toEqual(FIXTURE.vscode);
	});

	it("CURSOR_TOOL_MAP matches the committed snapshot", () => {
		expect(CURSOR_TOOL_MAP).toEqual(FIXTURE.cursor);
	});

	it("every pinned Copilot CLI tool name is a key in VSCODE_TOOL_MAP", () => {
		// Copilot CLI routes through the vscode hook mode, so its tool names must all
		// be mapped. This is the per-tool-name matrix the live drift layer fires.
		for (const name of FIXTURE.copilotCliToolNames) {
			expect(Object.keys(VSCODE_TOOL_MAP)).toContain(name);
		}
	});
});
