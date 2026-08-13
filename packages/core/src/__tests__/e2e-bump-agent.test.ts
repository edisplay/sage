import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// e2e/bump-agent.mjs is the version-bump the weekly drift actuator in CI runs for
// auto-bump-pr / review-pr. It must change ONLY the target agent's version line and preserve
// agents.json's tab formatting (so the bump PR's diff is one line). We run the real script
// against a temp COPY of the real agents.json so the tracked file is never touched.

const REPO_ROOT = join(import.meta.dirname, "../../../..");
const SCRIPT = join(REPO_ROOT, "e2e/bump-agent.mjs");
const AGENTS_JSON = join(REPO_ROOT, "e2e/agents.json");

const tmp = join(tmpdir(), `sage-agents-${process.pid}.json`);
afterAll(() => rmSync(tmp, { force: true }));

function bump(agent: string, pinned: string, resolved: string, file: string) {
	return execFileSync("node", [SCRIPT, agent, pinned, resolved, file], { encoding: "utf8" });
}

describe("e2e/bump-agent.mjs", () => {
	it("changes only the target agent's version line, preserving tab formatting", () => {
		copyFileSync(AGENTS_JSON, tmp);
		const before = readFileSync(tmp, "utf8");
		const agents = JSON.parse(before);
		const pinned = agents.claude.version;

		const out = bump("claude", pinned, "9.9.9-test", tmp);
		const after = readFileSync(tmp, "utf8");

		expect(out).toContain(`bumped claude: ${pinned} -> 9.9.9-test`);
		expect(JSON.parse(after).claude.version).toBe("9.9.9-test");
		// Exactly one line differs, and the tabs/structure are otherwise byte-identical.
		const afterLines = after.split("\n");
		const diff = before.split("\n").filter((l, i) => l !== afterLines[i]);
		expect(diff).toHaveLength(1);
		expect(diff[0]).toContain(`"version": "${pinned}"`);
		expect(after.includes("\t")).toBe(true);
		// No other agent's version moved.
		expect(JSON.parse(after).copilot.version).toBe(agents.copilot.version);
	});

	it("fails loudly (exit 1) when the pinned version isn't found", () => {
		copyFileSync(AGENTS_JSON, tmp);
		expect(() => bump("claude", "0.0.0-nonexistent", "1.2.3", tmp)).toThrow();
	});

	it("refuses to bump when the agent's version doesn't match pinned, even if another agent carries it", () => {
		copyFileSync(AGENTS_JSON, tmp);
		const before = readFileSync(tmp, "utf8");
		const agents = JSON.parse(before);
		// Pass copilot's actual version as claude's "pinned": the wrong-block bug would make
		// the text indexOf land on the copilot block and bump IT. The guard must refuse.
		expect(() => bump("claude", agents.copilot.version, "9.9.9-wrong", tmp)).toThrow();
		// Nothing changed: neither claude (mismatch → refused) nor copilot (must never be touched).
		expect(readFileSync(tmp, "utf8")).toBe(before);
	});
});
