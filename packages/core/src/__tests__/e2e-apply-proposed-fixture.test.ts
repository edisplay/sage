import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

// e2e/apply-proposed-fixture.mjs is the fixture-commit half the weekly drift actuator runs for
// review-pr — it copies e2e/output/proposed/<agent>/<same relative path as the real fixture> onto
// the repo root and prints the destination for the caller to `git add`. No per-agent table: the
// agent subdirectory alone scopes which candidates apply. We run the real script against temp
// proposedDir/repoRoot overrides so the tracked fixtures are never touched.

const REPO_ROOT = join(import.meta.dirname, "../../../..");
const SCRIPT = join(REPO_ROOT, "e2e/apply-proposed-fixture.mjs");

let proposedDir: string;
let repoRoot: string;

afterEach(() => {
	if (proposedDir) rmSync(proposedDir, { recursive: true, force: true });
	if (repoRoot) rmSync(repoRoot, { recursive: true, force: true });
});

function apply(agent: string) {
	return execFileSync("node", [SCRIPT, agent, proposedDir, repoRoot], { encoding: "utf8" });
}

function makeRoots() {
	proposedDir = mkdtempSync(join(tmpdir(), "sage-proposed-"));
	repoRoot = mkdtempSync(join(tmpdir(), "sage-repo-"));
}

const CLAUDE_PRE = "packages/claude-code/src/__tests__/fixtures/contract/pre-tool-use.json";
const CLAUDE_POST = "packages/claude-code/src/__tests__/fixtures/contract/post-tool-use.json";
const CURSOR_FIXTURE =
	"packages/extension/src/__tests__/fixtures/contract/cursor-pre-tool-use.json";

function writeNested(root: string, relPath: string, content: string) {
	const full = join(root, relPath);
	mkdirSync(join(full, ".."), { recursive: true });
	writeFileSync(full, content);
}

describe("e2e/apply-proposed-fixture.mjs", () => {
	it("copies both candidates for an agent with two envelopes (claude) and prints both dests", () => {
		makeRoots();
		writeNested(proposedDir, join("claude", CLAUDE_PRE), '{"pre":true}\n');
		writeNested(proposedDir, join("claude", CLAUDE_POST), '{"post":true}\n');
		writeNested(repoRoot, CLAUDE_PRE, '{"pre":false}\n');
		writeNested(repoRoot, CLAUDE_POST, '{"post":false}\n');

		const out = apply("claude");

		const lines = out.trim().split("\n").sort();
		expect(lines).toEqual([CLAUDE_POST, CLAUDE_PRE].sort());
		expect(readFileSync(join(repoRoot, CLAUDE_PRE), "utf8")).toBe('{"pre":true}\n');
		expect(readFileSync(join(repoRoot, CLAUDE_POST), "utf8")).toBe('{"post":true}\n');
	});

	it("copies only the candidate that exists — a partial match is normal, not an error", () => {
		makeRoots();
		writeNested(proposedDir, join("claude", CLAUDE_PRE), '{"pre":true}\n');
		writeNested(repoRoot, CLAUDE_PRE, '{"pre":false}\n');
		writeNested(repoRoot, CLAUDE_POST, '{"post":false}\n');

		const out = apply("claude");

		expect(out.trim()).toBe(CLAUDE_PRE);
		expect(readFileSync(join(repoRoot, CLAUDE_PRE), "utf8")).toBe('{"pre":true}\n');
		expect(readFileSync(join(repoRoot, CLAUDE_POST), "utf8")).toBe('{"post":false}\n');
	});

	it("copies a single-envelope agent (cursor) correctly", () => {
		makeRoots();
		writeNested(proposedDir, join("cursor", CURSOR_FIXTURE), '{"cursor":true}\n');
		writeNested(repoRoot, CURSOR_FIXTURE, '{"cursor":false}\n');

		const out = apply("cursor");

		expect(out.trim()).toBe(CURSOR_FIXTURE);
		expect(readFileSync(join(repoRoot, CURSOR_FIXTURE), "utf8")).toBe('{"cursor":true}\n');
	});

	it("fails loudly when the agent's proposed subdirectory is empty", () => {
		makeRoots();
		mkdirSync(join(proposedDir, "opencode"), { recursive: true });

		expect(() => apply("opencode")).toThrow();
	});

	it("fails loudly when the agent's proposed subdirectory doesn't exist at all", () => {
		makeRoots();

		expect(() => apply("not-a-real-agent")).toThrow();
	});

	it("skips symlinks entirely, even one planted at the exact expected fixture path", (ctx) => {
		makeRoots();
		const secretDir = mkdtempSync(join(tmpdir(), "sage-secret-"));
		const secretFile = join(secretDir, "secret.json");
		writeFileSync(secretFile, '{"leaked":true}\n');

		const linkPath = join(proposedDir, "cursor", CURSOR_FIXTURE);
		mkdirSync(join(linkPath, ".."), { recursive: true });
		try {
			symlinkSync(secretFile, linkPath);
		} catch {
			// Windows without Developer Mode / admin can't create symlinks (EPERM),
			// so the scenario can't be set up here. Skip rather than fail — the
			// script's symlink-skipping behaviour is exercised on POSIX CI.
			rmSync(secretDir, { recursive: true, force: true });
			ctx.skip();
			return;
		}
		writeNested(repoRoot, CURSOR_FIXTURE, '{"cursor":false}\n');

		// A symlink-only candidate is treated as zero candidates — same failure as the empty case
		// — and critically, nothing from outside the sandboxed proposed dir reaches the repo.
		expect(() => apply("cursor")).toThrow();
		expect(readFileSync(join(repoRoot, CURSOR_FIXTURE), "utf8")).toBe('{"cursor":false}\n');

		rmSync(secretDir, { recursive: true, force: true });
	});
});
