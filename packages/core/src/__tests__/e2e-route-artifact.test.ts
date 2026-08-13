import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { classifyDrift } from "../e2e-drift-routing.js";

// e2e/route.mjs is the local dry-run + CI seam for `latest`-mode routing: it computes the
// drift decision via classifyDrift and writes e2e/output/routing/<agent>.json for the weekly
// CI actuator to act on. This test drives the real script (it imports the built core
// dist, present here because vitest globalSetup builds the repo first) and asserts the
// artifact's shape and that its decision matches the brain — so the actuator can trust it.

const REPO_ROOT = join(import.meta.dirname, "../../../..");
const ROUTE_MJS = join(REPO_ROOT, "e2e/route.mjs");
const ROUTING_DIR = join(REPO_ROOT, "e2e/output/routing");

// Unique agent names so the test never collides with a real run's artifacts and is trivially
// cleaned up; the write path itself (e2e/output/routing/) is exercised for real.
const written: string[] = [];
function runRoute(
	agent: string,
	pinned: string,
	resolved: string,
	green: boolean,
	shaped: boolean,
	buildFailed?: boolean,
): { artifact: Record<string, unknown>; stdout: string } {
	const args = [ROUTE_MJS, agent, pinned, resolved, String(green), String(shaped)];
	if (buildFailed !== undefined) args.push(String(buildFailed));
	const stdout = execFileSync("node", args, { encoding: "utf8" });
	const path = join(ROUTING_DIR, `${agent}.json`);
	written.push(path);
	return { artifact: JSON.parse(readFileSync(path, "utf8")), stdout };
}

afterAll(() => {
	for (const path of written) rmSync(path, { force: true });
});

describe("e2e/route.mjs routing artifact", () => {
	const cases = [
		{ name: "auto-bump-pr", pinned: "1.0.0", resolved: "1.1.0", green: true, shaped: false },
		{ name: "review-pr", pinned: "1.0.0", resolved: "1.1.0", green: true, shaped: true },
		{ name: "drift-alarm", pinned: "1.0.0", resolved: "1.1.0", green: false, shaped: false },
		{ name: "infra-alarm", pinned: "1.0.0", resolved: "1.0.0", green: false, shaped: false },
		{ name: "steady", pinned: "1.0.0", resolved: "1.0.0", green: true, shaped: false },
	] as const;

	for (const c of cases) {
		it(`writes a complete artifact whose decision matches classifyDrift (${c.name})`, () => {
			const agent = `__test-${c.name}`;
			const { artifact, stdout } = runRoute(agent, c.pinned, c.resolved, c.green, c.shaped);
			const expected = classifyDrift({
				pinned: c.pinned,
				resolved: c.resolved,
				suiteGreen: c.green,
				shapeChanged: c.shaped,
				buildFailed: false,
			});

			// Every field the actuator reads is present and echoes the inputs verbatim.
			expect(artifact).toEqual({
				agent,
				pinned: c.pinned,
				resolved: c.resolved,
				suiteGreen: c.green,
				shapeChanged: c.shaped,
				buildFailed: false,
				action: expected.action,
				reason: expected.reason,
			});
			// The stdout dry-run line stays in lockstep with the artifact (unchanged behaviour).
			expect(stdout).toContain(`>> [latest] ${agent}: ${expected.action} —`);
		});
	}

	it("build failure short-circuits to build-alarm regardless of green/shaped", () => {
		const agent = "__test-build-alarm";
		const { artifact } = runRoute(agent, "1.0.0", "1.1.0", true, true, true);
		expect(artifact.buildFailed).toBe(true);
		expect(artifact.action).toBe("build-alarm");
		expect(artifact.reason).toBe(
			classifyDrift({
				pinned: "1.0.0",
				resolved: "1.1.0",
				suiteGreen: true,
				shapeChanged: true,
				buildFailed: true,
			}).reason,
		);
	});

	it("defaults buildFailed to false when the arg is omitted", () => {
		const agent = "__test-default-buildfailed";
		// runRoute reads the artifact back (readFileSync), so a successful return proves it
		// was written; we only need to assert the defaulted field here.
		const { artifact } = runRoute(agent, "1.0.0", "1.0.0", true, false);
		expect(artifact.buildFailed).toBe(false);
	});
});
