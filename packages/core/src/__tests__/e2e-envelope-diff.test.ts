import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runDriftCheck } from "../e2e-envelope-diff.js";

describe("runDriftCheck (latest-mode candidate writing)", () => {
	let dir: string;
	let fixturePath: string;
	let proposedPath: string;
	const fixture = { tool_name: "Bash", tool_input: { command: "echo hi" } };
	const noop = () => {};

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "sage-drift-test-"));
		fixturePath = join(dir, "fixture.json");
		proposedPath = join(dir, "proposed.json");
		writeFileSync(fixturePath, JSON.stringify(fixture));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	const run = (captured: Record<string, unknown>, mode: "pinned" | "latest") =>
		runDriftCheck({
			captured,
			fixturePath,
			label: "test",
			mode,
			volatileFields: [],
			proposedPath,
			log: noop,
		});

	it("writes a candidate on additive-only drift in latest mode (green path)", () => {
		const captured = { ...fixture, new_field: "x" };
		const { diff, drifted } = run(captured, "latest");
		expect(diff.extra).toEqual(["new_field"]);
		expect(drifted).toBe(false); // additive-only is not real drift — suite stays green
		expect(existsSync(proposedPath)).toBe(true);
		expect(JSON.parse(readFileSync(proposedPath, "utf-8"))).toMatchObject({ new_field: "x" });
	});

	it("does NOT write a candidate on additive-only drift in pinned mode", () => {
		run({ ...fixture, new_field: "x" }, "pinned");
		expect(existsSync(proposedPath)).toBe(false);
	});

	it("writes a candidate and reports drift on a missing key in latest mode", () => {
		const { drifted } = run({ tool_name: "Bash" }, "latest"); // tool_input dropped
		expect(drifted).toBe(true);
		expect(existsSync(proposedPath)).toBe(true);
	});

	it("writes nothing when the shape matches exactly (latest mode)", () => {
		const { drifted } = run({ ...fixture }, "latest");
		expect(drifted).toBe(false);
		expect(existsSync(proposedPath)).toBe(false);
	});
});
