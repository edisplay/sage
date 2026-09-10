import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows supply chain threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	it("detects Install-Module without -RequiredVersion (WIN-SUPPLY-001)", () => {
		expect(matchCommand(engine, "Install-Module PSReadLine")).toContain("CLT-WIN-SUPPLY-001");
	});

	it("does not match Install-Module with -RequiredVersion", () => {
		const ids = matchCommand(engine, "Install-Module PSReadLine -RequiredVersion 2.3.0");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-SUPPLY"))).toEqual([]);
	});

	it("does not match a prose mention of the risk (WIN-SUPPLY-001 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "run Install-Module Foo without -RequiredVersion to see the risk"',
		);
		expect(ids.filter((id) => id.startsWith("CLT-WIN-SUPPLY"))).toEqual([]);
	});
});
