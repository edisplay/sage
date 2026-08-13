import { describe, expect, it } from "vitest";
import { classifyDrift, resolvedDelta } from "../e2e-drift-routing.js";

describe("classifyDrift (Layer 2 latest-mode routing)", () => {
	const v = "1.0.0";
	const newer = "1.1.0";

	it("same version, green, no shape change → steady", () => {
		expect(
			classifyDrift({ pinned: v, resolved: v, suiteGreen: true, shapeChanged: false }).action,
		).toBe("steady");
	});

	it("same version, green, shape change → review-pr (refresh fixture, no bump)", () => {
		expect(
			classifyDrift({ pinned: v, resolved: v, suiteGreen: true, shapeChanged: true }).action,
		).toBe("review-pr");
	});

	it("same version, red → infra-alarm (pinned contract broke, no version change)", () => {
		expect(
			classifyDrift({ pinned: v, resolved: v, suiteGreen: false, shapeChanged: false }).action,
		).toBe("infra-alarm");
		// red routing ignores shapeChanged
		expect(
			classifyDrift({ pinned: v, resolved: v, suiteGreen: false, shapeChanged: true }).action,
		).toBe("infra-alarm");
	});

	it("newer version, green, no shape change → auto-bump-pr (agents.json only)", () => {
		expect(
			classifyDrift({ pinned: v, resolved: newer, suiteGreen: true, shapeChanged: false }).action,
		).toBe("auto-bump-pr");
	});

	it("newer version, green, shape change → review-pr (regenerate fixture + bump)", () => {
		expect(
			classifyDrift({ pinned: v, resolved: newer, suiteGreen: true, shapeChanged: true }).action,
		).toBe("review-pr");
	});

	it("newer version, red → drift-alarm (real drift, needs a Sage change)", () => {
		expect(
			classifyDrift({ pinned: v, resolved: newer, suiteGreen: false, shapeChanged: false }).action,
		).toBe("drift-alarm");
		expect(
			classifyDrift({ pinned: v, resolved: newer, suiteGreen: false, shapeChanged: true }).action,
		).toBe("drift-alarm");
	});

	it("build failed → build-alarm (own alarm, not drift/infra), for both newer and same version", () => {
		expect(
			classifyDrift({
				pinned: v,
				resolved: newer,
				suiteGreen: false,
				shapeChanged: false,
				buildFailed: true,
			}).action,
		).toBe("build-alarm");
		expect(
			classifyDrift({
				pinned: v,
				resolved: v,
				suiteGreen: false,
				shapeChanged: false,
				buildFailed: true,
			}).action,
		).toBe("build-alarm");
	});

	it("build failure short-circuits the suite/shape signals (never ran)", () => {
		// Even if green/shaped were somehow set, a build failure means nothing was observed.
		expect(
			classifyDrift({
				pinned: v,
				resolved: newer,
				suiteGreen: true,
				shapeChanged: true,
				buildFailed: true,
			}).action,
		).toBe("build-alarm");
	});

	it("reason names both versions so a triager can read the routing line standalone", () => {
		const { reason } = classifyDrift({
			pinned: v,
			resolved: newer,
			suiteGreen: true,
			shapeChanged: false,
		});
		expect(reason).toContain(newer);
		expect(reason).toContain(v);
	});

	it("resolved OLDER than pinned (rollback/yank) → infra-alarm, never a downgrade bump", () => {
		// green + older must NOT auto-bump; shapeChanged is irrelevant.
		expect(
			classifyDrift({ pinned: newer, resolved: v, suiteGreen: true, shapeChanged: false }).action,
		).toBe("infra-alarm");
		expect(
			classifyDrift({ pinned: newer, resolved: v, suiteGreen: true, shapeChanged: true }).action,
		).toBe("infra-alarm");
	});

	it("unorderable version pair → infra-alarm (fail-safe: don't bump)", () => {
		expect(
			classifyDrift({
				pinned: "1.0.0",
				resolved: "weird-build-xyz",
				suiteGreen: true,
				shapeChanged: false,
			}).action,
		).toBe("infra-alarm");
	});

	it("delegates ordering to resolvedDelta — a date-stamped (Cursor) bump routes correctly", () => {
		// Proves classifyDrift routes via resolvedDelta for non-numeric schemes; the full
		// date-stamp newer/older matrix is covered in the resolvedDelta suite below.
		expect(
			classifyDrift({
				pinned: "2026.06.19-20-24-33-653a7fb",
				resolved: "2026.06.20-09-00-00-abcdef0",
				suiteGreen: true,
				shapeChanged: false,
			}).action,
		).toBe("auto-bump-pr");
	});
});

describe("resolvedDelta", () => {
	it("equal versions → same", () => {
		expect(resolvedDelta("1.2.3", "1.2.3")).toBe("same");
	});

	it("numeric dotted (npm / VS Code) compares segment-by-segment", () => {
		expect(resolvedDelta("1.0.0", "1.1.0")).toBe("newer");
		expect(resolvedDelta("2.1.169", "2.1.170")).toBe("newer");
		expect(resolvedDelta("1.10.0", "1.9.0")).toBe("older"); // not lexical
		expect(resolvedDelta("1.1", "1.1.0")).toBe("same"); // numerically equal
	});

	it("date-stamped tags (Cursor) compare lexically = chronologically", () => {
		expect(resolvedDelta("2026.06.19-00-00-00-aaaaaaa", "2026.06.20-00-00-00-bbbbbbb")).toBe(
			"newer",
		);
		expect(resolvedDelta("2026.06.20-00-00-00-bbbbbbb", "2026.06.19-00-00-00-aaaaaaa")).toBe(
			"older",
		);
	});

	it("mixed / unrecognized schemes → unknown", () => {
		expect(resolvedDelta("1.0.0", "abc")).toBe("unknown");
		expect(resolvedDelta("nightly", "stable")).toBe("unknown");
	});
});
