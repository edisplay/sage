import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ENVELOPE_VOLATILE_FIELDS } from "../e2e-envelope-fixtures.js";

// Contract guard for the Layer 2 drift loop: each connector's volatile-field list must be a
// SUBSET of its committed contract fixture's top-level keys. If a field is renamed in the
// fixture (or mistyped in the list), the drift loop would silently stop scrubbing it and bake
// a live volatile value into a proposed fixture. This catches that desync at Layer 1. It can't
// catch a brand-new host field (nothing here knows the live host) — that surfaces as additive
// drift (`extra` → review-pr) in the Layer 2 run, where a human refreshes the fixture + list.
// (Claude Code's VOLATILE_ENVELOPE_FIELDS is asserted in its own package; see that connector.)

const REPO_ROOT = join(import.meta.dirname, "..", "..", "..", "..");

const FIXTURES: Record<keyof typeof ENVELOPE_VOLATILE_FIELDS, string> = {
	cursor: "packages/extension/src/__tests__/fixtures/contract/cursor-pre-tool-use.json",
	copilot: "packages/extension/src/__tests__/fixtures/contract/copilot-pre-tool-use.json",
	openclaw: "packages/openclaw/src/__tests__/fixtures/contract/openclaw-before-tool-call.json",
	opencode: "packages/opencode/src/__tests__/fixtures/contract/opencode-tool-execute-before.json",
};

describe("envelope volatile-field contract", () => {
	for (const [connector, fields] of Object.entries(ENVELOPE_VOLATILE_FIELDS)) {
		it(`${connector}: every volatile field is a key in the committed fixture`, () => {
			const path = FIXTURES[connector as keyof typeof FIXTURES];
			const fixture = JSON.parse(readFileSync(join(REPO_ROOT, path), "utf-8")) as Record<
				string,
				unknown
			>;
			const absent = fields.filter((field) => !(field in fixture));
			expect(
				absent,
				`${connector} volatile fields absent from ${path} (rename/typo desync): ${absent.join(", ")}`,
			).toEqual([]);
		});
	}
});
