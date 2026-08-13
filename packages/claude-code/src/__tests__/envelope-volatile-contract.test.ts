import { describe, expect, it } from "vitest";
import { loadEnvelope, VOLATILE_ENVELOPE_FIELDS } from "./contract-fixtures.js";

// Contract guard mirroring core's e2e-envelope-fixtures.test.ts, for Claude Code (whose
// VOLATILE_ENVELOPE_FIELDS lives in contract-fixtures.ts, shared with its integration tests).
// Each volatile field must be a key in at least one committed envelope — pre OR post, since
// some are event-specific (duration_ms is post-tool-use only; tool_use_id appears in both).
// A rename in a fixture without updating the list would silently stop the drift loop scrubbing
// it; this fails that desync at Layer 1.

describe("Claude Code envelope volatile-field contract", () => {
	it("every VOLATILE_ENVELOPE_FIELDS entry is a key in the pre/post envelope", () => {
		const keys = new Set([
			...Object.keys(loadEnvelope("pre-tool-use")),
			...Object.keys(loadEnvelope("post-tool-use")),
		]);
		const absent = VOLATILE_ENVELOPE_FIELDS.filter((field) => !keys.has(field));
		expect(
			absent,
			`volatile fields absent from the committed pre/post envelopes (rename/typo desync): ${absent.join(", ")}`,
		).toEqual([]);
	});
});
