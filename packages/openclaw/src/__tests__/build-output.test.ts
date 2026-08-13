/**
 * Build-output guards for the OpenClaw plugin bundle.
 *
 * startup-scan passes dist-relative worker paths to the core scan handler; if
 * a bundle is missing the worker silently never spawns (fail-open), so guard
 * the esbuild output here. Mirrors the claude-code build-output guard.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");

describe("OpenClaw build output: detached worker bundles", () => {
	it("bundles the skill-upload worker next to index", () => {
		expect(existsSync(resolve(DIST_DIR, "skill-upload-worker.cjs"))).toBe(true);
	});

	it("bundles the model-download worker next to index", () => {
		expect(existsSync(resolve(DIST_DIR, "model-download-worker.cjs"))).toBe(true);
	});
});
