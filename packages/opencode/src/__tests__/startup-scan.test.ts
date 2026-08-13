/**
 * Unit tests for OpenCode startup-scan worker-path resolution.
 *
 * OpenCode ships unbundled (tsc only), so it must resolve the detached
 * workers out of the installed `@gendigital/sage-core` package. That only
 * works if core exports the worker subpath — this test guards the
 * skill-upload worker resolution and the core `exports` entry it depends on.
 */

import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { resolveSkillUploadWorkerPath } from "../startup-scan.js";

describe("OpenCode startup-scan: skill-upload worker resolution", () => {
	it("resolves the skill-upload worker from @gendigital/sage-core", () => {
		const path = resolveSkillUploadWorkerPath();
		expect(path).toBeTypeOf("string");
		expect(path).toMatch(/skill-upload-worker\.js$/);
		expect(existsSync(path as string)).toBe(true);
	});
});
