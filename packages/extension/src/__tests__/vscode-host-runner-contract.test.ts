import { describe, expect, it } from "vitest";
import type { RunExtensionHostSuiteOptions } from "./vscode-host-runner.js";
import * as runner from "./vscode-host-runner.js";

// The runner is a runtime `.js` (the in-container entry `require`s it directly, so it can't be
// a `.ts`), with a hand-written `.d.ts`. That declaration can silently drift from the JS. This
// locks the exported runtime surface against the `.d.ts` so a rename/removal/shape change fails
// here instead of only showing up as a stale editor hint. (The `.d.ts` is excluded from
// `pnpm check`, so this runtime assertion is the only automated guard.)

describe("vscode-host-runner export contract", () => {
	it("exports the functions/objects the .d.ts declares", () => {
		expect(typeof runner.runExtensionHostSuite).toBe("function");
		expect(typeof runner.VSCODE_HOST).toBe("object");
	});

	it("VSCODE_HOST matches the declared shape (keys + value types)", () => {
		// Assigning the runtime value to the declared type is a compile-time check of the shape;
		// the runtime assertions below catch drift even though tests are excluded from `pnpm check`.
		const host: Pick<
			RunExtensionHostSuiteOptions,
			"extensionId" | "managedMarker" | "hookMode" | "hooksRelativePath"
		> = runner.VSCODE_HOST;

		expect(Object.keys(host).sort()).toEqual([
			"extensionId",
			"hookMode",
			"hooksRelativePath",
			"managedMarker",
		]);
		expect(typeof host.extensionId).toBe("string");
		expect(typeof host.managedMarker).toBe("string");
		expect(typeof host.hooksRelativePath).toBe("string");
		expect(host.hookMode).toBe("vscode");
	});
});
