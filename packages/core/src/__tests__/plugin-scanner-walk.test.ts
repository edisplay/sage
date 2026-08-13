import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { walkPluginFiles } from "../plugin-scanner.js";
import { nullLogger } from "../types.js";

const IS_WIN = platform() === "win32";

// See skill-id.test.ts for rationale: junctions on Windows avoid the
// Developer Mode / admin requirement for directory symlinks.
async function dirSymlink(target: string, link: string): Promise<void> {
	await symlink(target, link, IS_WIN ? "junction" : "dir");
}

const canCreateFileSymlink = (() => {
	const probe = mkdtempSync(join(tmpdir(), "sage-sym-probe-"));
	try {
		const target = join(probe, "target");
		writeFileSync(target, "");
		symlinkSync(target, join(probe, "link"), "file");
		return true;
	} catch {
		return false;
	} finally {
		try {
			rmSync(probe, { recursive: true, force: true });
		} catch {
			// best effort cleanup
		}
	}
})();

describe("walkPluginFiles symlink handling", () => {
	let tempRoot: string;

	beforeEach(async () => {
		tempRoot = await mkdtemp(join(tmpdir(), "sage-plugin-walk-"));
	});

	afterEach(async () => {
		await rm(tempRoot, { recursive: true, force: true });
	});

	it("does not hang on a symlink cycle", async () => {
		const pluginDir = join(tempRoot, "plugin");
		await mkdir(pluginDir, { recursive: true });
		await writeFile(join(pluginDir, "index.js"), "console.log(1)");
		await dirSymlink(pluginDir, join(pluginDir, "cycle"));

		const files = await walkPluginFiles(pluginDir, nullLogger);
		expect(files).toEqual([join(pluginDir, "index.js")]);
	});

	it("does not follow a directory symlink that escapes the plugin root", async () => {
		const outsideDir = join(tempRoot, "outside");
		await mkdir(outsideDir, { recursive: true });
		await writeFile(join(outsideDir, "secret.js"), "leak me");

		const pluginDir = join(tempRoot, "plugin2");
		await mkdir(pluginDir, { recursive: true });
		await writeFile(join(pluginDir, "index.js"), "console.log(1)");
		await dirSymlink(outsideDir, join(pluginDir, "sneaky"));

		const files = await walkPluginFiles(pluginDir, nullLogger);
		expect(files).toEqual([join(pluginDir, "index.js")]);
	});

	it.skipIf(!canCreateFileSymlink)(
		"does not follow a file symlink that escapes the plugin root",
		async () => {
			const outsideFile = join(tempRoot, "secret.js");
			await writeFile(outsideFile, "leak me");

			const pluginDir = join(tempRoot, "plugin3");
			await mkdir(pluginDir, { recursive: true });
			await writeFile(join(pluginDir, "index.js"), "console.log(1)");
			await symlink(outsideFile, join(pluginDir, "stolen.js"));

			const files = await walkPluginFiles(pluginDir, nullLogger);
			expect(files).toEqual([join(pluginDir, "index.js")]);
		},
	);

	it("follows a chain of symlinks that stays within the plugin root without duplicating or hanging", async () => {
		const pluginDir = join(tempRoot, "plugin4");
		const realSubdir = join(pluginDir, "real");
		await mkdir(realSubdir, { recursive: true });
		await writeFile(join(realSubdir, "helper.js"), "console.log(2)");
		await dirSymlink(realSubdir, join(pluginDir, "link1"));
		await dirSymlink(join(pluginDir, "link1"), join(pluginDir, "link2"));

		// All three paths (real dir + two chained symlinks) resolve to the
		// same real directory, so cycle detection should only walk it once.
		const files = await walkPluginFiles(pluginDir, nullLogger);
		expect(files).toHaveLength(1);
		expect(files[0].endsWith("helper.js")).toBe(true);
	});

	it("resolves to an empty list when the root does not exist", async () => {
		const ghost = join(tempRoot, "does-not-exist");
		const files = await walkPluginFiles(ghost, nullLogger);
		expect(files).toEqual([]);
	});
});
