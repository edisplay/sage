import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	computeSkillId,
	computeSkillIdsForRoot,
	entriesFromDirectory,
	findSkillPackagesWithMtime,
	SkillTooLargeError,
} from "../skill-id.js";

const IS_WIN = platform() === "win32";

// Use 'junction' on Windows so directory symlinks don't require Developer
// Mode or admin. Junctions follow the same stat/realpath semantics that
// the production cycle/escape defenses rely on. Targets must be absolute
// when type is 'junction', which all callers below already pass.
async function dirSymlink(target: string, link: string): Promise<void> {
	await symlink(target, link, IS_WIN ? "junction" : "dir");
}

// File symlinks have no junction equivalent; on Windows they require
// Developer Mode or admin privileges. Probe once at module load so the
// file-symlink test can skip cleanly instead of failing with EPERM.
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

describe("skill-id", () => {
	let tempRoot: string;

	beforeEach(async () => {
		tempRoot = await mkdtemp(join(tmpdir(), "sage-skill-id-"));
	});

	afterEach(async () => {
		await rm(tempRoot, { recursive: true, force: true });
	});

	// Folder-only view of discovery, for tests that only care about which
	// directories are skill packages (not their mtimes).
	const findSkillFolders = async (root: string): Promise<string[]> =>
		(await findSkillPackagesWithMtime(root)).map((p) => p.folder);

	describe("computeSkillId", () => {
		it("produces a stable 64-char hex digest", async () => {
			const skillDir = join(tempRoot, "audit-website");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "# Audit Website\n");
			await writeFile(join(skillDir, "helper.py"), "print('hello')\n");

			const entries = await entriesFromDirectory(skillDir);
			const { skillId } = computeSkillId(entries);
			expect(skillId).toMatch(/^[0-9a-f]{64}$/);

			const entries2 = await entriesFromDirectory(skillDir);
			const { skillId: skillId2 } = computeSkillId(entries2);
			expect(skillId2).toBe(skillId);
		});

		it("returns a different digest when content changes", async () => {
			const dirA = join(tempRoot, "a");
			const dirB = join(tempRoot, "b");
			await mkdir(dirA, { recursive: true });
			await mkdir(dirB, { recursive: true });
			await writeFile(join(dirA, "SKILL.md"), "version A\n");
			await writeFile(join(dirB, "SKILL.md"), "version B\n");

			const idA = computeSkillId(await entriesFromDirectory(dirA)).skillId;
			const idB = computeSkillId(await entriesFromDirectory(dirB)).skillId;
			expect(idA).not.toBe(idB);
		});

		it("ignores skill.sig content", async () => {
			const dirA = join(tempRoot, "with-sig");
			const dirB = join(tempRoot, "no-sig");
			await mkdir(dirA, { recursive: true });
			await mkdir(dirB, { recursive: true });
			await writeFile(join(dirA, "SKILL.md"), "same content\n");
			await writeFile(join(dirA, "skill.sig"), "any-signature-bytes");
			await writeFile(join(dirB, "SKILL.md"), "same content\n");

			const idA = computeSkillId(await entriesFromDirectory(dirA)).skillId;
			const idB = computeSkillId(await entriesFromDirectory(dirB)).skillId;
			expect(idA).toBe(idB);
		});

		it("normalizes single top-level prefix when only sub-paths share a wrapper", () => {
			// The prefix-strip rule fires when every entry starts with the
			// same top-level segment (and no separate entry exists for that
			// segment itself). This matches how tar-extracted archives can
			// look. The id should be independent of the wrapper name.
			const wrappedA = computeSkillId([
				{
					entryPath: "wrap-a/SKILL.md",
					isDir: false,
					content: Buffer.from("body"),
				},
				{
					entryPath: "wrap-a/helper.py",
					isDir: false,
					content: Buffer.from("print(1)"),
				},
			]).skillId;
			const wrappedB = computeSkillId([
				{
					entryPath: "wrap-b/SKILL.md",
					isDir: false,
					content: Buffer.from("body"),
				},
				{
					entryPath: "wrap-b/helper.py",
					isDir: false,
					content: Buffer.from("print(1)"),
				},
			]).skillId;
			const unwrapped = computeSkillId([
				{
					entryPath: "SKILL.md",
					isDir: false,
					content: Buffer.from("body"),
				},
				{
					entryPath: "helper.py",
					isDir: false,
					content: Buffer.from("print(1)"),
				},
			]).skillId;
			expect(wrappedA).toBe(wrappedB);
			expect(wrappedA).toBe(unwrapped);
		});

		it("matches the algorithm formula sha256('type\\0path\\0filehash\\n')", () => {
			// Pin the algorithm so the production copy here and the master
			// probe at compute_skill_id.ts cannot silently diverge.
			const content = Buffer.from("hello\n", "utf8");
			const fileHash = createHash("sha256").update(content).digest("hex");
			const expected = createHash("sha256")
				.update(Buffer.from(`file\0SKILL.md\0${fileHash}\n`, "utf8"))
				.digest("hex");

			const { skillId } = computeSkillId([{ entryPath: "SKILL.md", isDir: false, content }]);
			expect(skillId).toBe(expected);
		});
	});

	describe("findSkillPackagesWithMtime (folder discovery)", () => {
		it("finds folders containing SKILL.md", async () => {
			const a = join(tempRoot, "ext", "skills", "alpha");
			const b = join(tempRoot, "ext", "skills", "beta");
			await mkdir(a, { recursive: true });
			await mkdir(b, { recursive: true });
			await writeFile(join(a, "SKILL.md"), "a");
			await writeFile(join(b, "SKILL.md"), "b");

			// Stray files (no SKILL.md) should not match.
			await mkdir(join(tempRoot, "ext", "src"), { recursive: true });
			await writeFile(join(tempRoot, "ext", "src", "index.js"), "");

			const found = await findSkillFolders(tempRoot);
			expect(found.sort()).toEqual([a, b].sort());
		});

		it("skips node_modules / .git", async () => {
			const realSkill = join(tempRoot, "real");
			const noisySkill = join(tempRoot, "node_modules", "evil");
			await mkdir(realSkill, { recursive: true });
			await mkdir(noisySkill, { recursive: true });
			await writeFile(join(realSkill, "SKILL.md"), "real");
			await writeFile(join(noisySkill, "SKILL.md"), "evil");

			const found = await findSkillFolders(tempRoot);
			expect(found).toEqual([realSkill]);
		});

		it("returns empty list for missing or non-directory paths", async () => {
			const ghost = join(tempRoot, "does-not-exist");
			expect(await findSkillFolders(ghost)).toEqual([]);

			const file = join(tempRoot, "file.txt");
			await writeFile(file, "");
			expect(await findSkillFolders(file)).toEqual([]);
		});
	});

	describe("symlink loop protection", () => {
		it("entriesFromDirectory does not hang on a symlink loop", async () => {
			const skillDir = join(tempRoot, "loopy");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "loop test\n");
			await dirSymlink(skillDir, join(skillDir, "cycle"));

			const entries = await entriesFromDirectory(skillDir);
			const paths = entries.map((e) => e.entryPath);
			expect(paths).toContain("SKILL.md");
			expect(paths.filter((p) => p === "cycle")).toHaveLength(1);
		});

		it("findSkillPackagesWithMtime does not hang on a symlink loop", async () => {
			const skillDir = join(tempRoot, "loopy2");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "loop test\n");
			await dirSymlink(skillDir, join(skillDir, "back"));

			const found = await findSkillFolders(tempRoot);
			expect(found).toContain(skillDir);
		});

		it("entriesFromDirectory ignores symlinks that escape the root", async () => {
			const skillDir = join(tempRoot, "contained");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "contained\n");
			// Symlink pointing outside the skill directory
			await dirSymlink(tempRoot, join(skillDir, "escape"));

			const entries = await entriesFromDirectory(skillDir);
			const paths = entries.map((e) => e.entryPath);
			expect(paths).toContain("SKILL.md");
			// The escape symlink dir entry is listed but not recursed into
			expect(paths).toContain("escape");
			// No files from outside the skill dir should appear
			expect(paths.filter((p) => p.startsWith("escape/"))).toHaveLength(0);
		});

		it.skipIf(!canCreateFileSymlink)(
			"entriesFromDirectory skips file symlinks that escape the root",
			async () => {
				const outsideFile = join(tempRoot, "secret.txt");
				await writeFile(outsideFile, "secret content\n");

				const skillDir = join(tempRoot, "skill-with-file-escape");
				await mkdir(skillDir, { recursive: true });
				await writeFile(join(skillDir, "SKILL.md"), "legit\n");
				await symlink(outsideFile, join(skillDir, "stolen.txt"));

				const entries = await entriesFromDirectory(skillDir);
				const paths = entries.map((e) => e.entryPath);
				expect(paths).toContain("SKILL.md");
				expect(paths).not.toContain("stolen.txt");
			},
		);

		// Regression: a skill whose SKILL.md is symlinked out of the
		// folder (chezmoi / GNU stow style) is discovered by one walk and enumerates
		// to nothing in the other. That produced a skill id of sha256(zero bytes) and
		// a member-less 22-byte zip, uploaded to the analyzer once per session start.
		describe("skill whose SKILL.md is symlinked outside the folder", () => {
			const buildSymlinkedSkill = async (): Promise<string> => {
				const outside = join(tempRoot, "dotfiles");
				await mkdir(outside, { recursive: true });
				await writeFile(join(outside, "SKILL.md"), "---\nname: my-skill\n---\nbody\n");

				const skillDir = join(tempRoot, "skills", "symlinked-skill");
				await mkdir(skillDir, { recursive: true });
				await symlink(join(outside, "SKILL.md"), join(skillDir, "SKILL.md"), "file");
				return skillDir;
			};

			it.skipIf(!canCreateFileSymlink)(
				"the two walks disagree: discovered as a package, enumerates to zero entries",
				async () => {
					const skillDir = await buildSymlinkedSkill();

					// stat() follows the symlink, so discovery accepts the folder...
					expect(await findSkillFolders(skillDir)).toEqual([skillDir]);
					// ...but containment drops the file, leaving nothing to hash or zip.
					expect(await entriesFromDirectory(skillDir)).toEqual([]);
				},
			);

			it.skipIf(!canCreateFileSymlink)(
				"computeSkillIdsForRoot skips it, so the all-zeros id is never queued",
				async () => {
					await buildSymlinkedSkill();
					const normal = join(tempRoot, "skills", "normal-skill");
					await mkdir(normal, { recursive: true });
					await writeFile(join(normal, "SKILL.md"), "---\nname: normal\n---\nbody\n");

					const out = await computeSkillIdsForRoot(join(tempRoot, "skills"));

					// The unenumerable skill is dropped; its healthy sibling still returns.
					expect(out.map((s) => s.folder)).toEqual([normal]);
					const emptyTreeId = createHash("sha256").digest("hex");
					expect(out.map((s) => s.skillId)).not.toContain(emptyTreeId);
				},
			);
		});

		it("findSkillPackagesWithMtime ignores symlinks that escape the root", async () => {
			const outsideDir = join(tempRoot, "outside");
			await mkdir(outsideDir, { recursive: true });
			await writeFile(join(outsideDir, "SKILL.md"), "outside\n");

			const pluginDir = join(tempRoot, "plugin");
			await mkdir(pluginDir, { recursive: true });
			await writeFile(join(pluginDir, "SKILL.md"), "inside\n");
			await dirSymlink(outsideDir, join(pluginDir, "sneaky"));

			const found = await findSkillFolders(pluginDir);
			expect(found).toEqual([pluginDir]);
		});

		it("entriesFromDirectory size cap does not hang on a symlink loop", async () => {
			const skillDir = join(tempRoot, "loopy3");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "loop test\n");
			await dirSymlink(skillDir, join(skillDir, "cycle"));

			await expect(entriesFromDirectory(skillDir, 50 * 1024 * 1024)).resolves.toBeDefined();
		});

		it("entriesFromDirectory size cap ignores directory symlinks that escape the root", async () => {
			const outsideFile = join(tempRoot, "big-outside.bin");
			await writeFile(outsideFile, Buffer.alloc(1024));

			const skillDir = join(tempRoot, "contained-size");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "contained\n");
			await dirSymlink(tempRoot, join(skillDir, "escape"));

			// If the escape symlink were followed, the outside file would push
			// the total over this tiny limit.
			await expect(entriesFromDirectory(skillDir, 100)).resolves.toBeDefined();
		});

		it.skipIf(!canCreateFileSymlink)(
			"entriesFromDirectory size cap excludes file symlinks that escape the root",
			async () => {
				const outsideFile = join(tempRoot, "huge-outside.bin");
				await writeFile(outsideFile, Buffer.alloc(1024));

				const skillDir = join(tempRoot, "file-escape-size");
				await mkdir(skillDir, { recursive: true });
				await writeFile(join(skillDir, "SKILL.md"), "legit\n");
				await symlink(outsideFile, join(skillDir, "stolen.bin"));

				// The escaped file symlink is dropped from the entries, so it must
				// not count toward the size cap either — a tiny limit that only the
				// external file would exceed must not trip SkillTooLargeError.
				const entries = await entriesFromDirectory(skillDir);
				const expectedTotal = entries
					.filter((e) => !e.isDir)
					.reduce((sum, e) => sum + e.content.length, 0);
				expect(expectedTotal).toBeLessThan(1024);
				await expect(entriesFromDirectory(skillDir, expectedTotal)).resolves.toBeDefined();
			},
		);

		it("entriesFromDirectory throws SkillTooLargeError once files exceed maxBytes", async () => {
			const skillDir = join(tempRoot, "folded-oversize");
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "big.bin"), Buffer.alloc(200));

			await expect(entriesFromDirectory(skillDir, 100)).rejects.toThrow(SkillTooLargeError);
			// Without a limit it reads normally.
			await expect(entriesFromDirectory(skillDir)).resolves.toHaveLength(1);
		});

		it("entriesFromDirectory size cap counts contained files consistently with its own output", async () => {
			const skillDir = join(tempRoot, "folded-consistent");
			const subdir = join(skillDir, "sub");
			await mkdir(subdir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), "root\n"); // 5 bytes
			await writeFile(join(subdir, "f.txt"), "0123456789"); // 10 bytes

			const entries = await entriesFromDirectory(skillDir);
			const totalBytes = entries
				.filter((e) => !e.isDir)
				.reduce((sum, e) => sum + e.content.length, 0);

			await expect(entriesFromDirectory(skillDir, totalBytes)).resolves.toBeDefined();
			await expect(entriesFromDirectory(skillDir, totalBytes - 1)).rejects.toThrow(
				SkillTooLargeError,
			);
		});

		it("entriesFromDirectory rejects when the root does not exist", async () => {
			const ghost = join(tempRoot, "does-not-exist-either");
			await expect(entriesFromDirectory(ghost, 100)).rejects.toThrow();
		});
	});

	describe("findSkillPackagesWithMtime", () => {
		async function mtimeFor(root: string, folder: string): Promise<number | undefined> {
			const pkgs = await findSkillPackagesWithMtime(root);
			return pkgs.find((p) => p.folder === folder)?.newestMtimeMs;
		}

		it("reflects an in-place file edit that leaves the parent dir mtime unchanged", async () => {
			const skillDir = join(tempRoot, "freshness");
			const sub = join(skillDir, "sub");
			await mkdir(sub, { recursive: true });
			const skillMd = join(skillDir, "SKILL.md");
			const nested = join(sub, "helper.py");
			await writeFile(skillMd, "v1\n");
			await writeFile(nested, "print(1)\n");

			// Pin every node to an old, deterministic mtime.
			const old = new Date("2020-01-01T00:00:00Z");
			for (const p of [skillDir, sub, skillMd, nested]) await utimes(p, old, old);
			expect(await mtimeFor(tempRoot, skillDir)).toBe(old.getTime());

			// Edit a nested file in place and bump only that file's mtime —
			// the folder mtime deliberately stays old (the bug scenario).
			const newer = new Date("2021-06-15T12:00:00Z");
			await utimes(nested, newer, newer);

			expect(await mtimeFor(tempRoot, skillDir)).toBe(newer.getTime());
			expect(await mtimeFor(tempRoot, skillDir)).toBeGreaterThan(old.getTime());
		});

		it("a parent package's mtime includes a nested package's newer file", async () => {
			const parent = join(tempRoot, "parent");
			const child = join(parent, "child");
			await mkdir(child, { recursive: true });
			await writeFile(join(parent, "SKILL.md"), "parent");
			await writeFile(join(child, "SKILL.md"), "child");

			const old = new Date("2020-01-01T00:00:00Z");
			for (const p of [parent, child, join(parent, "SKILL.md"), join(child, "SKILL.md")]) {
				await utimes(p, old, old);
			}
			const newer = new Date("2022-03-03T03:03:03Z");
			await utimes(join(child, "SKILL.md"), newer, newer);

			const pkgs = await findSkillPackagesWithMtime(tempRoot);
			expect(pkgs.map((p) => p.folder).sort()).toEqual([parent, child].sort());
			// The nested edit rolls up into the parent's subtree max.
			expect(pkgs.find((p) => p.folder === parent)?.newestMtimeMs).toBe(newer.getTime());
			expect(pkgs.find((p) => p.folder === child)?.newestMtimeMs).toBe(newer.getTime());
		});

		it("returns an empty list for a missing directory", async () => {
			expect(await findSkillPackagesWithMtime(join(tempRoot, "nope"))).toEqual([]);
		});
	});

	describe("computeSkillIdsForRoot", () => {
		it("returns a (folder, id) pair per skill package", async () => {
			const a = join(tempRoot, "skills", "a");
			const b = join(tempRoot, "skills", "b");
			await mkdir(a, { recursive: true });
			await mkdir(b, { recursive: true });
			await writeFile(join(a, "SKILL.md"), "alpha\n");
			await writeFile(join(b, "SKILL.md"), "beta\n");

			const out = await computeSkillIdsForRoot(tempRoot);
			expect(out).toHaveLength(2);
			for (const entry of out) {
				expect(entry.skillId).toMatch(/^[0-9a-f]{64}$/);
			}
			const ids = new Set(out.map((e) => e.skillId));
			expect(ids.size).toBe(2);
		});
	});
});
