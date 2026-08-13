import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strFromU8, unzipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { computeSkillId, entriesFromDirectory, type SkillArchiveEntry } from "../skill-id.js";
import {
	SkillTooLargeError,
	zipEntries,
	zipEntriesWithLimit,
	zipSkillFolder,
} from "../skill-zip.js";

describe("skill-zip", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-zip-"));
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("round-trips a skill folder: files and content are preserved", async () => {
		await writeFile(join(dir, "SKILL.md"), "# My Skill\nhello");
		await writeFile(join(dir, "script.js"), "console.log('hi')");

		const zip = await zipSkillFolder(dir);
		const out = unzipSync(zip);

		// Wrapping temp-dir name is stripped by entriesFromDirectory's single
		// top-level prefix rule, so paths are relative to the skill root.
		expect(Object.keys(out).sort()).toEqual(["SKILL.md", "script.js"]);
		expect(strFromU8(out["SKILL.md"] ?? new Uint8Array())).toBe("# My Skill\nhello");
		expect(strFromU8(out["script.js"] ?? new Uint8Array())).toBe("console.log('hi')");
	});

	it("preserves nested paths with forward slashes", async () => {
		// A root-level file plus a subfolder means the entries do NOT share a
		// single top-level prefix, so entriesFromDirectory keeps paths as-is.
		await writeFile(join(dir, "SKILL.md"), "root");
		await mkdir(join(dir, "references"));
		await writeFile(join(dir, "references", "note.txt"), "note");

		const entries = await entriesFromDirectory(dir);
		const out = unzipSync(zipEntries(entries));

		for (const key of Object.keys(out)) {
			expect(key).not.toContain("\\");
		}
		// The `references/` directory entry is emitted so the zip hashes to the
		// same skill id as the disk walk (which counts `dir` tuples).
		expect(Object.keys(out).sort()).toEqual(["SKILL.md", "references/", "references/note.txt"]);
		expect(strFromU8(out["references/note.txt"] ?? new Uint8Array())).toBe("note");
	});

	it("emits directory entries (empty, trailing slash) so ids stay consistent", () => {
		const zip = zipEntries([
			{ entryPath: "dir", isDir: true, content: Buffer.alloc(0) },
			{ entryPath: "dir/file.txt", isDir: false, content: Buffer.from("x") },
		]);
		const out = unzipSync(zip);
		expect(Object.keys(out).sort()).toEqual(["dir/", "dir/file.txt"]);
		expect(out["dir/"]?.length).toBe(0);
		expect(strFromU8(out["dir/file.txt"] ?? new Uint8Array())).toBe("x");
	});

	it("zip round-trips to the same skill id as the disk walk", async () => {
		await writeFile(join(dir, "SKILL.md"), "root");
		await mkdir(join(dir, "scripts"));
		await writeFile(join(dir, "scripts", "run.py"), "print(1)\r\n"); // CRLF preserved verbatim

		const entries = await entriesFromDirectory(dir);
		const diskWalkId = computeSkillId(entries).skillId;

		// Reconstruct entries from the zip the way the analyzer would, then recompute.
		const out = unzipSync(zipEntries(entries));
		const fromZip: SkillArchiveEntry[] = Object.entries(out).map(([entryPath, content]) => ({
			entryPath,
			isDir: entryPath.endsWith("/"),
			content: Buffer.from(content),
		}));
		expect(computeSkillId(fromZip).skillId).toBe(diskWalkId);
	});

	it("produces an empty but valid zip for no files", () => {
		const out = unzipSync(zipEntries([]));
		expect(Object.keys(out)).toEqual([]);
	});

	describe("zipEntriesWithLimit", () => {
		it("produces correct output when under the limit", () => {
			const entries = [
				{ entryPath: "SKILL.md", isDir: false, content: Buffer.from("hello") },
				{ entryPath: "script.js", isDir: false, content: Buffer.from("world") },
			];
			const zip = zipEntriesWithLimit(entries, 1024 * 1024);
			const out = unzipSync(zip);
			expect(Object.keys(out).sort()).toEqual(["SKILL.md", "script.js"]);
			expect(strFromU8(out["SKILL.md"] ?? new Uint8Array())).toBe("hello");
		});

		it("emits directory entries (empty, trailing slash) like zipEntries", () => {
			const entries = [
				{ entryPath: "scripts", isDir: true, content: Buffer.alloc(0) },
				{ entryPath: "scripts/run.py", isDir: false, content: Buffer.from("print(1)") },
			];
			const out = unzipSync(zipEntriesWithLimit(entries, 1024 * 1024));
			expect(Object.keys(out).sort()).toEqual(["scripts/", "scripts/run.py"]);
			expect(out["scripts/"]?.length).toBe(0);
		});

		it("throws SkillTooLargeError when output exceeds the limit", () => {
			const entries = [{ entryPath: "large.bin", isDir: false, content: Buffer.alloc(1024) }];
			expect(() => zipEntriesWithLimit(entries, 100)).toThrow(SkillTooLargeError);
		});

		it("accepts output that exactly meets the limit", () => {
			const content = Buffer.from("x");
			const entries = [{ entryPath: "f.txt", isDir: false, content }];
			const full = zipEntriesWithLimit(entries, Infinity);
			expect(() => zipEntriesWithLimit(entries, full.byteLength)).not.toThrow();
		});
	});
});
