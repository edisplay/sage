/**
 * Build a ZIP archive from a skill package for upload to the Skill Analyzer.
 *
 * Sage computes the content-addressed skill id from the normalized file tree
 * (see `skill-id.ts`), never from the raw zip bytes — so the zip need not be
 * byte-deterministic (ordering, timestamps and compression are free to vary).
 * The analyzer, however, recomputes an id from the uploaded archive, so the zip
 * must carry the SAME set of entries the disk walk hashes — files AND directory
 * entries — or the two ids diverge. That invariant is why the packers below
 * emit directory entries rather than dropping them.
 */

import { Zip, ZipPassThrough, zipSync } from "fflate";
import { entriesFromDirectory, type SkillArchiveEntry, SkillTooLargeError } from "./skill-id.js";

export { SkillTooLargeError } from "./skill-id.js";

/**
 * Pack already-read archive entries into a ZIP. Pure — no I/O.
 *
 * Directory entries are emitted too (empty, with a trailing slash) so a skill id
 * recomputed from the ZIP matches the disk-walk id: `computeSkillId` counts `dir`
 * tuples (see `skill-id.ts`), so dropping directories here would make the
 * uploaded ZIP hash to a different id than the one Sage keys and looks up by.
 * `entriesFromDirectory` already normalizes paths to forward slashes, which is
 * what the ZIP format expects.
 */
export function zipEntries(entries: SkillArchiveEntry[]): Uint8Array {
	const files: Record<string, Uint8Array> = {};
	for (const entry of entries) {
		const name = entry.isDir ? `${entry.entryPath.replace(/\/*$/, "")}/` : entry.entryPath;
		files[name] = entry.isDir ? new Uint8Array(0) : entry.content;
	}
	return zipSync(files, { level: 0 });
}

/**
 * Read a skill folder and pack it into a ZIP ready for upload.
 *
 * Honors the same directory walk as skill-id computation (deterministic order,
 * symlink-escape protection via `entriesFromDirectory`).
 */
export async function zipSkillFolder(folder: string): Promise<Uint8Array> {
	const entries = await entriesFromDirectory(folder);
	return zipEntries(entries);
}

/**
 * Stream-zip entries, aborting early if the output exceeds `maxBytes`.
 *
 * Uses fflate's `Zip` + `ZipPassThrough` (store mode, no compression) so the
 * running output size is tracked chunk-by-chunk. Throws {@link SkillTooLargeError}
 * as soon as the limit is crossed — the full zip is never materialized in that
 * case.
 */
export function zipEntriesWithLimit(entries: SkillArchiveEntry[], maxBytes: number): Uint8Array {
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;

	const zip = new Zip((err, chunk) => {
		if (err) throw err;
		totalBytes += chunk.length;
		chunks.push(chunk);
	});

	for (const entry of entries) {
		// Emit directory entries too (empty, trailing slash) so the ZIP hashes to
		// the same skill id as the disk walk — see zipEntries for the rationale.
		const name = entry.isDir ? `${entry.entryPath.replace(/\/*$/, "")}/` : entry.entryPath;
		const file = new ZipPassThrough(name);
		zip.add(file);
		file.push(entry.isDir ? new Uint8Array(0) : entry.content, true);
		if (totalBytes > maxBytes) throw new SkillTooLargeError();
	}
	zip.end();
	if (totalBytes > maxBytes) throw new SkillTooLargeError();

	const result = new Uint8Array(totalBytes);
	let offset = 0;
	for (const chunk of chunks) {
		result.set(chunk, offset);
		offset += chunk.length;
	}
	return result;
}
