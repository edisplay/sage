/**
 * Skill ID computation — content-addressable identifier for a skill package
 * (a folder containing a `SKILL.md`).
 *
 * Algorithm:
 *  1. Walk the package directory in deterministic order (directories then
 *     files, lexicographic).
 *  2. Normalize entry paths (NFC, forward-slash, strip leading "./" / "/").
 *  3. If every entry shares a single top-level prefix, strip it (so the
 *     hash is independent of the wrapping directory name).
 *  4. Drop `skill.sig` (signature artefact).
 *  5. For each entry compute `sha256(content)` (empty buffer for dirs) then
 *     hash the sorted tuple list `(type, path, hash)\n` to produce the
 *     final skill id.
 */

import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { basename, join, relative, resolve, sep } from "node:path";
import type { Logger, PluginInfo } from "./types.js";

export const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__"]);
export const MAX_SKILL_BYTES = 50 * 1024 * 1024; // 50 MB

export class SkillTooLargeError extends Error {}

export function isContained(childReal: string, rootReal: string): boolean {
	return childReal === rootReal || childReal.startsWith(`${rootReal}${sep}`);
}

export interface SkillArchiveEntry {
	entryPath: string;
	isDir: boolean;
	content: Buffer;
}

export interface SkillIdResult {
	skillId: string;
	fileHashes: Record<string, string>;
}

function normalizePath(p: string): string {
	let out = p.replace(/\\/g, "/").normalize("NFC");
	out = out
		.split("/")
		.filter((c) => c !== "" && c !== ".")
		.join("/");
	while (out.startsWith("./") || out.startsWith("/")) {
		out = out.startsWith("./") ? out.slice(2) : out.slice(1);
	}
	return out;
}

/**
 * Walk `dirPath` and return its entries (directories + files) in
 * deterministic lexicographic order. Paths are relative to `dirPath`.
 *
 * Pass `maxBytes` to bound the walk: the running total of contained-file sizes
 * (from the `stat` this walk already performs) is checked *before* each file is
 * read, so an oversized skill throws {@link SkillTooLargeError} without ever
 * loading the offending file into memory. Because this is the single
 * enumeration used for both the size check and the id/zip content, the two can
 * never disagree on which entries count.
 */
export async function entriesFromDirectory(
	dirPath: string,
	maxBytes = Number.POSITIVE_INFINITY,
): Promise<SkillArchiveEntry[]> {
	const absDir = resolve(dirPath);
	const rootReal = await realpath(absDir);
	const entries: SkillArchiveEntry[] = [];
	const visited = new Set<string>();
	let total = 0;

	async function walk(currentPath: string): Promise<void> {
		const real = await realpath(currentPath);
		if (visited.has(real)) return;
		if (!isContained(real, rootReal)) return;
		visited.add(real);

		const items = await readdir(currentPath);
		const dirs: string[] = [];
		const files: Array<{ name: string; size: number }> = [];

		for (const item of items) {
			const fullPath = join(currentPath, item);
			const st = await stat(fullPath);
			if (st.isDirectory()) dirs.push(item);
			else if (st.isFile()) files.push({ name: item, size: st.size });
		}

		dirs.sort();
		files.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

		for (const d of dirs) {
			const fullPath = join(currentPath, d);
			const relPath = relative(absDir, fullPath).replace(/\\/g, "/");
			entries.push({ entryPath: relPath, isDir: true, content: Buffer.alloc(0) });
			await walk(fullPath);
		}

		for (const f of files) {
			const fullPath = join(currentPath, f.name);
			const fileReal = await realpath(fullPath);
			if (!isContained(fileReal, rootReal)) continue;
			total += f.size;
			if (total > maxBytes) throw new SkillTooLargeError();
			const relPath = relative(absDir, fullPath).replace(/\\/g, "/");
			entries.push({
				entryPath: relPath,
				isDir: false,
				content: await readFile(fullPath),
			});
		}
	}

	await walk(absDir);
	return entries;
}

/**
 * Compute the skill id over a list of archive entries. Pure function —
 * no I/O, deterministic given the same input bytes.
 */
export function computeSkillId(entries: SkillArchiveEntry[]): SkillIdResult {
	let normalized: SkillArchiveEntry[] = entries
		.map((e) => ({ ...e, entryPath: normalizePath(e.entryPath) }))
		.filter((e) => e.entryPath !== "");

	if (normalized.length > 0) {
		const topLevel = new Set(normalized.map((e) => e.entryPath.split("/")[0]));
		if (topLevel.size === 1) {
			const prefix = `${[...topLevel][0]}/`;
			normalized = normalized
				.map((e) => ({
					...e,
					entryPath: e.entryPath.startsWith(prefix)
						? e.entryPath.slice(prefix.length)
						: e.entryPath,
				}))
				.filter((e) => e.entryPath !== "");
		}
	}

	normalized = normalized.filter((e) => e.entryPath !== "skill.sig");

	const fileHashes: Record<string, string> = {};
	const treeEntries: Array<{ type: string; entryPath: string; hash: string }> = [];

	for (const e of normalized) {
		const contentHash = createHash("sha256")
			.update(e.isDir ? Buffer.alloc(0) : e.content)
			.digest("hex");
		const entryType = e.isDir ? "dir" : "file";
		treeEntries.push({ type: entryType, entryPath: e.entryPath, hash: contentHash });
		if (!e.isDir) fileHashes[e.entryPath] = contentHash;
	}

	treeEntries.sort((a, b) => (a.entryPath < b.entryPath ? -1 : a.entryPath > b.entryPath ? 1 : 0));

	const skillHasher = createHash("sha256");
	for (const e of treeEntries) {
		skillHasher.update(Buffer.from(`${e.type}\0${e.entryPath}\0${e.hash}\n`, "utf8"));
	}

	return { skillId: skillHasher.digest("hex"), fileHashes };
}

export interface SkillPackage {
	/** Absolute path of a directory that directly contains a `SKILL.md` file. */
	folder: string;
	/** Newest mtime (ms since epoch) across this folder's entire subtree. */
	newestMtimeMs: number;
}

/**
 * Walk `rootDir` recursively (once) and return every directory that directly
 * contains a `SKILL.md` file, each paired with the newest mtime across its whole
 * subtree. Useful when scanning a plugin / extension for embedded skill packages.
 *
 * - Honors {@link SKIP_DIRS} (skips `node_modules`, `.git`, `__pycache__`);
 *   symlink-safe (realpath + visited set + root containment).
 * - Returns packages in discovery order (DFS, lexicographic).
 * - Continues into subdirectories even after a hit, so nested skill packages are
 *   discovered too — and a parent's `newestMtimeMs` includes its nested packages.
 * - The subtree-max mtime is a content-sensitive freshness token: a folder's own
 *   mtime does not advance when a file inside it is edited in place (most
 *   filesystems only bump the dir mtime on add/remove/rename), so taking the max
 *   over the subtree catches in-place edits (file mtime) as well as structural
 *   changes (dir mtime).
 * - Fails-open on filesystem errors (returns whatever was found so far).
 */
export async function findSkillPackagesWithMtime(rootDir: string): Promise<SkillPackage[]> {
	const found: SkillPackage[] = [];

	let rootReal: string;
	try {
		rootReal = await realpath(resolve(rootDir));
	} catch {
		return found;
	}

	const visited = new Set<string>();

	// Returns the newest mtime (ms) across `currentPath`'s subtree, or 0 when it
	// (and everything under it) could not be read.
	async function walk(currentPath: string): Promise<number> {
		let real: string;
		try {
			real = await realpath(currentPath);
		} catch {
			return 0;
		}
		if (visited.has(real)) return 0;
		if (!isContained(real, rootReal)) return 0;
		visited.add(real);

		let st: Stats;
		try {
			st = await stat(currentPath);
		} catch {
			return 0;
		}
		let subtreeMax = st.mtimeMs;
		if (!st.isDirectory()) return subtreeMax;

		let items: string[];
		try {
			items = await readdir(currentPath);
		} catch {
			return subtreeMax;
		}
		items.sort();

		let entry: SkillPackage | undefined;
		if (items.includes("SKILL.md")) {
			try {
				if ((await stat(join(currentPath, "SKILL.md"))).isFile()) {
					entry = { folder: currentPath, newestMtimeMs: 0 };
					found.push(entry);
				}
			} catch {
				// Ignore — fail-open.
			}
		}

		for (const item of items) {
			if (SKIP_DIRS.has(item)) continue;
			const childMax = await walk(join(currentPath, item));
			if (childMax > subtreeMax) subtreeMax = childMax;
		}

		if (entry) entry.newestMtimeMs = subtreeMax;
		return subtreeMax;
	}

	await walk(resolve(rootDir));
	return found;
}

/**
 * Whether a loose skill lives in the user's profile (`personal`, shared across
 * projects) or inside a repository (`project`, this checkout only). Carried as
 * the version segment of a loose-skill key so the same tag in both scopes —
 * e.g. `~/.claude/skills/foo` and `<repo>/.claude/skills/foo` — produces
 * distinct keys instead of one shadowing the other in the scan cache.
 */
export type SkillScope = "personal" | "project";

/**
 * Canonical pseudo-plugin key for a loose skill folder:
 * `skill:<tag>/<relative/path>@<scope>`.
 *
 * `tag` identifies the skill root's directory family (e.g. "claude", "cursor",
 * "copilot", "github"). `scope` ("personal" | "project") records whether it
 * came from the user profile or a repository. Together they keep a single scan
 * that spans several roots — VS Code walks personal `~/.copilot`, `~/.claude`,
 * `~/.agents` plus the repo's `.github`, `.claude`, `.agents` — from emitting
 * one key for two distinct same-named skills; without them they collide in the
 * scan cache (`key:version:lastUpdated`) and one shadows the other, skipping
 * its scan. `tag` distinguishes families; `scope` distinguishes profile vs repo
 * for the same family. Both are always set (even single-root platforms) so
 * adding a root later never changes an existing key's format.
 *
 * Keyed on the path relative to the skills root, not just the basename:
 * discovery recurses, so same-named folders at different depths (e.g.
 * team-a/utils and team-b/utils) would otherwise collide too. Normalized to
 * forward slashes for a stable key that doesn't leak the absolute root.
 */
export function looseSkillKey(
	skillsRoot: string,
	folder: string,
	tag: string,
	scope: SkillScope,
): string {
	const rel =
		relative(resolve(skillsRoot), resolve(folder)).split(sep).join("/") || basename(folder);
	return `skill:${tag}/${rel}@${scope}`;
}

/**
 * Discover loose skill packages under `skillsDir` (e.g. `~/.claude/skills`,
 * `<repo>/.claude/skills`) as pseudo-plugin entries — one per skill folder,
 * keyed by {@link looseSkillKey} under `tag` (the directory family, e.g.
 * "claude") and `scope` ("personal" | "project"). A `SKILL.md` at the root
 * itself is skipped: the root is the container, not a skill. `lastUpdated`
 * derives from each folder's newest subtree mtime, so any edit produces a new
 * scan-cache key (key:version:lastUpdated) and triggers a rescan, mirroring how
 * plugin updates invalidate their cache entries. Fails open to an empty list.
 */
export async function discoverLooseSkills(
	skillsDir: string,
	tag: string,
	scope: SkillScope,
): Promise<PluginInfo[]> {
	const resolvedRoot = resolve(skillsDir);
	const packages = (await findSkillPackagesWithMtime(skillsDir)).filter(
		(p) => resolve(p.folder) !== resolvedRoot,
	);
	return packages.map(({ folder, newestMtimeMs }) => ({
		key: looseSkillKey(resolvedRoot, folder, tag, scope),
		installPath: folder,
		version: scope,
		lastUpdated: new Date(newestMtimeMs).toISOString(),
	}));
}

/**
 * A skill root to scan: its directory, the `tag` that names its family in keys,
 * and the `scope` (profile vs repository) it belongs to.
 */
export interface SkillRoot {
	dir: string;
	tag: string;
	scope: SkillScope;
}

/** Drop skills whose install paths resolve (symlinks followed) to the same folder. */
export async function dedupeSkillsByResolvedPath(skills: PluginInfo[]): Promise<PluginInfo[]> {
	const seen = new Set<string>();
	const out: PluginInfo[] = [];
	for (const skill of skills) {
		let canonical = skill.installPath;
		try {
			canonical = await realpath(skill.installPath);
		} catch {
			// Fall open to the literal path if it can't be resolved.
		}
		if (seen.has(canonical)) continue;
		seen.add(canonical);
		out.push(skill);
	}
	return out;
}

/**
 * Discover loose skill folders across one or more roots (e.g. Claude Code's
 * `~/.claude/skills` + `<project>/.claude/skills`, or VS Code's `~/.copilot`,
 * `~/.claude`, and `~/.agents`). Delegates per root to {@link discoverLooseSkills}
 * — the per-root `tag` keeps same-named skills in different roots from colliding.
 * Fails open per root.
 *
 * A single root is returned as-is (core already dedupes within a root). Across
 * multiple roots the result is deduped on the resolved (symlink-followed)
 * install path, so a skill reachable through more than one root — e.g. a
 * project whose `.claude/skills` is the home directory's — is scanned once,
 * while distinct same-named skills in different roots are all kept (dropping one
 * by name would hide a malicious variant).
 */
export async function discoverLooseSkillsAcrossRoots(roots: SkillRoot[]): Promise<PluginInfo[]> {
	const lists = await Promise.all(
		roots.map(async ({ dir, tag, scope }) => {
			try {
				return await discoverLooseSkills(dir, tag, scope);
			} catch {
				return [];
			}
		}),
	);
	// Single (or no) root: nothing to merge — core already dedupes within a root.
	return lists.length <= 1 ? (lists[0] ?? []) : dedupeSkillsByResolvedPath(lists.flat());
}

/**
 * Convenience: discover + hash in one call. Returns a list of
 * `{ folder, skillId }` pairs for every skill package under `rootDir`.
 * Fails-open per skill — a single unreadable skill folder is skipped, the
 * rest still return.
 */
export async function computeSkillIdsForRoot(
	rootDir: string,
	logger?: Logger,
): Promise<Array<{ folder: string; skillId: string }>> {
	const folders = (await findSkillPackagesWithMtime(rootDir)).map((p) => p.folder);
	const out: Array<{ folder: string; skillId: string }> = [];
	for (const folder of folders) {
		try {
			// Single walk: entriesFromDirectory enforces the size cap inline
			// (rejects before reading the file that crosses it), so there is no
			// separate pre-check walk and no way for the two to diverge.
			const entries = await entriesFromDirectory(folder, MAX_SKILL_BYTES);
			const { skillId } = computeSkillId(entries);
			out.push({ folder, skillId });
		} catch (e) {
			if (e instanceof SkillTooLargeError) {
				logger?.warn("Skill directory exceeds 50 MB limit; skipping", { folder });
			}
			// Fail-open: skip this skill (too large or unreadable), keep going.
		}
	}
	return out;
}
