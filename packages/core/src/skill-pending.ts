/**
 * Pending marker for skills handed off to the Skill Analyzer upload worker.
 *
 * Global (NOT per-session), keyed by content-addressed skill id. Purpose is
 * dedup: a skill already being analyzed must not be re-submitted by another
 * session while the worker is still running. Entries expire after
 * {@link PENDING_TTL_MS} so a skill whose worker died gets retried later.
 *
 * Cross-process by design: written by the session-start scan, read and cleared
 * by the detached upload worker (a separate process) — hence a file on disk,
 * not in-memory state. All writes are atomic (temp + rename).
 *
 * Usage follows the plugin-scan-cache pattern: `loadPendingMarker` once, mutate
 * the in-memory object with the pure helpers, then `savePendingMarker` once.
 */

import { unlink } from "node:fs/promises";
import { join } from "node:path";
import { isFreshTimestamp, resolvePath, SAGE_DIR } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

const SCHEMA_VERSION = 1;
/** A pending entry older than this is considered stale (dead worker) and retried. */
export const PENDING_TTL_MS = 60 * 60 * 1000; // 1 hour

export interface SkillPendingEntry {
	/** Absolute path to the skill folder the worker should zip and upload. */
	folder: string;
	/** ISO timestamp of when the skill was queued; drives TTL pruning. */
	submittedAt: string;
	/** Agent runtime whose scan queued this skill (e.g. "cursor"). */
	agentRuntime?: string;
	/** Pseudo-plugin key of the container the skill was found in. */
	containerKey?: string;
}

export interface PendingMarker {
	entries: Record<string, SkillPendingEntry>;
}

function defaultPendingPath(): string {
	return join(resolvePath(SAGE_DIR), "skill_pending.json");
}

/**
 * Load the pending marker, dropping entries older than {@link PENDING_TTL_MS}.
 * Fails-open: returns an empty marker on a missing/corrupt file.
 */
export async function loadPendingMarker(
	pendingPath = defaultPendingPath(),
	logger: Logger = nullLogger,
): Promise<PendingMarker> {
	let raw: string;
	try {
		raw = await getFileContent(pendingPath);
	} catch {
		return { entries: {} };
	}

	try {
		const data = JSON.parse(raw) as Record<string, unknown>;
		const rawEntries = (data.entries ?? {}) as Record<string, Record<string, unknown>>;
		const now = Date.now();
		const entries: Record<string, SkillPendingEntry> = {};
		for (const [skillId, entry] of Object.entries(rawEntries)) {
			const folder = entry.folder as string | undefined;
			const submittedAt = entry.submitted_at as string | undefined;
			if (!folder || !submittedAt) continue;
			const ts = Date.parse(submittedAt);
			if (!isFreshTimestamp(ts, PENDING_TTL_MS, now)) continue;
			entries[skillId] = {
				folder,
				submittedAt,
				agentRuntime: typeof entry.agent_runtime === "string" ? entry.agent_runtime : undefined,
				containerKey: typeof entry.container_key === "string" ? entry.container_key : undefined,
			};
		}
		return { entries };
	} catch (e) {
		logger.warn(`Failed to load pending marker from ${pendingPath}`, { error: String(e) });
		return { entries: {} };
	}
}

/**
 * Persist the marker. Deletes the file when empty so a clean state leaves no
 * residue on disk. `loadPendingMarker` fails-open on a missing file, so
 * absence is equivalent to an empty marker.
 * Fails-open: a write/delete error must never break the scan or worker.
 */
export async function savePendingMarker(
	marker: PendingMarker,
	pendingPath = defaultPendingPath(),
	logger: Logger = nullLogger,
): Promise<void> {
	if (Object.keys(marker.entries).length === 0) {
		try {
			await unlink(pendingPath);
		} catch (e: unknown) {
			if (!e || typeof e !== "object" || (e as { code?: string }).code !== "ENOENT") {
				logger.warn(`Failed to delete empty pending marker at ${pendingPath}`, {
					error: String(e),
				});
			}
		}
		return;
	}

	try {
		const data = {
			schema_version: SCHEMA_VERSION,
			entries: Object.fromEntries(
				Object.entries(marker.entries).map(([skillId, entry]) => [
					skillId,
					{
						folder: entry.folder,
						submitted_at: entry.submittedAt,
						agent_runtime: entry.agentRuntime,
						container_key: entry.containerKey,
					},
				]),
			),
		};
		await atomicWriteJson(pendingPath, data);
	} catch (e) {
		logger.warn(`Failed to save pending marker to ${pendingPath}`, { error: String(e) });
	}
}

/** True if the skill is already queued for analysis (pure). */
export function isPending(marker: PendingMarker, skillId: string): boolean {
	return skillId in marker.entries;
}

/** Where a queued skill was discovered; travels with the entry to the worker. */
export interface SkillPendingOrigin {
	agentRuntime?: string;
	containerKey?: string;
}

/** Queue a skill for analysis (pure; idempotent — refreshes the timestamp). */
export function addPending(
	marker: PendingMarker,
	skillId: string,
	folder: string,
	origin: SkillPendingOrigin = {},
): void {
	marker.entries[skillId] = {
		folder,
		submittedAt: new Date().toISOString(),
		agentRuntime: origin.agentRuntime,
		containerKey: origin.containerKey,
	};
}

/** Remove a skill from the marker once analyzed (pure; no-op if absent). */
export function removePending(marker: PendingMarker, skillId: string): void {
	delete marker.entries[skillId];
}

/** List queued skills (id + folder + origin) — the worker's work list. */
export function listPending(
	marker: PendingMarker,
): Array<SkillPendingOrigin & { skillId: string; folder: string }> {
	return Object.entries(marker.entries).map(([skillId, entry]) => ({
		skillId,
		folder: entry.folder,
		agentRuntime: entry.agentRuntime,
		containerKey: entry.containerKey,
	}));
}
