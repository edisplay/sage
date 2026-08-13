/**
 * Shared JSONL log file writer.
 */

import { appendFile, mkdir, rename, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { withFileLock } from "./file-utils.js";

export interface JsonlLogConfig {
	path: string;
	max_bytes: number;
	max_files: number;
}

const writeQueues = new Map<string, Promise<void>>();

async function shouldRotate(
	filePath: string,
	maxBytes: number,
	maxFiles: number,
): Promise<boolean> {
	if (maxBytes <= 0 || maxFiles <= 0) return false;

	try {
		const s = await stat(filePath);
		return s.size >= maxBytes;
	} catch {
		return false;
	}
}

/**
 * Classic logrotate: shift numbered backups and rename active file to .1.
 * Rotation is guarded by a short cross-process lock; writes themselves remain
 * normal append-mode writes. All renames ignore ENOENT so missing files and
 * residual races stay fail-open.
 */
async function rotateIfNeeded(filePath: string, maxBytes: number, maxFiles: number): Promise<void> {
	if (!(await shouldRotate(filePath, maxBytes, maxFiles))) return;

	await withFileLock(filePath, async () => {
		if (!(await shouldRotate(filePath, maxBytes, maxFiles))) return;

		try {
			await unlink(`${filePath}.${maxFiles}`);
		} catch {
			// ENOENT OK
		}

		for (let i = maxFiles - 1; i >= 1; i--) {
			try {
				await rename(`${filePath}.${i}`, `${filePath}.${i + 1}`);
			} catch {
				// ENOENT OK
			}
		}

		try {
			await rename(filePath, `${filePath}.1`);
		} catch {
			// ENOENT OK
		}
	});
}

async function appendJsonlEntryNow(
	path: string,
	config: JsonlLogConfig,
	entry: object,
): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	await rotateIfNeeded(path, config.max_bytes, config.max_files);
	await appendFile(path, `${JSON.stringify(entry)}\n`);
}

export async function appendJsonlEntry(config: JsonlLogConfig, entry: object): Promise<void> {
	const path = resolvePath(config.path);
	const previousWrite = writeQueues.get(path) ?? Promise.resolve();
	const nextWrite = previousWrite
		.catch(() => {
			// Keep later best-effort log writes moving if an earlier write failed.
		})
		.then(() => appendJsonlEntryNow(path, config, entry));

	writeQueues.set(path, nextWrite);
	try {
		await nextWrite;
	} finally {
		if (writeQueues.get(path) === nextWrite) writeQueues.delete(path);
	}
}
