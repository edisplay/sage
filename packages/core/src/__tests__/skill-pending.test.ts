import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	addPending,
	isPending,
	listPending,
	loadPendingMarker,
	PENDING_TTL_MS,
	type PendingMarker,
	removePending,
	savePendingMarker,
} from "../skill-pending.js";

const ID_A = "a".repeat(64);
const ID_B = "b".repeat(64);

describe("skill-pending", () => {
	let dir: string;
	let path: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-pending-"));
		path = join(dir, "skill_pending.json");
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("pure helpers: add / isPending / remove / list", () => {
		const marker: PendingMarker = { entries: {} };
		expect(isPending(marker, ID_A)).toBe(false);

		addPending(marker, ID_A, "C:/skills/a");
		expect(isPending(marker, ID_A)).toBe(true);
		expect(listPending(marker)).toEqual([{ skillId: ID_A, folder: "C:/skills/a" }]);

		removePending(marker, ID_A);
		expect(isPending(marker, ID_A)).toBe(false);
		removePending(marker, ID_A); // no-op
	});

	it("round-trips through disk (save → load), including origin", async () => {
		const marker: PendingMarker = { entries: {} };
		addPending(marker, ID_A, "C:/skills/a", {
			agentRuntime: "cursor",
			containerKey: "skill:a@local",
		});
		addPending(marker, ID_B, "C:/skills/b");
		await savePendingMarker(marker, path);

		const loaded = await loadPendingMarker(path);
		expect(isPending(loaded, ID_A)).toBe(true);
		expect(isPending(loaded, ID_B)).toBe(true);
		expect(loaded.entries[ID_A]?.folder).toBe("C:/skills/a");
		expect(loaded.entries[ID_A]?.agentRuntime).toBe("cursor");
		expect(loaded.entries[ID_A]?.containerKey).toBe("skill:a@local");
		expect(loaded.entries[ID_B]?.agentRuntime).toBeUndefined();

		const listed = listPending(loaded);
		expect(listed.find((s) => s.skillId === ID_A)?.containerKey).toBe("skill:a@local");
	});

	it("persists snake_case on disk", async () => {
		const marker: PendingMarker = { entries: {} };
		addPending(marker, ID_A, "C:/skills/a");
		await savePendingMarker(marker, path);

		const onDisk = JSON.parse(await readFile(path, "utf-8"));
		expect(onDisk.schema_version).toBe(1);
		expect(onDisk.entries[ID_A]).toHaveProperty("submitted_at");
		expect(onDisk.entries[ID_A]).toHaveProperty("folder");
	});

	it("drops stale entries (older than TTL) on load", async () => {
		const stale = new Date(Date.now() - PENDING_TTL_MS - 1000).toISOString();
		await writeFile(
			path,
			JSON.stringify({
				schema_version: 1,
				entries: {
					[ID_A]: { folder: "C:/skills/a", submitted_at: stale },
					[ID_B]: { folder: "C:/skills/b", submitted_at: new Date().toISOString() },
				},
			}),
		);

		const loaded = await loadPendingMarker(path);
		expect(isPending(loaded, ID_A)).toBe(false); // stale → dropped
		expect(isPending(loaded, ID_B)).toBe(true);
	});

	it("fails open to empty marker on missing or corrupt file", async () => {
		expect((await loadPendingMarker(join(dir, "nope.json"))).entries).toEqual({});
		await writeFile(path, "{ not json");
		expect((await loadPendingMarker(path)).entries).toEqual({});
	});
});
