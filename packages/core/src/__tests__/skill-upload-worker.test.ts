import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SkillAnalyzeResult } from "../clients/skill-analyze.js";
import { addPending, isPending, loadPendingMarker, savePendingMarker } from "../skill-pending.js";
import { runSkillUploadWorker, type SkillAnalyzer } from "../skill-upload-worker.js";
import { getVerdict, loadSkillVerdictCache } from "../skill-verdict-cache.js";

const ID = "a".repeat(64);

const CRITICAL: SkillAnalyzeResult = {
	jobId: "job-1",
	verdict: "CRITICAL",
	summary: "reverse shell",
};

describe("runSkillUploadWorker", () => {
	let dir: string;
	let pendingPath: string;
	let verdictCachePath: string;
	let skillFolder: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-worker-"));
		pendingPath = join(dir, "skill_pending.json");
		verdictCachePath = join(dir, "skill_verdict_cache.json");
		skillFolder = join(dir, "my-skill");
		await mkdir(skillFolder);
		await writeFile(join(skillFolder, "SKILL.md"), "# skill");

		const marker = { entries: {} };
		addPending(marker, ID, skillFolder);
		await savePendingMarker(marker, pendingPath);
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("uploads pending skill, caches verdict, clears marker", async () => {
		const client: SkillAnalyzer = { analyzeZip: vi.fn().mockResolvedValue(CRITICAL) };

		const result = await runSkillUploadWorker({ pendingPath, verdictCachePath, client });

		expect(result).toEqual({ analyzed: 1, retained: 0 });

		const cache = await loadSkillVerdictCache(verdictCachePath);
		expect(getVerdict(cache, ID)?.verdict).toBe("CRITICAL");
		expect(getVerdict(cache, ID)?.summary).toBe("reverse shell");

		const marker = await loadPendingMarker(pendingPath);
		expect(isPending(marker, ID)).toBe(false); // cleared
	});

	it("passes the skill id and a slug to the analyzer", async () => {
		const analyzeZip = vi.fn().mockResolvedValue(CRITICAL);
		await runSkillUploadWorker({ pendingPath, verdictCachePath, client: { analyzeZip } });

		const [zip, metadata] = analyzeZip.mock.calls[0];
		expect(zip).toBeInstanceOf(Uint8Array);
		expect(metadata).toEqual({ skillId: ID, slug: "my-skill" });
	});

	it("fail-open: keeps skill pending and writes no verdict when analyzer returns null", async () => {
		const client: SkillAnalyzer = { analyzeZip: vi.fn().mockResolvedValue(null) };

		const result = await runSkillUploadWorker({ pendingPath, verdictCachePath, client });

		expect(result).toEqual({ analyzed: 0, retained: 1 });
		const marker = await loadPendingMarker(pendingPath);
		expect(isPending(marker, ID)).toBe(true); // retained for retry
		const cache = await loadSkillVerdictCache(verdictCachePath);
		expect(getVerdict(cache, ID)).toBeNull();
	});

	it("fail-open: one failing skill does not block the others", async () => {
		const ID2 = "b".repeat(64);
		const folder2 = join(dir, "skill-2");
		await mkdir(folder2);
		await writeFile(join(folder2, "SKILL.md"), "# two");
		const marker = await loadPendingMarker(pendingPath);
		addPending(marker, ID2, folder2);
		await savePendingMarker(marker, pendingPath);

		const analyzeZip = vi
			.fn()
			.mockRejectedValueOnce(new Error("boom")) // first skill throws
			.mockResolvedValueOnce(CRITICAL); // second succeeds
		const result = await runSkillUploadWorker({
			pendingPath,
			verdictCachePath,
			client: { analyzeZip },
		});

		expect(result.analyzed).toBe(1);
		expect(result.retained).toBe(1);
	});

	it("removes oversized skill from pending and caches a sentinel verdict", async () => {
		await writeFile(join(skillFolder, "large.bin"), Buffer.alloc(51 * 1024 * 1024));
		const client: SkillAnalyzer = { analyzeZip: vi.fn() };

		const result = await runSkillUploadWorker({ pendingPath, verdictCachePath, client });

		expect(result).toEqual({ analyzed: 0, retained: 0 });
		expect(client.analyzeZip).not.toHaveBeenCalled();
		// Skill must be removed from pending so deferCache stops firing.
		const marker = await loadPendingMarker(pendingPath);
		expect(isPending(marker, ID)).toBe(false);
		// Sentinel verdict (no verdict string) must be cached so the scanner
		// doesn't re-enqueue it on the next session.
		const cache = await loadSkillVerdictCache(verdictCachePath);
		const entry = getVerdict(cache, ID);
		expect(entry).not.toBeNull();
		expect(entry?.verdict).toBeUndefined();
	});

	it("processes 4 skills across two batches, all analyzed and cleared", async () => {
		const ids = [ID, "b".repeat(64), "c".repeat(64), "d".repeat(64)];
		const folders = [skillFolder];
		for (let i = 1; i < 4; i++) {
			const f = join(dir, `skill-${i}`);
			await mkdir(f);
			await writeFile(join(f, "SKILL.md"), `# skill ${i}`);
			folders.push(f);
		}
		const marker = await loadPendingMarker(pendingPath);
		for (let i = 1; i < 4; i++) addPending(marker, ids[i], folders[i]);
		await savePendingMarker(marker, pendingPath);

		const analyzeZip = vi.fn().mockResolvedValue(CRITICAL);
		const result = await runSkillUploadWorker({
			pendingPath,
			verdictCachePath,
			client: { analyzeZip },
		});

		expect(result).toEqual({ analyzed: 4, retained: 0 });
		expect(analyzeZip).toHaveBeenCalledTimes(4);
		const cache = await loadSkillVerdictCache(verdictCachePath);
		for (const id of ids) expect(getVerdict(cache, id)?.verdict).toBe("CRITICAL");
		const fresh = await loadPendingMarker(pendingPath);
		for (const id of ids) expect(isPending(fresh, id)).toBe(false);
	});

	it("no-op when nothing is pending", async () => {
		await savePendingMarker({ entries: {} }, pendingPath);
		const client: SkillAnalyzer = { analyzeZip: vi.fn() };
		const result = await runSkillUploadWorker({ pendingPath, verdictCachePath, client });
		expect(result).toEqual({ analyzed: 0, retained: 0 });
		expect(client.analyzeZip).not.toHaveBeenCalled();
	});
});
