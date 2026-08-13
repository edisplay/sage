import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	decideSkillUploadRollout,
	INSTALL_STATE_SCHEMA_VERSION,
	type InstallState,
	loadInstallState,
	resetSkillUploadRolloutForTest,
	resolveSkillUploadRollout,
	saveInstallState,
	takePendingNotices,
} from "../install-state.js";
import { SKILL_UPLOAD_NOTICE } from "../notices.js";

const SKILL_UPLOAD_NOTICE_ID = SKILL_UPLOAD_NOTICE.id;

function freshState(): InstallState {
	return { schemaVersion: INSTALL_STATE_SCHEMA_VERSION, notices: {} };
}

function noticedState(version = "0.12.0"): InstallState {
	return {
		schemaVersion: INSTALL_STATE_SCHEMA_VERSION,
		lastRunVersion: version,
		notices: { [SKILL_UPLOAD_NOTICE_ID]: { noticed: true, version } },
	};
}

describe("decideSkillUploadRollout (pure)", () => {
	it("first session (no notice): shows notice, uploads nothing, records noticed", () => {
		const d = decideSkillUploadRollout(freshState(), { version: "0.12.0" });
		expect(d.showNotice).toBe(true);
		expect(d.uploadActive).toBe(false);
		expect(d.nextState?.notices[SKILL_UPLOAD_NOTICE_ID]).toEqual({
			noticed: true,
			version: "0.12.0",
		});
	});

	it("next session (already noticed): activates upload, no notice, no write", () => {
		const d = decideSkillUploadRollout(noticedState("0.12.0"), { version: "0.12.0" });
		expect(d.showNotice).toBe(false);
		expect(d.uploadActive).toBe(true);
		expect(d.nextState).toBeNull();
	});

	it("explicit config true wins: uploads, no notice, no state machine", () => {
		const d = decideSkillUploadRollout(freshState(), {
			explicitConfig: true,
			explicitValue: true,
			version: "0.12.0",
		});
		expect(d.uploadActive).toBe(true);
		expect(d.showNotice).toBe(false);
		// No notice record is written when config is explicit.
		expect(d.nextState?.notices[SKILL_UPLOAD_NOTICE_ID]).toBeUndefined();
	});

	it("explicit config false wins: never uploads, never notices", () => {
		const d = decideSkillUploadRollout(freshState(), {
			explicitConfig: true,
			explicitValue: false,
			version: "0.12.0",
		});
		expect(d.uploadActive).toBe(false);
		expect(d.showNotice).toBe(false);
	});

	it("explicit config value wins even after the install was noticed", () => {
		const d = decideSkillUploadRollout(noticedState(), {
			explicitConfig: true,
			explicitValue: false,
		});
		expect(d.uploadActive).toBe(false);
		expect(d.showNotice).toBe(false);
	});

	it("bumps last_run_version on a steady-state activated session", () => {
		const d = decideSkillUploadRollout(noticedState("0.12.0"), { version: "0.13.0" });
		expect(d.uploadActive).toBe(true);
		expect(d.nextState?.lastRunVersion).toBe("0.13.0");
	});
});

describe("install state persistence", () => {
	let sageDir: string;

	beforeEach(async () => {
		sageDir = await mkdtemp(join(tmpdir(), "sage-install-state-"));
	});
	afterEach(async () => {
		await rm(sageDir, { recursive: true, force: true });
	});

	it("round-trips through disk with snake_case on disk", async () => {
		await saveInstallState(noticedState("0.12.0"), sageDir);
		const onDisk = JSON.parse(await readFile(join(sageDir, "install-state.json"), "utf-8"));
		expect(onDisk.schema_version).toBe(INSTALL_STATE_SCHEMA_VERSION);
		expect(onDisk.last_run_version).toBe("0.12.0");
		expect(onDisk.notices[SKILL_UPLOAD_NOTICE_ID]).toEqual({ noticed: true, version: "0.12.0" });

		const loaded = await loadInstallState(sageDir);
		expect(loaded).toEqual(noticedState("0.12.0"));
	});

	it("fails open to an empty state on a missing file", async () => {
		const loaded = await loadInstallState(sageDir);
		expect(loaded.notices).toEqual({});
	});

	it("fails open to an empty state on a corrupt file", async () => {
		await writeFile(join(sageDir, "install-state.json"), "{ not json");
		const loaded = await loadInstallState(sageDir);
		expect(loaded.notices).toEqual({});
	});
});

describe("resolveSkillUploadRollout (orchestrator)", () => {
	let sageDir: string;
	let configPath: string;

	beforeEach(async () => {
		sageDir = await mkdtemp(join(tmpdir(), "sage-rollout-"));
		configPath = join(sageDir, "config.json");
		resetSkillUploadRolloutForTest();
	});
	afterEach(async () => {
		resetSkillUploadRolloutForTest();
		await rm(sageDir, { recursive: true, force: true });
	});

	it("existing/new install: first session notices without uploading, next session uploads", async () => {
		// Session 1 (fresh state file, no config).
		const first = await resolveSkillUploadRollout({ sageDirPath: sageDir, version: "0.12.0" });
		expect(first).toEqual({ uploadActive: false, showNotice: true, deferUnknownSkills: true });
		const persisted = await loadInstallState(sageDir);
		expect(persisted.notices[SKILL_UPLOAD_NOTICE_ID]?.noticed).toBe(true);

		// Session 2 (new process → clear the in-process memo).
		resetSkillUploadRolloutForTest();
		const second = await resolveSkillUploadRollout({ sageDirPath: sageDir, version: "0.12.0" });
		expect(second).toEqual({ uploadActive: true, showNotice: false, deferUnknownSkills: false });
	});

	it("in-process guard: a second session-start fire returns the same result (no same-session activation)", async () => {
		// Fire 1 (e.g. OpenClaw gateway_start): notice session.
		const fire1 = await resolveSkillUploadRollout({ sageDirPath: sageDir, version: "0.12.0" });
		// Fire 2 (e.g. session_start, same process) — disk now says noticed:true,
		// but the memo must keep upload OFF so the notice and activation don't
		// collapse into one wall-clock session.
		const fire2 = await resolveSkillUploadRollout({ sageDirPath: sageDir, version: "0.12.0" });
		expect(fire1).toEqual({ uploadActive: false, showNotice: true, deferUnknownSkills: true });
		expect(fire2).toEqual(fire1);
	});

	it("user disables during grace: explicit upload_enabled=false never uploads", async () => {
		await writeFile(configPath, JSON.stringify({ skill_check: { upload_enabled: false } }));
		const r = await resolveSkillUploadRollout({
			sageDirPath: sageDir,
			configPath,
			version: "0.12.0",
		});
		expect(r).toEqual({ uploadActive: false, showNotice: false, deferUnknownSkills: false });
	});

	it("explicit upload_enabled=true uploads immediately with no notice", async () => {
		await writeFile(configPath, JSON.stringify({ skill_check: { upload_enabled: true } }));
		const r = await resolveSkillUploadRollout({
			sageDirPath: sageDir,
			configPath,
			version: "0.12.0",
		});
		expect(r).toEqual({ uploadActive: true, showNotice: false, deferUnknownSkills: false });
	});

	it("commitNotice=false: no persist, no scan-time surface, but STILL defers the grace cache", async () => {
		const r = await resolveSkillUploadRollout({
			sageDirPath: sageDir,
			version: "0.12.0",
			commitNotice: false,
		});
		// uploadActive reflects the on-disk flag (still false) and the scan does not
		// surface the notice itself — but deferUnknownSkills must stay true so the
		// grace scan doesn't cache unknown skills as clean (regression guard).
		expect(r).toEqual({ uploadActive: false, showNotice: false, deferUnknownSkills: true });
		const persisted = await loadInstallState(sageDir);
		expect(persisted.notices[SKILL_UPLOAD_NOTICE_ID]?.noticed).toBeUndefined();
	});

	it("honors a mid-process explicit opt-out even after the memo activated upload", async () => {
		// A pre-activated install (already noticed) → the implicit session memoizes
		// uploadActive: true for the process lifetime.
		await saveInstallState(noticedState("0.12.0"), sageDir);
		const first = await resolveSkillUploadRollout({
			sageDirPath: sageDir,
			configPath,
			version: "0.12.0",
		});
		expect(first.uploadActive).toBe(true);

		// User sets upload_enabled: false mid-process. The memo says true, but the
		// explicit config is re-read every call and must win — a long-lived gateway
		// honors the opt-out without a restart (regression guard).
		await writeFile(configPath, JSON.stringify({ skill_check: { upload_enabled: false } }));
		const second = await resolveSkillUploadRollout({
			sageDirPath: sageDir,
			configPath,
			version: "0.12.0",
		});
		expect(second).toEqual({ uploadActive: false, showNotice: false, deferUnknownSkills: false });
	});
});

describe("takePendingNotices (generic delivery-time resolver)", () => {
	let sageDir: string;
	let configPath: string;

	beforeEach(async () => {
		sageDir = await mkdtemp(join(tmpdir(), "sage-take-notices-"));
		configPath = join(sageDir, "config.json");
	});
	afterEach(async () => {
		await rm(sageDir, { recursive: true, force: true });
	});

	it("returns and commits an unshown eligible notice, then is idempotent", async () => {
		const first = await takePendingNotices({ sageDirPath: sageDir, configPath });
		expect(first).toContain(SKILL_UPLOAD_NOTICE_ID);
		const persisted = await loadInstallState(sageDir);
		expect(persisted.notices[SKILL_UPLOAD_NOTICE_ID]?.noticed).toBe(true);

		// Second call: already shown → nothing returned, nothing new written.
		const second = await takePendingNotices({ sageDirPath: sageDir, configPath });
		expect(second).toEqual([]);
	});

	it("skips a notice that is not eligible (explicit upload_enabled set)", async () => {
		await writeFile(configPath, JSON.stringify({ skill_check: { upload_enabled: false } }));
		const ids = await takePendingNotices({ sageDirPath: sageDir, configPath });
		expect(ids).not.toContain(SKILL_UPLOAD_NOTICE_ID);
		// Not shown → flag not committed, so it can still surface if the user later
		// removes the explicit setting.
		const persisted = await loadInstallState(sageDir);
		expect(persisted.notices[SKILL_UPLOAD_NOTICE_ID]?.noticed).toBeUndefined();
	});
});
