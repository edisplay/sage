/**
 * Integration tests for sage-statusline cleanup behavior.
 *
 * Spawns the bundled sage-statusline.cjs as a child process with a fake HOME
 * to verify that uninstall/disable cleanup works correctly.
 *
 * NOTE: The script resolves its plugin root via __dirname and compares it
 * against ~/.claude/ to decide whether it's a marketplace install. Cleanup
 * tests copy the bundle under tmpHome/.claude/plugins/ so the check passes.
 * The --plugin-dir test uses the repo path directly.
 */

import { execFile } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { makeTmpDir } from "../../../core/src/__tests__/test-utils.js";

const STATUSLINE_SCRIPT = resolve(__dirname, "..", "..", "dist", "sage-statusline.cjs");
const PLUGIN_NAME = "sage";

/**
 * Copy the bundled script under tmpHome/.claude/plugins/sage/ so that
 * isMarketplaceInstallation() returns true (plugin root starts with ~/.claude/).
 */
function setupMarketplaceScript(tmpHome: string): string {
	const marketplaceRoot = join(tmpHome, ".claude", "plugins", "sage");
	const distDir = join(marketplaceRoot, "packages", "claude-code", "dist");
	mkdirSync(distDir, { recursive: true });

	const scriptDest = join(distDir, "sage-statusline.cjs");
	copyFileSync(STATUSLINE_SCRIPT, scriptDest);

	mkdirSync(join(marketplaceRoot, ".claude-plugin"), { recursive: true });
	writeFileSync(
		join(marketplaceRoot, ".claude-plugin", "plugin.json"),
		JSON.stringify({ name: PLUGIN_NAME }),
	);

	return scriptDest;
}

function runStatusLine(
	input: Record<string, unknown> | string,
	env: Record<string, string>,
	script = STATUSLINE_SCRIPT,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolve) => {
		const child = execFile(
			"node",
			[script],
			{ timeout: 10_000, env: { ...process.env, ...env } },
			(error, stdout, stderr) => {
				resolve({ stdout, stderr, code: error?.code ? Number(error.code) : child.exitCode });
			},
		);
		const stdin = typeof input === "string" ? input : JSON.stringify(input);
		child.stdin?.end(stdin);
	});
}

function setupHome(
	tmpHome: string,
	options: {
		pluginInstalled?: boolean;
		pluginEnabled?: boolean;
		statusLine?: boolean;
		statusFiles?: string[];
	} = {},
): void {
	const {
		pluginInstalled = true,
		pluginEnabled = true,
		statusLine = true,
		statusFiles = [],
	} = options;

	// Plugin registry
	mkdirSync(join(tmpHome, ".claude", "plugins"), { recursive: true });
	const plugins: Record<string, unknown> = {};
	if (pluginInstalled) {
		plugins[`${PLUGIN_NAME}@some-source`] = [{ installPath: "/tmp/sage", version: "1.0.0" }];
	}
	writeFileSync(
		join(tmpHome, ".claude", "plugins", "installed_plugins.json"),
		JSON.stringify({ version: "1", plugins }),
	);

	// Settings with statusLine and enabledPlugins
	const settings: Record<string, unknown> = {};
	if (statusLine) {
		settings.statusLine = {
			command: "node /path/to/sage-statusline.cjs",
		};
	}
	if (!pluginEnabled) {
		settings.enabledPlugins = { [`${PLUGIN_NAME}@some-source`]: false };
	}
	writeFileSync(join(tmpHome, ".claude", "settings.json"), JSON.stringify(settings, null, 2));

	// Status files
	if (statusFiles.length > 0) {
		mkdirSync(join(tmpHome, ".sage"), { recursive: true });
		for (const sessionId of statusFiles) {
			writeFileSync(
				join(tmpHome, ".sage", `statusline-${sessionId}.txt`),
				JSON.stringify({ denied: 1, flagged: 0, lastReason: "test", lastCategory: "test" }),
			);
		}
	}
}

function readSettings(tmpHome: string): Record<string, unknown> {
	return JSON.parse(readFileSync(join(tmpHome, ".claude", "settings.json"), "utf-8"));
}

function statusFileExists(tmpHome: string, sessionId: string): boolean {
	try {
		readFileSync(join(tmpHome, ".sage", `statusline-${sessionId}.txt`));
		return true;
	} catch {
		return false;
	}
}

describe("sage-statusline cleanup", () => {
	let tmpHome: string;

	beforeEach(async () => {
		tmpHome = await makeTmpDir();
	});

	it("removes statusLine when plugin is disabled (no sessionId)", async () => {
		const script = setupMarketplaceScript(tmpHome);
		setupHome(tmpHome, { pluginEnabled: false, statusLine: true });

		const { stdout, code } = await runStatusLine("", { HOME: tmpHome }, script);

		expect(code).toBe(0);
		expect(stdout).toBe("");
		expect(readSettings(tmpHome)).not.toHaveProperty("statusLine");
	}, 10_000);

	it("removes statusLine when plugin is disabled (with sessionId and status file)", async () => {
		const script = setupMarketplaceScript(tmpHome);
		setupHome(tmpHome, {
			pluginEnabled: false,
			statusLine: true,
			statusFiles: ["sess1"],
		});

		const { stdout, code } = await runStatusLine(
			{ session_id: "sess1" },
			{ HOME: tmpHome },
			script,
		);

		expect(code).toBe(0);
		expect(stdout).toBe("");
		expect(readSettings(tmpHome)).not.toHaveProperty("statusLine");
	}, 10_000);

	it("prunes status files on successful cleanup", async () => {
		const script = setupMarketplaceScript(tmpHome);
		setupHome(tmpHome, {
			pluginEnabled: false,
			statusLine: true,
			statusFiles: ["sess1", "sess2"],
		});

		await runStatusLine("", { HOME: tmpHome }, script);

		expect(statusFileExists(tmpHome, "sess1")).toBe(false);
		expect(statusFileExists(tmpHome, "sess2")).toBe(false);
	}, 10_000);

	it("does not prune status files when statusLine removal fails", async () => {
		const script = setupMarketplaceScript(tmpHome);
		setupHome(tmpHome, {
			pluginEnabled: false,
			statusLine: true,
			statusFiles: ["sess1"],
		});
		// Delete settings.json so removeOwnStatusLine fails with ENOENT
		const { unlinkSync } = await import("node:fs");
		unlinkSync(join(tmpHome, ".claude", "settings.json"));

		const { code } = await runStatusLine("", { HOME: tmpHome }, script);

		expect(code).toBe(0);
		expect(statusFileExists(tmpHome, "sess1")).toBe(true);
	}, 10_000);

	it("outputs status when plugin is installed and enabled (with sessionId)", async () => {
		setupHome(tmpHome, {
			pluginInstalled: true,
			pluginEnabled: true,
			statusLine: true,
			statusFiles: ["sess1"],
		});

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("blocked");
		expect(readSettings(tmpHome)).toHaveProperty("statusLine");
	}, 10_000);

	it("outputs fallback status when plugin is installed but no sessionId", async () => {
		setupHome(tmpHome, { pluginInstalled: true, statusLine: true });

		const { stdout, code } = await runStatusLine("", { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("✅");
		expect(readSettings(tmpHome)).toHaveProperty("statusLine");
	}, 10_000);

	it("shows fallback when status file is missing (startup race or stale --plugin-dir)", async () => {
		setupHome(tmpHome, { pluginInstalled: false, statusLine: true });

		const { stdout, code } = await runStatusLine({ session_id: "nonexistent" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("✅");
		expect(readSettings(tmpHome)).toHaveProperty("statusLine");
	}, 10_000);

	it("does not touch settings when plugin is installed and enabled", async () => {
		setupHome(tmpHome, { pluginInstalled: true, statusLine: true, statusFiles: ["sess1"] });
		const before = readFileSync(join(tmpHome, ".claude", "settings.json"), "utf-8");

		await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		const after = readFileSync(join(tmpHome, ".claude", "settings.json"), "utf-8");
		expect(after).toBe(before);
	}, 10_000);

	it("does not clean up when plugin is not in registry but loaded via --plugin-dir", async () => {
		setupHome(tmpHome, { pluginInstalled: false, statusLine: true });

		const { stdout, code } = await runStatusLine("", { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("✅");
		expect(readSettings(tmpHome)).toHaveProperty("statusLine");
	}, 10_000);
});

describe("sage-statusline skill verdict display", () => {
	let tmpHome: string;
	const SESSION_START_ISO = new Date(Date.now() - 60_000).toISOString();

	beforeEach(async () => {
		tmpHome = await makeTmpDir();
		setupHome(tmpHome, { pluginInstalled: true, pluginEnabled: true, statusLine: true });
	});

	function writeStatusFile(sessionId: string, status: Record<string, unknown>): void {
		mkdirSync(join(tmpHome, ".sage"), { recursive: true });
		writeFileSync(
			join(tmpHome, ".sage", `statusline-${sessionId}.txt`),
			JSON.stringify({ denied: 0, flagged: 0, ...status }),
		);
	}

	function writeVerdictCache(content: string): void {
		mkdirSync(join(tmpHome, ".sage"), { recursive: true });
		writeFileSync(join(tmpHome, ".sage", "skill_verdict_cache.json"), content);
	}

	function cacheWith(
		verdict: string,
		analyzedAt: string,
		summary: string,
		skillName?: string,
		sources?: Array<{ agent_runtime?: string; container_key?: string }>,
	): string {
		return JSON.stringify({
			schema_version: 1,
			entries: {
				["a".repeat(64)]: {
					verdict,
					summary,
					skill_name: skillName,
					sources,
					analyzed_at: analyzedAt,
				},
			},
		});
	}

	it("shows a fresh risky verdict that arrived during the session", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(
			cacheWith("CRITICAL", new Date().toISOString(), "Exfiltrates SSH keys", "ssh-stealer"),
		);

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("⚠️");
		expect(stdout).toContain("1 malicious skill (ssh-stealer)");
	}, 10_000);

	it("includes the skill name in the warning", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(
			cacheWith("CRITICAL", new Date().toISOString(), "Exfiltrates SSH keys", "evil-skill"),
		);

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("1 malicious skill (evil-skill)");
	}, 10_000);

	it("lists multiple risky skill names, newest first", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		const older = new Date(Date.now() - 2_000).toISOString();
		const newer = new Date().toISOString();
		writeVerdictCache(
			JSON.stringify({
				schema_version: 1,
				entries: {
					["a".repeat(64)]: { verdict: "CRITICAL", skill_name: "older-skill", analyzed_at: older },
					["b".repeat(64)]: { verdict: "HIGH", skill_name: "newer-skill", analyzed_at: newer },
				},
			}),
		);

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).toContain("2 malicious skills (newer-skill, older-skill)");
	}, 10_000);

	it("hides a verdict discovered only by another agent, but shows its own", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(
			cacheWith("CRITICAL", new Date().toISOString(), "bad skill", "evil-skill", [
				{ agent_runtime: "cursor", container_key: "skill:evil-skill@local" },
			]),
		);
		const foreign = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });
		expect(foreign.stdout).not.toContain("⚠️");
		expect(foreign.stdout).toContain("✅");

		writeVerdictCache(
			cacheWith("CRITICAL", new Date().toISOString(), "bad skill", "evil-skill", [
				{ agent_runtime: "cursor" },
				{ agent_runtime: "claude-code" },
			]),
		);
		const local = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });
		expect(local.stdout).toContain("1 malicious skill (evil-skill)");
		expect(local.stdout).not.toContain("Cursor");
	}, 15_000);

	it("reverts to base output once the verdict ages past the display window", async () => {
		// Analyzed during the session, but longer ago than the 10s display window.
		const analyzedAt = new Date(Date.now() - 30_000).toISOString();
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(cacheWith("CRITICAL", analyzedAt, "already-shown finding"));

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("✅");
	}, 10_000);

	it("ignores verdicts analyzed before the session started", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(
			cacheWith("CRITICAL", new Date(Date.now() - 120_000).toISOString(), "old finding"),
		);

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("✅");
	}, 10_000);

	it("falls back to base output on a corrupt verdict cache", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache("{ not json");

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("✅");
	}, 10_000);

	it("falls back to base output when the verdict cache is missing", async () => {
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("✅");
	}, 10_000);

	it("shows base output for old status files without startedAt", async () => {
		writeStatusFile("sess1", { denied: 1, lastReason: "test", lastCategory: "test" });
		writeVerdictCache(cacheWith("CRITICAL", new Date().toISOString(), "fresh finding"));

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("blocked");
	}, 10_000);

	it("shows base output when skill_check is disabled", async () => {
		mkdirSync(join(tmpHome, ".sage"), { recursive: true });
		writeFileSync(
			join(tmpHome, ".sage", "config.json"),
			JSON.stringify({ skill_check: { enabled: false } }),
		);
		writeStatusFile("sess1", { startedAt: SESSION_START_ISO });
		writeVerdictCache(cacheWith("CRITICAL", new Date().toISOString(), "fresh finding"));

		const { stdout, code } = await runStatusLine({ session_id: "sess1" }, { HOME: tmpHome });

		expect(code).toBe(0);
		expect(stdout).not.toContain("⚠️");
		expect(stdout).toContain("✅");
	}, 10_000);
});
