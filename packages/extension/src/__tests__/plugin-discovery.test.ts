import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nullLogger } from "@gendigital/sage-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discoverExtensionPlugins, discoverLooseSkillFolders } from "../plugin-discovery.js";

describe("discoverExtensionPlugins", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-ext-discovery-"));
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("discovers extensions from dirs with package.json", async () => {
		const extDir = join(dir, "publisher.my-extension-1.0.0");
		await mkdir(extDir, { recursive: true });
		await writeFile(
			join(extDir, "package.json"),
			JSON.stringify({ name: "my-extension", version: "1.0.0" }),
		);

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("my-extension@1.0.0");
		expect(plugins[0]?.installPath).toBe(extDir);
		expect(plugins[0]?.version).toBe("1.0.0");
	});

	it("skips directories without package.json", async () => {
		const extDir = join(dir, "broken-ext");
		await mkdir(extDir, { recursive: true });
		await writeFile(join(extDir, "index.js"), "module.exports = {};");

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(0);
	});

	it("skips non-directory entries", async () => {
		await writeFile(join(dir, "extensions.json"), "[]");

		const extDir = join(dir, "real-ext");
		await mkdir(extDir, { recursive: true });
		await writeFile(
			join(extDir, "package.json"),
			JSON.stringify({ name: "real-ext", version: "2.0.0" }),
		);

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("real-ext@2.0.0");
	});

	it("handles missing extensions directory", async () => {
		const plugins = await discoverExtensionPlugins(nullLogger, join(dir, "nonexistent"));
		expect(plugins).toHaveLength(0);
	});

	it("discovers multiple extensions", async () => {
		for (const name of ["alpha", "beta", "gamma"]) {
			const extDir = join(dir, name);
			await mkdir(extDir, { recursive: true });
			await writeFile(join(extDir, "package.json"), JSON.stringify({ name, version: "1.0.0" }));
		}

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(3);
	});

	it("falls back to directory name when package.json has no name", async () => {
		const extDir = join(dir, "unnamed-ext");
		await mkdir(extDir, { recursive: true });
		await writeFile(join(extDir, "package.json"), JSON.stringify({ version: "0.1.0" }));

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("unnamed-ext@0.1.0");
	});

	it("uses 'unknown' version when package.json has no version", async () => {
		const extDir = join(dir, "no-version");
		await mkdir(extDir, { recursive: true });
		await writeFile(join(extDir, "package.json"), JSON.stringify({ name: "no-version" }));

		const plugins = await discoverExtensionPlugins(nullLogger, dir);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("no-version@unknown");
	});
});

describe("discoverLooseSkillFolders", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-skill-discovery-"));
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("discovers skill folders that contain SKILL.md", async () => {
		const skillDir = join(dir, "my-skill");
		await mkdir(skillDir, { recursive: true });
		await writeFile(join(skillDir, "SKILL.md"), "# My Skill\nDoes stuff.");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir, tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("skill:cursor/my-skill@personal");
		expect(plugins[0]?.installPath).toBe(skillDir);
		expect(plugins[0]?.version).toBe("personal");
	});

	it("skips directories without SKILL.md", async () => {
		const skillDir = join(dir, "not-a-skill");
		await mkdir(skillDir, { recursive: true });
		await writeFile(join(skillDir, "README.md"), "nothing here");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir, tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(0);
	});

	it("skips non-directory entries", async () => {
		await writeFile(join(dir, "SKILL.md"), "top-level file, not a folder skill");

		const skillDir = join(dir, "real-skill");
		await mkdir(skillDir, { recursive: true });
		await writeFile(join(skillDir, "SKILL.md"), "# Real Skill");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir, tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("skill:cursor/real-skill@personal");
	});

	it("handles missing skills directory", async () => {
		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: join(dir, "nonexistent"), tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(0);
	});

	it("discovers multiple skill folders", async () => {
		for (const name of ["skill-a", "skill-b", "skill-c"]) {
			const skillDir = join(dir, name);
			await mkdir(skillDir, { recursive: true });
			await writeFile(join(skillDir, "SKILL.md"), `# ${name}`);
		}

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir, tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(3);
		expect(plugins.map((p) => p.key).sort()).toEqual([
			"skill:cursor/skill-a@personal",
			"skill:cursor/skill-b@personal",
			"skill:cursor/skill-c@personal",
		]);
	});

	it("assigns unique keys to same-named folders at different depths", async () => {
		const a = join(dir, "team-a", "utils");
		const b = join(dir, "team-b", "utils");
		await mkdir(a, { recursive: true });
		await mkdir(b, { recursive: true });
		await writeFile(join(a, "SKILL.md"), "# utils a");
		await writeFile(join(b, "SKILL.md"), "# utils b");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir, tag: "cursor", scope: "personal" },
		]);
		expect(plugins).toHaveLength(2);
		const keys = plugins.map((p) => p.key).sort();
		expect(keys).toEqual([
			"skill:cursor/team-a/utils@personal",
			"skill:cursor/team-b/utils@personal",
		]);
		// The bug this guards against: both would have been "skill:cursor/utils@personal".
		expect(new Set(keys).size).toBe(2);
	});
});

describe("discoverLooseSkillFolders across multiple roots", () => {
	let rootA: string;
	let rootB: string;

	beforeEach(async () => {
		rootA = await mkdtemp(join(tmpdir(), "sage-skills-a-"));
		rootB = await mkdtemp(join(tmpdir(), "sage-skills-b-"));
	});

	afterEach(async () => {
		await rm(rootA, { recursive: true, force: true });
		await rm(rootB, { recursive: true, force: true });
	});

	async function writeSkill(root: string, name: string): Promise<void> {
		const skillDir = join(root, name);
		await mkdir(skillDir, { recursive: true });
		await writeFile(join(skillDir, "SKILL.md"), `# ${name}`);
	}

	it("merges skills from multiple roots", async () => {
		await writeSkill(rootA, "alpha");
		await writeSkill(rootB, "beta");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: rootA, tag: "copilot", scope: "personal" },
			{ dir: rootB, tag: "claude", scope: "personal" },
		]);
		expect(plugins.map((p) => p.key).sort()).toEqual([
			"skill:claude/beta@personal",
			"skill:copilot/alpha@personal",
		]);
	});

	it("gives same-named skills in different roots distinct, non-colliding keys", async () => {
		await writeSkill(rootA, "utils");
		await writeSkill(rootB, "utils");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: rootA, tag: "copilot", scope: "personal" },
			{ dir: rootB, tag: "claude", scope: "personal" },
		]);
		// The bug this guards against: both would key as "skill:utils@personal" and one
		// would shadow the other in the scan cache, skipping its scan. The root tag
		// keeps them distinct so both are always scanned.
		expect(plugins).toHaveLength(2);
		expect(plugins.map((p) => p.key).sort()).toEqual([
			"skill:claude/utils@personal",
			"skill:copilot/utils@personal",
		]);
	});

	it("keeps a personal and project skill of the same family from colliding", async () => {
		await writeSkill(rootA, "utils");
		await writeSkill(rootB, "utils");

		// Same tag (family), different scope — the scope segment is what keeps
		// `~/.claude/skills/utils` and `<repo>/.claude/skills/utils` distinct.
		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: rootA, tag: "claude", scope: "personal" },
			{ dir: rootB, tag: "claude", scope: "project" },
		]);
		expect(plugins).toHaveLength(2);
		expect(plugins.map((p) => p.key).sort()).toEqual([
			"skill:claude/utils@personal",
			"skill:claude/utils@project",
		]);
	});

	it("dedupes a root reachable through more than one path", async () => {
		await writeSkill(rootA, "alpha");

		// Same physical root listed twice resolves to one install path → scanned once.
		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: rootA, tag: "copilot", scope: "personal" },
			{ dir: rootA, tag: "copilot", scope: "personal" },
		]);
		expect(plugins).toHaveLength(1);
		expect(plugins[0]?.key).toBe("skill:copilot/alpha@personal");
	});

	it("tolerates missing roots and returns whatever exists", async () => {
		await writeSkill(rootA, "alpha");

		const plugins = await discoverLooseSkillFolders(nullLogger, [
			{ dir: rootA, tag: "copilot", scope: "personal" },
			{ dir: join(rootB, "does-not-exist"), tag: "claude", scope: "personal" },
		]);
		expect(plugins.map((p) => p.key)).toEqual(["skill:copilot/alpha@personal"]);
	});
});
