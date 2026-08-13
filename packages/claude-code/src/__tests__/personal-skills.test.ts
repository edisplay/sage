import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { makeTmpDir } from "../../../core/src/__tests__/test-utils.js";
import { discoverClaudeCodeSkills } from "../personal-skills.js";

async function makeSkill(skillsDir: string, name: string): Promise<string> {
	const folder = join(skillsDir, name);
	await mkdir(folder, { recursive: true });
	const skillMd = join(folder, "SKILL.md");
	await writeFile(skillMd, `# ${name}`);
	return skillMd;
}

describe("discoverClaudeCodeSkills", () => {
	it("merges personal and project skills under distinct scopes", async () => {
		const personalDir = join(await makeTmpDir(), "skills");
		await makeSkill(personalDir, "personal-skill");
		const projectDir = await makeTmpDir();
		await makeSkill(join(projectDir, ".claude", "skills"), "project-skill");

		const entries = await discoverClaudeCodeSkills(projectDir, personalDir);

		expect(entries.map((e) => e.key).sort()).toEqual([
			"skill:claude/personal-skill@personal",
			"skill:claude/project-skill@project",
		]);
	});

	it("keeps a personal and project skill of the same name from colliding", async () => {
		const personalDir = join(await makeTmpDir(), "skills");
		await makeSkill(personalDir, "shared");
		const projectDir = await makeTmpDir();
		await makeSkill(join(projectDir, ".claude", "skills"), "shared");

		const entries = await discoverClaudeCodeSkills(projectDir, personalDir);

		expect(entries).toHaveLength(2);
		expect(entries.map((e) => e.key).sort()).toEqual([
			"skill:claude/shared@personal",
			"skill:claude/shared@project",
		]);
	});

	it("scans a folder reachable through both roots only once", async () => {
		// Project cwd IS the home dir → personal ~/.claude/skills and project
		// <cwd>/.claude/skills resolve to the same folder; dedup keeps one entry.
		const home = await makeTmpDir();
		const personalDir = join(home, ".claude", "skills");
		await makeSkill(personalDir, "only-skill");

		const entries = await discoverClaudeCodeSkills(home, personalDir);

		expect(entries).toHaveLength(1);
	});
});
