/**
 * Loose-skill discovery for Claude Code — treats each skill folder under a
 * skills root as its own pseudo-plugin so the session-start scan pipeline
 * (heuristics, skill check, verdict cache, upload worker) covers skills the
 * user installed outside any plugin. Two roots are covered, mirroring Claude
 * Code's own skill resolution, both tagged `claude` (the directory family) and
 * distinguished by scope:
 *   - Personal: `~/.claude/skills` (scope `personal`) — shared across projects.
 *   - Project:  `<cwd>/.claude/skills` (scope `project`) — this project only.
 * Keys use the cross-platform `skill:<tag>/<relative/path>@<scope>` format owned
 * by core, so exceptions and cache entries are portable across agents (Claude
 * Code, Cursor, VS Code). The scope keeps a personal and a project skill of the
 * same name from colliding in the scan cache.
 */

import { join } from "node:path";
import {
	discoverLooseSkillsAcrossRoots,
	getClaudeConfigDir,
	type PluginInfo,
} from "@gendigital/sage-core";

/**
 * Discover both personal (`~/.claude/skills`) and project (`<cwd>/.claude/skills`)
 * loose skills in one pass, deduped by resolved path so a project whose skills
 * folder is the home directory's is scanned only once. Fails open to an empty
 * list — loose-skill coverage must never break session start.
 */
export async function discoverClaudeCodeSkills(
	projectDir: string,
	personalSkillsDir = join(getClaudeConfigDir(), "skills"),
): Promise<PluginInfo[]> {
	try {
		return await discoverLooseSkillsAcrossRoots([
			{ dir: personalSkillsDir, tag: "claude", scope: "personal" },
			{ dir: join(projectDir, ".claude", "skills"), tag: "claude", scope: "project" },
		]);
	} catch {
		return [];
	}
}
