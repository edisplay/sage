/**
 * Discovers installed OpenClaw extensions for plugin scanning.
 * Walks ~/.openclaw/extensions/ for directories with package.json.
 */

import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Branding, Logger, PluginInfo, SkillRoot } from "@gendigital/sage-core";
import {
	defaultBranding,
	discoverLooseSkillsAcrossRoots,
	getFileContent,
	getHomeDir,
} from "@gendigital/sage-core";

const DEFAULT_EXTENSIONS_DIR = join(homedir(), ".openclaw", "extensions");

/**
 * Personal loose-skill roots OpenClaw loads (priorities 3–4 of its documented
 * order): `~/.agents/skills` and `~/.openclaw/skills`. Keyed by scope so they
 * never collide with the same-named families in other connectors' caches.
 *
 * Only these two are covered. The workspace-relative roots (priorities 1–2)
 * would need a workspace path, which OpenClaw's plugin API never hands the
 * plugin (scan events take no args; tool context exposes only a session key).
 * Bundled skills (priority 5) sit inside the trusted install, and plugin skills
 * (priority 6) are already covered by the extension scan below.
 */
const SKILL_ROOTS: SkillRoot[] = [
	{ dir: join(getHomeDir(), ".agents", "skills"), tag: "agents", scope: "personal" },
	{ dir: join(getHomeDir(), ".openclaw", "skills"), tag: "openclaw", scope: "personal" },
];

export async function discoverOpenClawPlugins(
	logger: Logger,
	extensionsDir = DEFAULT_EXTENSIONS_DIR,
	branding: Branding = defaultBranding,
	// Injectable so tests can isolate loose-skill discovery from the real home
	// dir (SKILL_ROOTS resolves under getHomeDir()); pass `[]` to disable it.
	skillRoots: SkillRoot[] = SKILL_ROOTS,
): Promise<PluginInfo[]> {
	logger.debug(`${branding.name} plugin discovery: scanning extensions directory`, {
		path: extensionsDir,
	});

	const plugins: PluginInfo[] = [];

	let entries: string[];
	try {
		entries = await readdir(extensionsDir);
	} catch {
		logger.debug("OpenClaw extensions directory not found", { path: extensionsDir });
		entries = [];
	}

	for (const entry of entries) {
		const extDir = join(extensionsDir, entry);

		// Skip non-directories
		let stats: Awaited<ReturnType<typeof stat>>;
		try {
			stats = await stat(extDir);
			if (!stats.isDirectory()) continue;
		} catch {
			continue;
		}

		// Load and parse package.json
		let pkg: Record<string, unknown>;
		try {
			const pkgPath = join(extDir, "package.json");
			const raw = await getFileContent(pkgPath);
			pkg = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			logger.warn("Invalid or missing package.json in extension", { path: extDir });
			continue;
		}

		const name = (pkg.name ?? entry) as string;
		const version = (pkg.version ?? "unknown") as string;

		const key = `${name}@${version}`;
		logger.debug(`${branding.name} plugin discovery: found extension`, {
			key,
			path: extDir,
		});
		plugins.push({
			key,
			installPath: extDir,
			version,
			lastUpdated: stats.mtime.toISOString(),
		});
	}

	logger.debug(`${branding.name} plugin discovery: found ${plugins.length} extension(s)`);

	// Loose skills join the scan as pseudo-plugins (deduped by resolved path,
	// fails open per root) so skills installed outside any extension are covered.
	const skills = await discoverLooseSkillsAcrossRoots(skillRoots);
	logger.debug(`${branding.name} skill discovery: found ${skills.length} loose skill(s)`);
	plugins.push(...skills);

	return plugins;
}
