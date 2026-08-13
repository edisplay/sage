import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Branding, Logger, PluginInfo, SkillRoot } from "@gendigital/sage-core";
import {
	defaultBranding,
	discoverLooseSkillsAcrossRoots,
	getFileContent,
} from "@gendigital/sage-core";

export type { SkillRoot };

/**
 * Discover loose skill folders across one or more skill roots (e.g. Cursor's
 * `~/.cursor/skills`, or VS Code's `~/.copilot/skills` + `~/.claude/skills` +
 * `~/.agents/skills`). Delegates to core's {@link discoverLooseSkillsAcrossRoots}
 * (symlink-safe, recursive, subtree-mtime cache keying, cross-root dedup by
 * resolved path); this wrapper adds branded debug logging.
 */
export async function discoverLooseSkillFolders(
	logger: Logger,
	roots: SkillRoot[],
	branding: Branding = defaultBranding,
): Promise<PluginInfo[]> {
	for (const { dir } of roots) {
		logger.debug(`${branding.name} skill discovery: scanning skills directory`, { path: dir });
	}

	const merged = await discoverLooseSkillsAcrossRoots(roots);

	for (const plugin of merged) {
		logger.debug(`${branding.name} skill discovery: found loose skill`, {
			key: plugin.key,
			path: plugin.installPath,
		});
	}
	logger.debug(`${branding.name} skill discovery: found ${merged.length} loose skill(s)`);
	return merged;
}

export async function discoverExtensionPlugins(
	logger: Logger,
	extensionsDir: string,
	branding: Branding = defaultBranding,
): Promise<PluginInfo[]> {
	logger.debug(`${branding.name} plugin discovery: scanning extensions directory`, {
		path: extensionsDir,
	});

	let entries: string[];
	try {
		entries = await readdir(extensionsDir);
	} catch {
		logger.debug("Extensions directory not found", { path: extensionsDir });
		return [];
	}

	const plugins: PluginInfo[] = [];

	for (const entry of entries) {
		const extDir = join(extensionsDir, entry);

		let stats: Awaited<ReturnType<typeof stat>>;
		try {
			stats = await stat(extDir);
			if (!stats.isDirectory()) continue;
		} catch {
			continue;
		}

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
	return plugins;
}
