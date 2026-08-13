#!/usr/bin/env node
/**
 * Sage SessionStart hook entry point.
 * Scans installed Claude Code plugins for threats at session startup.
 * Always exits 0 — outputs status JSON with systemMessage.
 */

import { readFileSync } from "node:fs";
import { open, readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import {
	atomicWriteJson,
	type Branding,
	checkAllowlistMigration,
	createOperationalLogger,
	discoverPlugins,
	formatAllowlistMigrationWarning,
	formatConfigurationWarnings,
	formatNoticeById,
	getClaudeConfigDir,
	getConfigurationWarnings,
	initSessionStatus,
	type Logger,
	loadConfig,
	nullLogger,
	pruneSessionStatusFiles,
	resolveBranding,
	runPluginScan,
} from "@gendigital/sage-core";
import { pruneStaleSessionFiles } from "./approval-tracker.js";
import { STATUSLINE_MARKER } from "./constants.js";
import { discoverClaudeCodeSkills } from "./personal-skills.js";
import { resolveClaudeCodeVersion } from "./runtime-version.js";

let logger: Logger = nullLogger;

function getPluginRoot(): string {
	// When bundled by esbuild into CJS, __dirname points to packages/claude-code/dist/
	// Plugin root is three levels up.
	return resolve(__dirname, "..", "..", "..");
}

function getPluginManifest(pluginRoot: string): { name: string | null; version: string } {
	try {
		const manifest = readFileSync(join(pluginRoot, ".claude-plugin", "plugin.json"), "utf-8");
		const parsed = JSON.parse(manifest) as Record<string, unknown>;
		return {
			name: (parsed.name as string) ?? null,
			version: (parsed.version as string) ?? "0.0.0",
		};
	} catch {
		return { name: null, version: "0.0.0" };
	}
}

/**
 * Read and parse the SessionStart hook input from stdin. fd 0 can only be
 * consumed once, so both `session_id` and `cwd` are pulled from this single
 * read. `cwd` falls back to the process working directory (Claude Code runs the
 * hook from the project root) so project-skill discovery still has a root.
 */
function readHookInput(): { sessionId: string; cwd: string } {
	try {
		const input = readFileSync(0, "utf-8");
		const parsed = JSON.parse(input) as Record<string, unknown>;
		return {
			sessionId: (parsed.session_id as string) ?? "unknown",
			cwd: (parsed.cwd as string) ?? process.cwd(),
		};
	} catch {
		return { sessionId: "unknown", cwd: process.cwd() };
	}
}

async function readSettingsJson(path: string): Promise<Record<string, unknown> | null> {
	let raw: string;
	try {
		raw = await readFile(path, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			return {}; // Missing file — safe to create
		}
		return null; // Existing file could not be read — do not overwrite
	}
	try {
		const parsed = JSON.parse(raw);
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
	} catch {
		// File exists but is corrupt
	}
	return null; // Corrupt or non-object — do not overwrite
}

// Common interpreters; matched against the token's basename so absolute paths
// like /usr/bin/env or /bin/bash are recognized too.
const INTERPRETERS = /^(bash|sh|zsh|dash|fish|env|node|deno|python\d?|perl|ruby)$/;
const SCRIPT_READ_LIMIT = 64 * 1024;

/**
 * Check if a statusline command points to a script that already references
 * sage-statusline.cjs internally (e.g. a wrapper shell script).
 *
 * Only the script path itself is read — the first non-flag, non-interpreter
 * token. Trailing arguments are ignored to avoid false positives from
 * unrelated files passed as arguments.
 */
async function scriptReferencesMarker(command: string, home: string): Promise<boolean> {
	// Handles: ~/script.sh, bash ~/script.sh, "~/script.sh" --flag, etc.
	const tokens = command.match(/(?:"([^"]+)"|'([^']+)'|(\S+))/g) ?? [];
	const scriptToken = tokens
		.map((raw) => raw.replace(/^["']|["']$/g, ""))
		.find((t) => !t.startsWith("-") && !INTERPRETERS.test(basename(t)));
	if (!scriptToken) return false;
	const resolved = scriptToken.replace(/^~/, home);
	try {
		const info = await stat(resolved);
		if (!info.isFile()) return false;
		const handle = await open(resolved, "r");
		try {
			const len = Math.min(info.size, SCRIPT_READ_LIMIT);
			const buf = Buffer.alloc(len);
			await handle.read(buf, 0, len, 0);
			return buf.toString("utf8").includes(STATUSLINE_MARKER);
		} finally {
			await handle.close();
		}
	} catch {
		return false;
	}
}

/**
 * Auto-configure Claude Code status line to display Sage session status.
 * - No existing statusLine → install Sage's
 * - Already Sage's → update path if changed
 * - Another statusLine that integrates Sage → leave it alone
 * - Another statusLine without Sage → return a hint message for the user
 */
async function configureStatusLine(pluginRoot: string, branding: Branding): Promise<string | null> {
	const home = process.env.HOME ?? "";
	const settingsPath = join(getClaudeConfigDir(), "settings.json");
	const settings = await readSettingsJson(settingsPath);
	if (settings === null) {
		return `${branding.name}: Could not read ${settingsPath} — skipping status line auto-configuration.`;
	}
	const statuslineCjs = join(pluginRoot, "packages", "claude-code", "dist", "sage-statusline.cjs");
	const command = `node "${statuslineCjs}"`;
	// refreshInterval makes Claude Code re-run the script periodically, so the
	// statusline picks up skill verdicts that arrive mid-session.
	const sageStatusLine = { type: "command", command, refreshInterval: 5 };

	const existing = settings.statusLine as Record<string, unknown> | undefined;
	const existingCommand =
		existing && typeof existing.command === "string" ? existing.command : null;

	if (existingCommand?.includes(STATUSLINE_MARKER)) {
		// Already Sage's — upgrade when the path changed or an older install
		// predates refreshInterval
		if (
			existingCommand !== command ||
			existing?.refreshInterval !== sageStatusLine.refreshInterval
		) {
			settings.statusLine = sageStatusLine;
			await atomicWriteJson(settingsPath, settings);
		}
		return null;
	}

	if (existingCommand) {
		// Check if the command points to a wrapper script that already integrates Sage
		if (await scriptReferencesMarker(existingCommand, home)) {
			return null;
		}
		// User has a different status line — don't overwrite, suggest integration
		return `${branding.name} status line: You already have a custom status line. To add ${branding.name} status, include \`node "${statuslineCjs}"\` in your script or pipe its output alongside yours.`;
	}

	// No status line configured — install Sage's
	settings.statusLine = sageStatusLine;
	await atomicWriteJson(settingsPath, settings);
	return null;
}

async function main(): Promise<void> {
	const { sessionId, cwd } = readHookInput();
	const config = await loadConfig();
	logger = createOperationalLogger(config.operational_logging, "claude-code").forComponent(
		"session-start",
	);
	const branding = resolveBranding(config.brand_key, logger);

	logger.debug("SessionStart hook started", { hookType: "SessionStart", sessionId });
	const completeHook = async (
		result: string,
		data: Record<string, unknown> = {},
	): Promise<void> => {
		logger.debug("SessionStart hook completed", {
			hookType: "SessionStart",
			sessionId,
			result,
			...data,
		});
		await logger.flush?.();
	};

	const warningMessage = formatConfigurationWarnings(
		await getConfigurationWarnings(undefined, logger),
		branding,
	);

	// Prune stale files
	await pruneStaleSessionFiles(logger);
	pruneSessionStatusFiles().catch(() => {});

	const pluginRoot = getPluginRoot();
	const threatsDir = join(pluginRoot, "threats");
	const trustedDomainsDir = join(pluginRoot, "trusted-domains");
	const manifest = getPluginManifest(pluginRoot);

	// Discover plugins and filter out self
	let plugins = await discoverPlugins(undefined, logger);
	if (manifest.name) {
		const prefix = `${manifest.name}@`;
		plugins = plugins.filter((p) => !p.key.startsWith(prefix));
	}

	// Loose skills join the scan as pseudo-plugins, one per skill folder:
	// personal (~/.claude/skills, key `skill:claude/...@personal`) and project
	// (<cwd>/.claude/skills, key `skill:claude/...@project`).
	plugins.push(...(await discoverClaudeCodeSkills(cwd)));

	const noticeMessages: string[] = [];
	const statusMsg = await runPluginScan(
		logger,
		"session",
		plugins,
		threatsDir,
		trustedDomainsDir,
		manifest.version,
		"claude-code",
		branding,
		resolve(__dirname, "model-download-worker.cjs"),
		"verbose",
		resolveClaudeCodeVersion(),
		resolve(__dirname, "skill-upload-worker.cjs"),
		(noticeIds) => {
			for (const id of noticeIds) {
				const text = formatNoticeById(id, branding);
				if (text) noticeMessages.push(text);
			}
		},
		undefined,
		config.announce_clean_scans,
	);

	// Initialize status file before registering the status line so the
	// statusline script always finds the file on its first poll.
	try {
		await initSessionStatus(sessionId);
	} catch {
		// Best effort
	}

	// Auto-configure status line (after status file exists)
	let statusLineHint: string | null = null;
	try {
		statusLineHint = await configureStatusLine(pluginRoot, branding);
	} catch {
		// Best-effort — don't block session start
	}

	const allowlistMigration = await checkAllowlistMigration();
	const parts: string[] = [];
	// One-time notices (e.g. skill-upload consent) go at the top of the message.
	if (noticeMessages.length > 0) parts.push(noticeMessages.join("\n"));
	if (warningMessage) parts.push(warningMessage);
	if (allowlistMigration.needed) {
		parts.push(formatAllowlistMigrationWarning(allowlistMigration.entryTypes, branding));
	}
	if (statusMsg) parts.push(statusMsg);
	if (statusLineHint) parts.push(statusLineHint);
	const finalMsg = parts.join("\n");
	// When announce_clean_scans=false and nothing else has to be surfaced, emit
	// an empty hook response so Claude Code shows no system banner at all.
	if (finalMsg === "") {
		process.stdout.write("{}\n");
	} else {
		process.stdout.write(`${JSON.stringify({ systemMessage: finalMsg })}\n`);
	}
	await completeHook("completed", {
		statusLineHintShown: !!statusLineHint,
	});
}

main().catch(async (error) => {
	logger.error("SessionStart hook failed open", { error: String(error) });
	process.stdout.write("{}\n");
	await logger.flush?.();
});
