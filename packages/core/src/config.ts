/**
 * Configuration loader for Sage.
 * Loads settings from ~/.sage/config.json with full defaults fallback.
 */

import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { getFileContent, getFileContentSync, getHomeDir } from "./file-utils.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

export const SAGE_DIR = "~/.sage";

/** Hook timeout in seconds, shared across all connector hook installers. */
export const HOOK_TIMEOUT_SECONDS = 8;

/** Milliseconds in one day. Shared so day-based TTLs convert consistently. */
export const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Skill verdict / plugin-scan cache TTL in milliseconds, derived from
 * `skill_check.cache_ttl_days`. Floored at one day: the config schema permits
 * `0`, but a zero/sub-day TTL would expire every cached verdict immediately and
 * re-upload every unknown skill on every session (an egress + cost footgun). To
 * stop uploads entirely, set `skill_check.upload_enabled` to `false` instead.
 * Flooring here rather than in the schema keeps a misconfigured value from
 * failing whole-config validation and silently reverting all other settings.
 */
export function skillCacheTtlMs(config: Config): number {
	return Math.max(1, config.skill_check.cache_ttl_days) * MS_PER_DAY;
}

/** Tolerated future clock skew before a timestamp is treated as invalid. */
const CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000;

/**
 * Whether a millisecond timestamp is valid and still within `ttlMs`. Guards
 * the `now - ts < ttl` pattern against two failure modes: unparsable values
 * (`NaN`) and timestamps in the future — from clock skew or a tampered state
 * file — which would otherwise produce a negative age and read as permanently
 * fresh (never expiring, pinning stale verdicts / pending entries forever). A
 * small skew tolerance avoids needless re-checks on minor clock drift.
 */
export function isFreshTimestamp(ts: number, ttlMs: number, now: number = Date.now()): boolean {
	if (Number.isNaN(ts)) return false;
	if (ts - now > CLOCK_SKEW_TOLERANCE_MS) return false;
	return now - ts < ttlMs;
}

function resolvedSageDir(): string {
	return resolvePath(SAGE_DIR);
}

export function defaultConfigPath(): string {
	return join(resolvedSageDir(), "config.json");
}

function defaultCachePath(): string {
	return join(resolvedSageDir(), "cache.json");
}

function defaultExceptionsPath(): string {
	return join(resolvedSageDir(), "exceptions.json");
}

function defaultAuditPath(): string {
	return join(resolvedSageDir(), "audit.jsonl");
}

function defaultOperationalLogPath(): string {
	return join(resolvedSageDir(), "operational.jsonl");
}

/** Expand ~ to the user's home directory. Prefers HOME env over os.homedir(). */
export function resolvePath(pathStr: string): string {
	if (pathStr.startsWith("~/") || pathStr === "~") {
		const home = getHomeDir();
		return join(home, pathStr.slice(1));
	}
	return pathStr;
}

/**
 * Returns the Claude Code config directory, respecting the CLAUDE_CONFIG_DIR
 * environment variable. Falls back to ~/.claude when unset.
 */
export function getClaudeConfigDir(): string {
	const envDir = process.env.CLAUDE_CONFIG_DIR;
	if (envDir) return resolvePath(envDir);
	return resolvePath("~/.claude");
}

function isWithinDirectory(baseDir: string, targetPath: string): boolean {
	const rel = relative(baseDir, targetPath);
	if (rel === "") return true;
	if (isAbsolute(rel)) return false;
	return rel !== ".." && !rel.startsWith(`..${sep}`);
}

function normalizeStateFilePath(
	configuredPath: string,
	fallbackPath: string,
	field: "cache" | "exceptions" | "logging" | "operational_logging",
	logger: Logger,
): string {
	const sageDir = resolvedSageDir();
	const trimmed = configuredPath.trim();
	if (trimmed === "") {
		logger.warn(`Config ${field}.path is empty; using default`, {
			configuredPath,
			defaultPath: fallbackPath,
		});
		return fallbackPath;
	}

	const expanded = resolvePath(trimmed);
	const resolved = isAbsolute(expanded) ? resolve(expanded) : resolve(sageDir, expanded);
	if (isWithinDirectory(sageDir, resolved)) {
		if (resolved === sageDir) {
			logger.warn(`Config ${field}.path must point to a file; using default`, {
				configuredPath,
				defaultPath: fallbackPath,
			});
			return fallbackPath;
		}
		return resolved;
	}

	logger.warn(`Config ${field}.path escapes ${sageDir}; using default`, {
		configuredPath,
		defaultPath: fallbackPath,
	});
	return fallbackPath;
}

const BRAND_KEY_RE = /^[a-z0-9_-]+$/u;

function sanitizeBrandKey(data: Record<string, unknown>, logger: Logger): Record<string, unknown> {
	const brandKey = data.brand_key;
	if (brandKey === undefined) return data;
	if (
		typeof brandKey === "string" &&
		brandKey.length >= 1 &&
		brandKey.length <= 32 &&
		BRAND_KEY_RE.test(brandKey)
	) {
		return data;
	}
	logger.warn(`Invalid brand_key in config - ignoring`, { brand_key: brandKey });
	const { brand_key: _, ...rest } = data;
	return rest;
}

function sanitizeConfigPaths(config: Config, logger: Logger): Config {
	const cachePath = defaultCachePath();
	const exceptionsPath = defaultExceptionsPath();
	const auditPath = defaultAuditPath();
	const operationalLogPath = defaultOperationalLogPath();
	return {
		...config,
		cache: {
			...config.cache,
			path: normalizeStateFilePath(config.cache.path, cachePath, "cache", logger),
		},
		exceptions: {
			...config.exceptions,
			path: normalizeStateFilePath(config.exceptions.path, exceptionsPath, "exceptions", logger),
		},
		logging: {
			...config.logging,
			path: normalizeStateFilePath(config.logging.path, auditPath, "logging", logger),
		},
		operational_logging: {
			...config.operational_logging,
			path: normalizeStateFilePath(
				config.operational_logging.path,
				operationalLogPath,
				"operational_logging",
				logger,
			),
		},
	};
}

function defaultConfig(logger: Logger): Config {
	return sanitizeConfigPaths(ConfigSchema.parse({}), logger);
}

function parseConfig(raw: string, path: string, logger: Logger): Config {
	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to parse config from ${path}`, { error: String(e) });
		return defaultConfig(logger);
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Config file ${path} does not contain a JSON object`);
		return defaultConfig(logger);
	}

	const sanitized = sanitizeBrandKey(data as Record<string, unknown>, logger);

	try {
		return sanitizeConfigPaths(ConfigSchema.parse(sanitized), logger);
	} catch (e) {
		logger.warn(`Config validation failed, using defaults`, { error: String(e) });
		return defaultConfig(logger);
	}
}

/**
 * Whether `skill_check.upload_enabled` is *explicitly* set in the user's raw
 * config, and its value. `ConfigSchema` applies `.default(true)`, which erases
 * the absent-vs-explicit distinction after parse — but the skill-upload rollout
 * needs it: an explicit value must win over the notice/activation state machine
 * ("explicit config wins"), while an absent key must fall through to it.
 *
 * Fails-open to `{ present: false }`: a missing/corrupt config, or a
 * non-boolean value, is treated as "not explicitly set" so the rollout governs
 * and no upload happens until the user has been noticed.
 */
export async function readExplicitSkillUploadEnabled(
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<{ present: boolean; value: boolean }> {
	const path = configPath ? resolvePath(configPath) : defaultConfigPath();
	try {
		const data = JSON.parse(await getFileContent(path)) as Record<string, unknown>;
		const skillCheck = data.skill_check;
		if (
			skillCheck &&
			typeof skillCheck === "object" &&
			!Array.isArray(skillCheck) &&
			"upload_enabled" in skillCheck
		) {
			const value = (skillCheck as Record<string, unknown>).upload_enabled;
			if (typeof value === "boolean") return { present: true, value };
			logger.warn("Config skill_check.upload_enabled is not a boolean; ignoring", { value });
		}
	} catch {
		// Missing/corrupt config — treat as not explicitly set (fail-open).
	}
	return { present: false, value: false };
}

export async function loadConfig(
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<Config> {
	const path = configPath ? resolvePath(configPath) : defaultConfigPath();

	try {
		return parseConfig(await getFileContent(path), path, logger);
	} catch {
		// Missing file -> full defaults (fail-open)
		return defaultConfig(logger);
	}
}

/**
 * Synchronous config loader. Required because branding resolution depends on
 * config, and some callers (OpenClaw plugin registration, extension activation)
 * need branding synchronously before any async init.
 */
export function loadConfigSync(configPath?: string, logger: Logger = nullLogger): Config {
	const path = configPath ? resolvePath(configPath) : defaultConfigPath();

	try {
		return parseConfig(getFileContentSync(path), path, logger);
	} catch {
		return defaultConfig(logger);
	}
}
