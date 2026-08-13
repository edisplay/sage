/**
 * Shared SessionStart scanning pipeline for hook entry points.
 * Hooks provide transport-specific paths and output formatting.
 */

import { join } from "node:path";
import { logPluginScan } from "./audit-log.js";
import { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
import { loadConfig, skillCacheTtlMs } from "./config.js";
import { findPluginAllowException, findPluginDenyException, loadExceptions } from "./exceptions.js";
import {
	computeConfigHash,
	getCached,
	loadScanCache,
	saveScanCache,
	storeResult,
} from "./plugin-scan-cache.js";
import { scanPlugin } from "./plugin-scanner.js";
import type {
	Config,
	ExceptionRule,
	Logger,
	PluginFinding,
	PluginFindingData,
	PluginInfo,
	PluginScanResult,
} from "./types.js";
import { nullLogger } from "./types.js";

export interface SessionStartScanContext {
	plugins: PluginInfo[];
	threatsDir: string;
	trustedDomainsDir: string;
	sageVersion?: string;
	logger?: Logger;
	configPath?: string;
	scanCachePath?: string;
	checkUrls?: boolean;
	checkFileHashes?: boolean;
	/** Resolved absolute path to the sage data directory; used to derive skill
	 *  pending and verdict-cache paths so they stay consistent with the worker. */
	sageDirPath?: string;
	/** Agent runtime running this scan (e.g. "cursor"); recorded as skill verdict origin. */
	agentRuntime?: string;
	uploadUnknownSkills?: boolean;
	deferUnknownSkills?: boolean;
}

export function fromCachedFinding(finding: PluginFindingData): PluginFinding {
	return {
		threatId: finding.threat_id,
		title: finding.title,
		severity: finding.severity,
		artifact: finding.artifact,
		sourceFile: finding.source_file,
		recommendations: finding.recommendations,
	};
}

export function toFindingData(finding: PluginFinding): PluginFindingData {
	return {
		threat_id: finding.threatId,
		title: finding.title,
		severity: finding.severity,
		artifact: finding.artifact,
		source_file: finding.sourceFile,
		recommendations: finding.recommendations,
	};
}

export function toAuditFindingData(finding: PluginFinding): Record<string, unknown> {
	return { ...toFindingData(finding) };
}

export async function runSessionStartScan(
	context: SessionStartScanContext,
): Promise<PluginScanResult[]> {
	const logger = context.logger ?? nullLogger;

	const sageConfig = await loadConfig(context.configPath, logger);

	const plugins = context.plugins;
	if (plugins.length === 0) {
		logger.debug("Session plugin scan completed", {
			totalPlugins: 0,
			resultsWithFindings: 0,
			findingsCount: 0,
			cacheHits: 0,
			cacheMisses: 0,
			scanned: 0,
			allowedByException: 0,
			deniedByException: 0,
		});
		return [];
	}

	// Load exceptions for plugin allow/deny rules
	let exceptions: ExceptionRule[] = [];
	try {
		exceptions = await loadExceptions(sageConfig.exceptions, logger);
	} catch {
		// Fail open — proceed without exceptions.
	}

	// Initialize AMSI once, reuse across all plugins
	let amsiClient: AmsiClient | null = null;
	if (sageConfig.amsi_check.enabled && isAmsiSupported()) {
		try {
			amsiClient = new AmsiClient(logger);
			await amsiClient.init();
			if (!amsiClient.isAvailable) {
				amsiClient.close();
				amsiClient = null;
			}
		} catch {
			amsiClient?.close();
			amsiClient = null;
		}
	}

	try {
		return await scanAllPlugins(context, sageConfig, plugins, exceptions, amsiClient, logger);
	} finally {
		amsiClient?.close();
	}
}

async function scanAllPlugins(
	context: SessionStartScanContext,
	config: Config,
	plugins: PluginInfo[],
	exceptions: ExceptionRule[],
	amsiClient: AmsiClient | null,
	logger: Logger,
): Promise<PluginScanResult[]> {
	const configHash = await computeConfigHash(
		context.sageVersion ?? "",
		context.threatsDir,
		context.trustedDomainsDir,
	);
	const cache = await loadScanCache(configHash, context.scanCachePath, logger);
	const resultsWithFindings: PluginScanResult[] = [];
	let cacheModified = false;
	const stats = {
		totalPlugins: plugins.length,
		cacheHitsClean: 0,
		cacheHitsWithFindings: 0,
		cacheMisses: 0,
		scanned: 0,
		allowedByException: 0,
		deniedByException: 0,
		findingsCount: 0,
	};

	const skillPendingPath = context.sageDirPath
		? join(context.sageDirPath, "skill_pending.json")
		: undefined;
	const skillVerdictCachePath = context.sageDirPath
		? join(context.sageDirPath, "skill_verdict_cache.json")
		: undefined;
	const cacheTtlMs = skillCacheTtlMs(config);

	for (const plugin of plugins) {
		// 1. Exception checks — always run first, before cache
		const denyMatch = findPluginDenyException(exceptions, plugin.key);
		if (denyMatch) {
			stats.deniedByException += 1;
			stats.findingsCount += 1;
			resultsWithFindings.push({
				plugin,
				findings: [
					{
						threatId: "EXCEPTION-DENY",
						title: `Denied by exception: ${denyMatch.pattern}${denyMatch.reason ? ` — ${denyMatch.reason}` : ""}`,
						severity: "critical",
						artifact: plugin.key,
						sourceFile: "~/.sage/exceptions.json",
					},
				],
			});
			continue;
		}

		const allowMatch = findPluginAllowException(exceptions, plugin.key);
		if (allowMatch) {
			stats.allowedByException += 1;
			continue;
		}

		// 2. Cache check (only reached when no exception matched)
		const cached = getCached(cache, plugin.key, plugin.version, plugin.lastUpdated, cacheTtlMs);
		if (cached && cached.findings.length === 0) {
			stats.cacheHitsClean += 1;
			continue;
		}

		if (cached && cached.findings.length > 0) {
			stats.cacheHitsWithFindings += 1;
			stats.findingsCount += cached.findings.length;
			resultsWithFindings.push({
				plugin,
				findings: cached.findings.map(fromCachedFinding),
			});
			continue;
		}

		// 3. Scan (only reached on cache miss with no exception)
		stats.cacheMisses += 1;
		stats.scanned += 1;
		const result = await scanPlugin(plugin, {
			checkUrls: context.checkUrls ?? true,
			checkFileHashes: context.checkFileHashes ?? true,
			checkSkills: config.skill_check.enabled,
			uploadEnabled: context.uploadUnknownSkills ?? config.skill_check.upload_enabled,
			deferUnknownSkills: context.deferUnknownSkills,
			amsiClient,
			logger,
			skillPendingPath,
			skillVerdictCachePath,
			skillVerdictTtlMs: cacheTtlMs,
			loggingConfig: config.logging,
			agentRuntime: context.agentRuntime,
		});

		// Don't cache a plugin whose skill verdict is still pending (queued for
		// the upload worker) — re-scan next session to pick up the verdict and
		// surface it as a finding for skills that are still installed.
		if (result.deferCache) {
			logger.debug("Plugin cache deferred (skill verdict pending)", { plugin: plugin.key });
		} else {
			storeResult(
				cache,
				plugin.key,
				plugin.version,
				plugin.lastUpdated,
				result.findings.map(toFindingData),
			);
			cacheModified = true;
		}

		if (result.findings.length > 0) {
			stats.findingsCount += result.findings.length;
			resultsWithFindings.push(result);
		}
	}

	if (cacheModified) {
		await saveScanCache(cache, context.scanCachePath, logger);
	}

	try {
		for (const result of resultsWithFindings) {
			await logPluginScan(
				config.logging,
				result.plugin.key,
				result.plugin.version,
				result.findings.map(toAuditFindingData),
			);
		}
	} catch {
		// Logging must never crash the hook.
	}

	logger.debug("Session plugin scan completed", {
		...stats,
		cacheHits: stats.cacheHitsClean + stats.cacheHitsWithFindings,
		resultsWithFindings: resultsWithFindings.length,
	});

	return resultsWithFindings;
}
