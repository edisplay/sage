/**
 * Generic scan orchestration for all connectors.
 * Extracts the common runScan + createScanHandler pattern from
 * OpenCode/OpenClaw startup-scan files.
 */

import { defaultBranding } from "./brands.js";
import { formatSessionStartMessage, type ThreatBannerStyle } from "./format.js";
import { runSessionStart } from "./session-start.js";
import type { AgentRuntime, Branding, Logger, PluginInfo } from "./types.js";

/**
 * Run a plugin scan with the given plugins and return a formatted status message.
 * Always returns a message (clean or findings) — callers can always show the result.
 *
 * `style` controls the threat-banner layout and defaults to `"verbose"` for
 * backwards compatibility with existing CLI hosts (Claude Code, OpenClaw).
 * IDE connectors that surface the result through a small toast (Cursor /
 * VS Code) should pass `"compact"`.
 */
export async function runPluginScan(
	logger: Logger,
	context: string,
	plugins: PluginInfo[],
	threatsDir: string,
	trustedDomainsDir: string,
	version: string,
	agentRuntime: AgentRuntime,
	branding: Branding = defaultBranding,
	modelDownloadWorkerPath?: string,
	style: ThreatBannerStyle = "verbose",
	// Trailing optional to stay backward-compatible with existing positional callers.
	agentRuntimeVersion?: string,
	skillUploadWorkerPath?: string,
	onNotices?: (noticeIds: string[]) => void,
	commitUploadNotice?: boolean,
	announceCleanScans = true,
): Promise<string> {
	logger.debug(`${branding.name} plugin scan started (${context})`, {
		agentRuntime,
		pluginsCount: plugins.length,
		threatsDir,
		trustedDomainsDir,
	});

	const result = await runSessionStart({
		plugins,
		threatsDir,
		trustedDomainsDir,
		version,
		logger,
		agentRuntime,
		agentRuntimeVersion,
		modelDownloadWorkerPath,
		skillUploadWorkerPath,
		commitUploadNotice,
	});

	if (result.notices && result.notices.length > 0) {
		logger.debug(`${branding.name} session-start produced notices`, {
			context,
			noticeIds: result.notices,
			forwarded: Boolean(onNotices),
		});
		onNotices?.(result.notices);
	} else {
		logger.debug(`${branding.name} session-start produced no notices`, { context });
	}

	const findingsCount = result.scanResults.reduce(
		(total, scanResult) => total + scanResult.findings.length,
		0,
	);
	const completionData = {
		agentRuntime,
		pluginsCount: plugins.length,
		resultsWithFindings: result.scanResults.length,
		findingsCount,
		updateAvailable: result.versionCheck?.updateAvailable ?? false,
	};
	if (findingsCount > 0) {
		logger.warn(`${branding.name} plugin scan (${context}) complete with findings`, completionData);
	} else {
		logger.debug(`${branding.name} plugin scan (${context}) complete`, completionData);
	}

	// Suppress the noisy "No threats found" banner when the install opts out.
	// Threat banners are unaffected because findingsCount > 0 always wins here.
	if (findingsCount === 0 && !announceCleanScans) {
		return "";
	}

	return formatSessionStartMessage(version, result, branding, style);
}

/**
 * Convenience wrapper for in-process connectors: discovery + self-filter + scan + error handling.
 */
export interface ScanHandlerOptions {
	logger: Logger;
	context: string;
	discoverPlugins: () => Promise<PluginInfo[]>;
	selfPrefix: string;
	threatsDir: string;
	trustedDomainsDir: string;
	version: string;
	agentRuntime: AgentRuntime;
	/** Host runtime version (e.g. Cursor `"3.6.31"`, Claude Code `"2.1.150"`). Omit when no source exists. */
	agentRuntimeVersion?: string;
	branding?: Branding;
	onResult?: (msg: string) => void;
	/** Called with one-time notice ids to surface (rendered via formatNoticeById). */
	onNotices?: (noticeIds: string[]) => void;
	/** Connector-bundled `dist/model-download-worker.cjs` (see runSessionStart). */
	modelDownloadWorkerPath?: string;
	/** Connector-bundled `dist/skill-upload-worker.cjs` (see runSessionStart). */
	skillUploadWorkerPath?: string;
	/** Threat-banner style passed through to `runPluginScan`. Defaults to verbose. */
	style?: ThreatBannerStyle;
	/**
	 * Whether the scan may commit the one-time notice flag and surface it. Defaults
	 * true. Connectors that deliver notices in a separate process/turn (OpenClaw)
	 * pass false and commit at delivery via `takePendingNotices`.
	 */
	commitUploadNotice?: boolean;
	/**
	 * When false, `runPluginScan` returns "" for a clean scan and the connector
	 * skips its user-facing surface. Threat scans are unaffected. Defaults to
	 * true so connectors that don't plumb the config opt-in retain today's
	 * behaviour.
	 */
	announceCleanScans?: boolean;
}

export function createScanHandler(options: ScanHandlerOptions): () => Promise<void> {
	const {
		logger,
		context,
		discoverPlugins,
		selfPrefix,
		threatsDir,
		trustedDomainsDir,
		version,
		agentRuntime,
		agentRuntimeVersion,
		branding = defaultBranding,
		onResult,
		onNotices,
		modelDownloadWorkerPath,
		skillUploadWorkerPath,
		style = "verbose",
		commitUploadNotice,
		announceCleanScans = true,
	} = options;

	return async () => {
		try {
			let plugins = await discoverPlugins();
			plugins = plugins.filter((p) => !p.key.startsWith(selfPrefix));

			if (plugins.length === 0) {
				logger.debug(
					`${branding.name} plugin scan (${context}): no plugins to scan after filtering`,
				);
			}

			const msg = await runPluginScan(
				logger,
				context,
				plugins,
				threatsDir,
				trustedDomainsDir,
				version,
				agentRuntime,
				branding,
				modelDownloadWorkerPath,
				style,
				agentRuntimeVersion,
				skillUploadWorkerPath,
				onNotices,
				commitUploadNotice,
				announceCleanScans,
			);
			if (msg !== "") {
				onResult?.(msg);
			}
		} catch (e) {
			logger.error(`${branding.name} ${context} scan failed`, { error: String(e) });
		}
	};
}
