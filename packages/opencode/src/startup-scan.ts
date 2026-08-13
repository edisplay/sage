/**
 * Startup and session scan handlers for OpenCode.
 * Runs core's session scan and hands back the structured findings so the
 * connector can build its own TUI popup (rather than a formatted string).
 */

import { createRequire } from "node:module";
import {
	type Branding,
	defaultBranding,
	type Logger,
	type PluginScanResult,
	runSessionStart,
} from "@gendigital/sage-core";
import { getBundledDataDirs, getSageVersion } from "./bundled-dirs.js";
import { discoverOpenCodePlugins } from "./plugin-discovery.js";

const SELF_PREFIX = "@gendigital/sage-opencode@";

/**
 * OpenCode is published as an unbundled ESM plugin (tsc only). The detached
 * workers therefore live in the `@gendigital/sage-core` package under
 * `dist/`. Resolve via `require.resolve` so we pick them up wherever
 * pnpm/node placed them.
 */
function resolveModelDownloadWorkerPath(): string | undefined {
	try {
		const req = createRequire(import.meta.url);
		return req.resolve("@gendigital/sage-core/dist/model-download-worker.js");
	} catch {
		return undefined;
	}
}

export function resolveSkillUploadWorkerPath(): string | undefined {
	try {
		const req = createRequire(import.meta.url);
		return req.resolve("@gendigital/sage-core/dist/skill-upload-worker.js");
	} catch {
		return undefined;
	}
}

/**
 * Build a session-scan runner. Discovers OpenCode plugins/skills (minus Sage
 * itself), runs the core session scan — which populates the verdict cache and
 * spawns the skill-upload worker — and passes the structured results to
 * `onResults`. Fails open: any error is logged and the handler resolves.
 */
export function createSessionScanHandler(
	logger: Logger,
	projectDir?: string,
	onResults?: (results: PluginScanResult[]) => void,
	branding: Branding = defaultBranding,
	onNotices?: (noticeIds: string[]) => void,
): () => Promise<void> {
	const { threatsDir, trustedDomainsDir } = getBundledDataDirs();
	const version = getSageVersion();

	return async () => {
		try {
			const discovered = await discoverOpenCodePlugins(logger, projectDir, branding);
			const plugins = discovered.filter((p) => !p.key.startsWith(SELF_PREFIX));

			const { scanResults, notices } = await runSessionStart({
				plugins,
				threatsDir,
				trustedDomainsDir,
				version,
				logger,
				agentRuntime: "opencode",
				// No agentRuntimeVersion: the OpenCode SDK exposes no host version synchronously.
				modelDownloadWorkerPath: resolveModelDownloadWorkerPath(),
				skillUploadWorkerPath: resolveSkillUploadWorkerPath(),
			});

			const findingsCount = scanResults.reduce((n, r) => n + r.findings.length, 0);
			logger.debug(`${branding.name} session scan complete`, {
				agentRuntime: "opencode",
				pluginsCount: plugins.length,
				resultsWithFindings: scanResults.length,
				findingsCount,
			});
			// Surface the one-time notice BEFORE the finding toasts. The toast queue
			// is FIFO, so enqueuing notices first shows the "new feature" info ahead
			// of any malware findings.
			if (notices && notices.length > 0) onNotices?.(notices);
			onResults?.(scanResults);
		} catch (error) {
			logger.error(`${branding.name} session scan failed (fail-open)`, {
				error: String(error),
			});
		}
	};
}
