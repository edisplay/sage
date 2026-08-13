/**
 * Startup and session scan handlers for OpenClaw.
 * Thin wrappers over core's createScanHandler.
 */

import { resolve } from "node:path";
import {
	type Branding,
	createScanHandler as coreScanHandler,
	defaultBranding,
	type Logger,
} from "@gendigital/sage-core";
import { getBundledDataDirs, getSageVersion } from "./bundled-dirs.js";
import { discoverOpenClawPlugins } from "./plugin-discovery.js";

function createOpenClawScanHandler(
	logger: Logger,
	context: string,
	branding: Branding = defaultBranding,
	onResult?: (msg: string) => void,
	announceCleanScans = true,
): () => Promise<void> {
	const { threatsDir, trustedDomainsDir } = getBundledDataDirs();
	const version = getSageVersion();

	return coreScanHandler({
		logger,
		context,
		discoverPlugins: () => discoverOpenClawPlugins(logger, undefined, branding),
		selfPrefix: "@gendigital/sage-openclaw@",
		threatsDir,
		trustedDomainsDir,
		version,
		agentRuntime: "openclaw",
		// No agentRuntimeVersion: the OpenClaw plugin API exposes no host version.
		branding,
		onResult,
		// No onNotices: OpenClaw delivers the one-time notice from
		// `before_agent_start` (a different process/turn than this scan) via
		// takePendingNotices, so the scan-time callback would never fire.
		modelDownloadWorkerPath: resolve(__dirname, "model-download-worker.cjs"),
		skillUploadWorkerPath: resolve(__dirname, "skill-upload-worker.cjs"),
		// Don't commit the "shown" flag here — commit happens at delivery.
		commitUploadNotice: false,
		announceCleanScans,
	});
}

export function createStartupScanHandler(
	logger: Logger,
	branding: Branding = defaultBranding,
	onResult?: (msg: string) => void,
	announceCleanScans = true,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "startup", branding, onResult, announceCleanScans);
}

export function createSessionScanHandler(
	logger: Logger,
	branding: Branding = defaultBranding,
	onResult?: (msg: string) => void,
	announceCleanScans = true,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "session", branding, onResult, announceCleanScans);
}

/**
 * Creates a before_agent_start handler that surfaces one-time notices and
 * plugin scan findings as prepended context.
 *
 * Notices and security findings ride SEPARATE blocks on purpose. A one-time
 * notice (e.g. the skill-upload consent message) is informational — it must not
 * be framed as a `<security-alert>` finding, and it must surface even when there
 * are no scan findings at all. Because OpenClaw exposes no direct UI, prepended
 * agent context is the only channel to the user; the model is asked to relay it.
 *
 * The notice text is passed IN per call (derived from disk at delivery time by
 * `takePendingNotices`), not read from an in-memory queue: `before_agent_start`
 * runs in a different process/turn than the async scan, so a scan-populated queue
 * is empty when this fires. Security findings still come from the in-process
 * closure — one-shot, cleared after the first delivery.
 */
export function createBeforeAgentStartHandler(
	getSecurityFindings: () => string | null,
	clearFindings: () => void,
	logger: Logger,
	branding: Branding = defaultBranding,
): (notices: string | null) => { prependContext: string } | undefined {
	return (notices: string | null) => {
		const findings = getSecurityFindings();
		if (!notices && !findings) {
			logger.debug(`${branding.name}: before_agent_start - nothing pending to surface`);
			return undefined;
		}

		if (findings) clearFindings();
		logger.debug(`${branding.name}: surfacing context via before_agent_start`, {
			hasNotices: Boolean(notices),
			hasFindings: Boolean(findings),
		});

		const blocks: string[] = [];
		if (notices) {
			blocks.push(
				[
					'<sage-notice source="sage-session-start">',
					notices,
					"",
					"Relay this notice to the user. It is informational, not a security finding.",
					"</sage-notice>",
				].join("\n"),
			);
		}
		if (findings) {
			blocks.push(
				[
					'<security-alert source="sage-plugin-scan">',
					findings,
					"",
					"Inform the user about these security findings.",
					"</security-alert>",
				].join("\n"),
			);
		}

		return { prependContext: blocks.join("\n\n") };
	};
}
