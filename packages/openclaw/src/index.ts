/**
 * Sage OpenClaw plugin entry point.
 * Registers before_tool_call handler, startup/session scan hooks,
 * and before_prompt_build handler.
 */

import {
	ApprovalStore,
	checkAllowlistMigration,
	createOperationalLogger,
	formatAllowlistMigrationWarning,
	formatConfigurationWarnings,
	formatNoticeById,
	getConfigurationWarningsSync,
	loadConfigSync,
	resolveBranding,
	takePendingNotices,
} from "@gendigital/sage-core";
import { getBundledDataDirs } from "./bundled-dirs.js";
import {
	createPromptContextHandler,
	createSessionScanHandler,
	createStartupScanHandler,
} from "./startup-scan.js";
import { createToolCallHandler } from "./tool-handler.js";

interface PluginApi {
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
	on(event: string, handler: (...args: any[]) => any, options?: { priority?: number }): void;
}

// Load branding at module scope so the plugin registration name reflects the brand.
// Uses loadConfigSync because branding depends on config.brand_key and this runs
// before any async init (OpenClaw reads `name` from the default export at import time).
const config = loadConfigSync();
const branding = resolveBranding(config.brand_key);

export default {
	id: "sage-openclaw",
	name: branding.name,
	description: "Safety for Agents — ADR layer that guards commands, files, and web requests",
	configSchema: {
		jsonSchema: { type: "object", additionalProperties: false, properties: {} },
	},
	register(api: PluginApi) {
		const operationalLogger = createOperationalLogger(config.operational_logging, "openclaw");
		const logger = operationalLogger.forComponent("plugin");
		const toolLogger = operationalLogger.forComponent("tool-handler");
		const scanLogger = operationalLogger.forComponent("startup-scan");
		const approvalStore = new ApprovalStore();
		const { threatsDir, trustedDomainsDir } = getBundledDataDirs();

		const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
		const interval = setInterval(() => approvalStore.cleanup(), CLEANUP_INTERVAL_MS);
		if (typeof interval.unref === "function") interval.unref();

		// Shared state: warnings/findings waiting to be surfaced to the user.
		let pendingConfigurationWarnings =
			formatConfigurationWarnings(getConfigurationWarningsSync(undefined, logger), branding) ??
			null;
		// Store the promise so before_prompt_build can await it — avoids a race where
		// before_prompt_build fires before the file read completes and the notice is lost.
		const migrationCheckPromise = checkAllowlistMigration()
			.then((result) => {
				if (result.needed) {
					const notice = formatAllowlistMigrationWarning(result.entryTypes, branding);
					pendingConfigurationWarnings = pendingConfigurationWarnings
						? `${pendingConfigurationWarnings}\n\n${notice}`
						: notice;
				}
			})
			.catch(() => {});
		let pendingScanFindings: string | null = null;
		const onFindings = (msg: string) => {
			pendingScanFindings = msg;
		};
		// Security findings (config warnings + scan results) share one block; the
		// one-time notice rides its own block (see below) so it is never framed as
		// a security alert.
		const getPendingSecurityFindings = () =>
			[pendingConfigurationWarnings, pendingScanFindings].filter(Boolean).join("\n\n") || null;

		const promptContextHandler = createPromptContextHandler(
			getPendingSecurityFindings,
			() => {
				pendingConfigurationWarnings = null;
				pendingScanFindings = null;
			},
			logger,
			branding,
		);

		// Resolve one-time notices from disk at delivery time. The scan
		// (gateway_start/session_start) runs in a different process/turn and its
		// in-memory hand-off never reaches before_prompt_build, so we read
		// install-state.json here and commit each notice's "shown" flag exactly
		// when it is handed to the user. Idempotent: only the first turn per
		// install returns anything.
		const resolveNoticeText = async (): Promise<string | null> => {
			try {
				const ids = await takePendingNotices({ logger });
				const text = ids
					.map((id) => formatNoticeById(id, branding))
					.filter(Boolean)
					.join("\n\n");
				logger.debug(`${branding.name}: notices resolved for delivery`, {
					noticeIds: ids,
					willShow: text.length > 0,
				});
				return text.length > 0 ? text : null;
			} catch (e) {
				logger.warn(`${branding.name}: notice resolution failed`, { error: String(e) });
				return null;
			}
		};

		api.on(
			"before_tool_call",
			createToolCallHandler(approvalStore, toolLogger, threatsDir, trustedDomainsDir, branding),
			{ priority: 100 },
		);
		api.on(
			"gateway_start",
			createStartupScanHandler(scanLogger, branding, onFindings, config.announce_clean_scans),
		);
		api.on(
			"session_start",
			createSessionScanHandler(scanLogger, branding, onFindings, config.announce_clean_scans),
		);
		// before_prompt_build replaces the legacy before_agent_start hook, which
		// OpenClaw removed in 2026.9.x (ClawHub's Plugin Inspector rejects packages
		// that still register it). Both return the same `prependContext` shape.
		api.on("before_prompt_build", async () => {
			await migrationCheckPromise;
			const notices = await resolveNoticeText();
			return promptContextHandler(notices);
		});
	},
};
