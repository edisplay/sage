/**
 * Sage OpenCode plugin.
 * Intercepts tool calls and uses @gendigital/sage-core to enforce security verdicts.
 */

import { mkdirSync, watchFile } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AgentRuntime,
	ApprovalStore,
	approveAction,
	checkAllowlistMigration,
	createOperationalLogger,
	foreignSourceRuntime,
	formatAllowlistMigrationWarning,
	formatConfigurationWarnings,
	formatNoticeById,
	getConfigurationWarnings,
	type Logger,
	loadConfig,
	loadSkillVerdictCache,
	type PluginFinding,
	type PluginScanResult,
	resolveBranding,
	resolvePath,
} from "@gendigital/sage-core";
import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import { getBundledDataDirs } from "./bundled-dirs.js";
import { createSessionScanHandler } from "./startup-scan.js";
import { createToolHandlers } from "./tool-handler.js";

const APPROVAL_STORE_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

type ToastVariant = "info" | "success" | "warning" | "error";
type ToastFn = (msg: string, variant: ToastVariant, durationMs?: number) => void;

const DEFAULT_TOAST_DURATION_MS = 5000;

// The startup security summary lists every risky skill, so it's shown longer to
// give the user time to read the list before it dismisses.
const STARTUP_SUMMARY_DURATION_MS = 10_000;

// Module-scoped so repeated SagePlugin instantiations (OpenCode may load the
// plugin more than once) share a single watcher and one notified-set, instead
// of each instance attaching its own watcher and toasting the same verdict.
const notifiedSkillVerdicts = new Set<string>();
let skillWatcherAttached = false;

// One scan per session, shared across instances: the entry guards against
// re-running the scan when session.updated fires repeatedly or on more than one
// plugin instance.
const sessionScanPromises = new Map<string, Promise<void>>();

interface QueuedToast {
	message: string;
	variant: ToastVariant;
	durationMs: number;
}
const toastQueue: QueuedToast[] = [];
let toastPumpRunning = false;
// Bound to a live client's showToast by the first instance (see SagePlugin).
let displayToast: ToastFn | undefined;

async function pumpToasts(): Promise<void> {
	if (toastPumpRunning) return;
	toastPumpRunning = true;
	try {
		while (toastQueue.length > 0) {
			const next = toastQueue[0];
			// No client bound yet — leave the item queued; a later enqueue resumes.
			if (!displayToast || !next) break;
			displayToast(next.message, next.variant, next.durationMs);
			toastQueue.shift();
			// Hold the slot for this toast's full duration before showing the next,
			// so a following toast can't replace it early (showToast overwrites).
			await new Promise((resolve) => setTimeout(resolve, next.durationMs));
		}
	} finally {
		toastPumpRunning = false;
	}
}

function enqueueToast(
	message: string,
	variant: ToastVariant,
	durationMs = DEFAULT_TOAST_DURATION_MS,
): void {
	toastQueue.push({ message, variant, durationMs });
	void pumpToasts();
}

// Shared dedup key across the two surfacing paths: the scan-findings popup keys
// on `finding.artifact` (which is `skillId.slice(0, 16)`), and the cache watcher
// keys on the full skillId — so both reduce to this 16-char content-hash prefix
// and `notifiedSkillVerdicts` never double-announces the same skill version.
function shortSkillId(skillId: string): string {
	return skillId.slice(0, 16);
}

interface RiskySkill {
	skillId: string;
	key: string;
	severity: "CRITICAL" | "WARNING";
	summary?: string;
}

/**
 * Read `~/.sage/skill_verdict_cache.json` and return every HIGH/CRITICAL verdict
 * relevant to this runtime — one per cache entry, NOT deduped, since dedup is
 * caller-specific (the popup keys on current content, the toast queue on
 * skillId). HIGH maps to the "WARNING" label. Verdicts sourced only from other
 * agent runtimes are skipped so one host doesn't echo another's finds.
 */
async function collectRiskySkills(agentRuntime: AgentRuntime): Promise<RiskySkill[]> {
	const cache = await loadSkillVerdictCache();
	const out: RiskySkill[] = [];
	for (const [skillId, verdict] of Object.entries(cache.entries)) {
		const risk = (verdict.verdict ?? "").toUpperCase();
		if (risk !== "HIGH" && risk !== "CRITICAL") continue;
		if (foreignSourceRuntime(verdict.sources, agentRuntime)) continue;
		const key =
			verdict.sources?.find((s) => s.containerKey)?.containerKey ||
			verdict.skillName ||
			skillId.slice(0, 16);
		out.push({
			skillId,
			key,
			severity: risk === "CRITICAL" ? "CRITICAL" : "WARNING",
			summary: verdict.summary?.trim(),
		});
	}
	return out;
}

/**
 * Watch `~/.sage/skill_verdict_cache.json` and queue one toast per verdict the
 * upload worker writes mid-session (it writes asynchronously, ~one session after
 * discovery). The serial queue shows them one at a time so two skills finishing
 * together are both seen.
 *
 * Verdicts cached by earlier sessions are *seeded silently* on attach — marked
 * notified without a toast — because the plugin initialises before the TUI is
 * ready to render toasts. Those are surfaced instead by the session-start
 * summary popup (see `surfaceStartupSummary`), which runs after the scan when
 * the TUI is up.
 *
 * Dedup keys on `skillId` (content hash), not the container key, so editing a
 * skill — which yields a new hash under the same key — is treated as a new
 * finding and re-announced rather than silently collapsed into the old one.
 */
function setupSkillFindingsWatcher(logger: Logger, agentRuntime: AgentRuntime): void {
	if (skillWatcherAttached) return;
	const sageDir = resolvePath("~/.sage");

	const seedNotified = async (): Promise<void> => {
		try {
			for (const s of await collectRiskySkills(agentRuntime)) {
				notifiedSkillVerdicts.add(shortSkillId(s.skillId));
			}
		} catch (e) {
			logger.debug("Skill verdict seed failed", { error: String(e) });
		}
	};

	// Mid-session: queue one toast per newly written (not-yet-notified) verdict.
	const announceNew = async (): Promise<void> => {
		try {
			for (const s of await collectRiskySkills(agentRuntime)) {
				const short = shortSkillId(s.skillId);
				if (notifiedSkillVerdicts.has(short)) continue;
				notifiedSkillVerdicts.add(short);
				const detail = s.summary ? `${s.key} — ${s.summary}` : `${s.key} detected`;
				logger.debug("Skill finding toast queued", { key: s.key, severity: s.severity });
				enqueueToast(`${detail} (${s.severity})`, s.severity === "CRITICAL" ? "error" : "warning");
			}
		} catch (e) {
			logger.debug("Skill verdict watcher scan failed", { error: String(e) });
		}
	};

	try {
		mkdirSync(sageDir, { recursive: true });
		void seedNotified();
		// Poll the cache file with watchFile rather than watch() the directory.
		// On Windows, fs.watch aborts the whole process (an uncatchable libuv
		// assertion in fs-event.c) when the watched path is an 8.3 short name
		// (e.g. an os.tmpdir() like C:\Users\FOO~1.BAR\...) or symlinked home.
		// watchFile is stat-based polling — immune to that. A few seconds of
		// latency for mid-session verdicts is fine (matches the statusline poll
		// cadence used elsewhere). Handles a not-yet-existent file (polls until
		// it appears).
		const cacheFile = join(sageDir, "skill_verdict_cache.json");
		const watcher = watchFile(cacheFile, { interval: 3000 }, (curr, prev) => {
			if (curr.mtimeMs !== prev.mtimeMs) void announceNew();
		});
		watcher.unref?.();
		skillWatcherAttached = true;
		logger.debug("Skill findings watcher attached", { cacheFile });
	} catch (e) {
		// ~/.sage/ may be unwritable — no watcher, no notifications (fail-open).
		logger.debug("Skill findings watcher setup failed", { error: String(e) });
	}
}

export const SagePlugin: Plugin = async ({ client, directory }) => {
	const config = await loadConfig();
	const operationalLogger = createOperationalLogger(config.operational_logging, "opencode");
	const logger = operationalLogger.forComponent("plugin");
	const toolLogger = operationalLogger.forComponent("tool-handler");
	const scanLogger = operationalLogger.forComponent("startup-scan");
	const branding = resolveBranding(config.brand_key, logger);
	const showToast: ToastFn = (msg, variant, durationMs = DEFAULT_TOAST_DURATION_MS) => {
		client.tui
			.showToast({
				body: { title: branding.name, message: msg, variant, duration: durationMs },
			})
			.catch(() => {});
	};
	// Bind the module-scoped skill-toast queue to this (first) instance's client.
	// The queue passes each item's own duration, which showToast honors.
	displayToast ??= showToast;
	const warningMessage = formatConfigurationWarnings(
		await getConfigurationWarnings(undefined, logger),
		branding,
	);
	if (warningMessage) {
		client.tui
			.showToast({
				body: {
					title: branding.name,
					message: warningMessage,
					variant: "warning",
					duration: DEFAULT_TOAST_DURATION_MS,
				},
			})
			.catch(() => {});
	}
	const allowlistMigration = await checkAllowlistMigration();
	if (allowlistMigration.needed) {
		client.tui
			.showToast({
				body: {
					title: branding.name,
					message: formatAllowlistMigrationWarning(allowlistMigration.entryTypes, branding),
					variant: "warning",
					duration: 8000,
				},
			})
			.catch(() => {});
	}
	const { threatsDir, trustedDomainsDir } = getBundledDataDirs();
	const approvalStore = new ApprovalStore();

	// Watch for verdicts the upload worker writes mid-session (queued toasts).
	// Verdicts cached by earlier sessions are surfaced by surfaceStartupSummary.
	setupSkillFindingsWatcher(logger, "opencode");

	// Surface the scan's structured findings after the scan (TUI ready). Findings
	// are install- and content-accurate: the scan hashes current on-disk content
	// and looks up its verdict, so a deleted skill isn't discovered and an edited
	// skill is matched by its new hash — no cache re-derivation needed.
	//
	// Single startup surface: one summary toast listing every risky skill from
	// this scan. Summarized skills are marked notified so the cache watcher does
	// not also announce them per-skill; verdicts that land *after* the scan
	// (worker uploads) are still surfaced individually by the watcher.
	const surfaceStartupSummary = (scanResults: PluginScanResult[]): void => {
		try {
			const skills: Array<{
				key: string;
				severity: "CRITICAL" | "WARNING";
				finding: PluginFinding;
			}> = [];
			const seen = new Set<string>();
			for (const result of scanResults) {
				for (const finding of result.findings) {
					if (finding.threatId !== "SKILL_CHECK") continue;
					if (finding.severity !== "critical" && finding.severity !== "warning") continue;
					if (seen.has(result.plugin.key)) continue;
					seen.add(result.plugin.key);
					skills.push({
						key: result.plugin.key,
						severity: finding.severity === "critical" ? "CRITICAL" : "WARNING",
						finding,
					});
				}
			}
			if (skills.length === 0) return;

			// Mark every summarized skill as notified so the cache watcher doesn't
			// also announce it per-skill. `finding.artifact` is the 16-char short
			// hash — the same key the watcher dedups on. Verdicts that land after
			// this scan (worker uploads) are still surfaced individually.
			for (const s of skills) {
				if (s.finding.artifact) notifiedSkillVerdicts.add(s.finding.artifact);
			}

			// The summary: a single toast listing every risky skill, shown longer.
			const hasCritical = skills.some((s) => s.severity === "CRITICAL");
			const body = skills.map((s) => `${s.key} (${s.severity})`).join("\n");
			enqueueToast(
				`${branding.name} detected ${skills.length} malicious/suspicious skill(s):\n${body}`,
				hasCritical ? "error" : "warning",
				STARTUP_SUMMARY_DURATION_MS,
			);
		} catch (e) {
			logger.debug("Skill summary popup failed", { error: String(e) });
		}
	};

	// Set up the cron job that cleans up the approval store.
	const interval = setInterval(() => {
		approvalStore.cleanup();
	}, APPROVAL_STORE_CLEANUP_INTERVAL_MS);
	interval.unref?.();

	const toolHandlers = createToolHandlers(
		toolLogger,
		approvalStore,
		threatsDir,
		trustedDomainsDir,
		{ showToast },
		branding,
	);

	/**
	 * Run the session scan exactly once per session and cache the promise. The
	 * cached promise is the dedupe guard — a second call (repeated
	 * `session.updated`, or another plugin instance) returns the same
	 * in-flight/settled promise instead of re-scanning. The scan's structured
	 * findings drive the summary popup (see `surfaceStartupSummary`).
	 */
	const scanSession = (sessionID: string): Promise<void> => {
		if (sessionID === "unknown") return Promise.resolve();
		const existing = sessionScanPromises.get(sessionID);
		if (existing) return existing;

		const promise = (async () => {
			logger.debug(`${branding.name}: starting session scan`, { sessionID });
			const scanHandler = createSessionScanHandler(
				scanLogger,
				directory,
				// After the scan (TUI ready): summary popup from the structured findings.
				surfaceStartupSummary,
				branding,
				// One-time notices (e.g. skill-upload consent) as info toasts.
				(noticeIds) => {
					for (const id of noticeIds) {
						const text = formatNoticeById(id, branding);
						if (text) enqueueToast(text, "info", STARTUP_SUMMARY_DURATION_MS);
					}
				},
			);
			await scanHandler();
		})();
		sessionScanPromises.set(sessionID, promise);
		return promise;
	};

	return {
		/**
		 * Register the Sage MCP server so sage_report_false_positive /
		 * sage_list_audit_entries are available as agent tools. OpenCode runs
		 * config hooks before MCP init, so mutating cfg.mcp here is sufficient.
		 * ??= ensures a user-supplied override in opencode.json is never clobbered.
		 */
		config: async (cfg) => {
			const dir = dirname(fileURLToPath(import.meta.url));
			const serverPath = join(dir, "mcp-server.cjs");
			// biome-ignore lint/suspicious/noExplicitAny: OpenCode Config.mcp types not exported
			const mcp = (cfg as any).mcp as Record<string, unknown> | undefined;
			if (mcp?.sage) return;
			// biome-ignore lint/suspicious/noExplicitAny: assigning McpLocalConfig without importing its type
			(cfg as any).mcp = {
				...mcp,
				sage: {
					type: "local",
					command: [process.execPath, serverPath],
					environment: { BUN_BE_BUN: "1", SAGE_AGENT_RUNTIME: "opencode" },
					enabled: true,
				},
			};
		},

		"tool.execute.before": toolHandlers["tool.execute.before"],

		// Run the session scan on the first session.updated event. It discovers
		// skills, populates the verdict cache, and (post-scan, once the TUI is up)
		// shows the summary popup. OpenCode >=1.3 replaced session.created with
		// session.updated. Dedupe + the work live in scanSession.
		event: async ({ event }) => {
			if (event.type !== "session.updated") return;
			// biome-ignore lint/suspicious/noExplicitAny: Event types from SDK not fully typed
			const props = (event as any).properties;
			const sessionID = props?.sessionID ?? props?.info?.id ?? "unknown";
			await scanSession(sessionID);
		},

		tool: {
			sage_approve: tool({
				description: `Review a ${branding.name}-flagged tool call. Shows a native approval dialog to the user. Call this immediately when ${branding.name} flags an action — do NOT ask the user in chat first.`,
				args: {
					actionId: tool.schema
						.string()
						.describe(`Action ID from ${branding.name} flagged message`),
				},
				async execute(args: { actionId: string }, context) {
					const pending = approvalStore.getPending(args.actionId);
					if (!pending) {
						return `No pending ${branding.name} approval found for this action ID.`;
					}

					try {
						// "doom_loop" is the only permission OpenCode always gates with an ask dialog,
						// bypassing wildcard `*: allow` defaults. If OpenCode changes this, the dialog silently stops appearing.
						await context.ask({
							permission: "doom_loop",
							patterns: pending.artifacts.map((a) => `[${a.type}] ${a.value}`),
							always: [],
							metadata: {},
						});
					} catch (error) {
						logger.debug(`${branding.name}: approval dialog failed`, {
							actionId: args.actionId,
							error: String(error),
						});
						approvalStore.deletePending(args.actionId);
						logger.debug("OpenCode approval rejected", { actionId: args.actionId });
						return "Rejected by user.";
					}
					logger.info("OpenCode approval accepted", { actionId: args.actionId });

					return approveAction(approvalStore, args.actionId, branding);
				},
			}),
		},
	};
};

export default SagePlugin;
