/**
 * Per-install rollout state — `~/.sage/install-state.json`.
 *
 * Purpose: gate the consent transition for skill-content upload.
 * Skill upload defaults on (`upload_enabled: true`), which would silently turn
 * every existing install into an uploader on a background update. To avoid that,
 * the first session that runs the feature shows a one-time notice and uploads
 * nothing; uploading activates from the *next* session onward. New installs go
 * through the identical path, so they too upload from their second session — no
 * new-vs-existing classification is attempted (that signal is unreliable on this
 * transition).
 *
 * Mechanism is a boolean, not a timestamp: the first session with no notice
 * record shows the notice and writes `noticed: true`; any later session sees the
 * flag and uploads. "Next session" is therefore "the next session-start
 * invocation in a different process". The in-process guard below keeps a single
 * process that fires session-start more than once (e.g. OpenClaw's
 * `gateway_start` + `session_start`) from collapsing notice and activation into
 * the same wall-clock session.
 *
 * The `notices` map is keyed by a notice id so future one-time notices reuse the
 * same file and code path. `last_run_version` is a generic marker (which Sage
 * version last ran in this home dir) kept for future rollouts.
 *
 * Fail-open, but inverted from Sage's global convention: when state cannot be
 * read or written, the safe direction here is to NOT upload — the notice repeats
 * and activation is deferred rather than an unintended upload happening.
 *
 * JSON is snake_case per repo convention; the TS interface is camelCase, with
 * conversion at the load/save boundary.
 */

import { join } from "node:path";
import { readExplicitSkillUploadEnabled, resolvePath, SAGE_DIR } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import { NOTICES, SKILL_UPLOAD_NOTICE } from "./notices.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export const INSTALL_STATE_SCHEMA_VERSION = 1;

/** Notice id for the skill-content-upload consent transition (see notices.ts). */
const SKILL_UPLOAD_NOTICE_ID = SKILL_UPLOAD_NOTICE.id;

export interface NoticeRecord {
	/** True once the one-time notice has been shown; the activation trigger. */
	noticed: boolean;
	/** Sage version that first showed the notice (diagnostics only). */
	version?: string;
}

export interface InstallState {
	schemaVersion: number;
	/** Which Sage version last ran in this home dir. Generic rollout marker. */
	lastRunVersion?: string;
	notices: Record<string, NoticeRecord>;
}

function defaultStatePath(sageDirPath?: string): string {
	return join(sageDirPath ?? resolvePath(SAGE_DIR), "install-state.json");
}

function emptyState(): InstallState {
	return { schemaVersion: INSTALL_STATE_SCHEMA_VERSION, notices: {} };
}

/**
 * Load the install state. Fails-open to an empty state on a missing/corrupt
 * file — a fresh install (no file) is indistinguishable from empty, which is
 * exactly the "not yet noticed" starting point.
 */
export async function loadInstallState(
	sageDirPath?: string,
	logger: Logger = nullLogger,
): Promise<InstallState> {
	let raw: string;
	try {
		raw = await getFileContent(defaultStatePath(sageDirPath));
	} catch {
		return emptyState();
	}

	try {
		const data = JSON.parse(raw) as Record<string, unknown>;
		const rawNotices = (data.notices ?? {}) as Record<string, Record<string, unknown>>;
		const notices: Record<string, NoticeRecord> = {};
		for (const [id, rec] of Object.entries(rawNotices)) {
			notices[id] = {
				noticed: rec.noticed === true,
				version: typeof rec.version === "string" ? rec.version : undefined,
			};
		}
		return {
			schemaVersion:
				typeof data.schema_version === "number"
					? data.schema_version
					: INSTALL_STATE_SCHEMA_VERSION,
			lastRunVersion: typeof data.last_run_version === "string" ? data.last_run_version : undefined,
			notices,
		};
	} catch (e) {
		logger.warn("Failed to parse install state; treating as fresh", { error: String(e) });
		return emptyState();
	}
}

/** Persist the install state atomically (snake_case). Fails-open. */
export async function saveInstallState(
	state: InstallState,
	sageDirPath?: string,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		const data = {
			schema_version: state.schemaVersion,
			last_run_version: state.lastRunVersion,
			notices: Object.fromEntries(
				Object.entries(state.notices).map(([id, rec]) => [
					id,
					{ noticed: rec.noticed, version: rec.version },
				]),
			),
		};
		await atomicWriteJson(defaultStatePath(sageDirPath), data);
	} catch (e) {
		logger.warn("Failed to save install state", { error: String(e) });
	}
}

export interface SkillUploadRollout {
	/** Whether unknown skills may be queued and the upload worker spawned this session. */
	uploadActive: boolean;
	/** Whether the connector should show the one-time upload notice this session. */
	showNotice: boolean;
	/**
	 * Grace session: unknown skills must NOT be cached as clean — defer the plugin
	 * scan cache so the next session re-scans and queues them. True during the
	 * one-time-notice session regardless of whether the notice is surfaced now
	 * (commit-at-scan) or later (deferred delivery). Kept distinct from
	 * `showNotice`, which only governs *surfacing the notice at scan time*: the
	 * deferred-delivery path sets `showNotice: false` but must still defer, or the
	 * grace scan poisons the cache and activation slips by a full cache TTL.
	 */
	deferUnknownSkills: boolean;
}

/**
 * The pure rollout decision. Deliberately NOT a `SkillUploadRollout`: here
 * `showNotice` is the *grace-session* signal (notice not yet shown), which the
 * resolver maps onto both `deferUnknownSkills` and — only for commit-at-scan
 * connectors — the connector-facing `showNotice` (surface-the-notice-now).
 */
export interface RolloutDecision {
	/** Whether unknown skills may be queued/uploaded this session. */
	uploadActive: boolean;
	/** Grace session: the notice has not yet been shown for this install. */
	showNotice: boolean;
	/** State to persist, or null when no write is needed (steady state). */
	nextState: InstallState | null;
}

export interface DecideRolloutOptions {
	/** True when `skill_check.upload_enabled` is explicitly set in the user's config. */
	explicitConfig?: boolean;
	/** The explicit config value (only meaningful when `explicitConfig` is true). */
	explicitValue?: boolean;
	/** Current Sage version, recorded on the notice + `last_run_version`. */
	version?: string;
}

/**
 * Pure rollout decision. No IO, no in-process guard — fully unit-testable.
 *
 * Precedence:
 *  1. Explicit `upload_enabled` in config always wins; no notice, no state machine.
 *  2. Otherwise, the notice flag drives it: unset → this is the notice session
 *     (show it, upload OFF, write `noticed: true`); set → activated (upload ON).
 */
export function decideSkillUploadRollout(
	state: InstallState,
	opts: DecideRolloutOptions = {},
): RolloutDecision {
	const versionChanged = opts.version !== undefined && state.lastRunVersion !== opts.version;
	const withVersion = (): InstallState => ({ ...state, lastRunVersion: opts.version });

	// 1. Explicit config wins outright.
	if (opts.explicitConfig) {
		return {
			uploadActive: opts.explicitValue === true,
			showNotice: false,
			nextState: versionChanged ? withVersion() : null,
		};
	}

	// 2. Notice flag governs.
	const notice = state.notices[SKILL_UPLOAD_NOTICE_ID];
	if (notice?.noticed === true) {
		// Already noticed in a prior session → activated.
		return {
			uploadActive: true,
			showNotice: false,
			nextState: versionChanged ? withVersion() : null,
		};
	}

	// First feature-version session: show the notice, upload nothing, and record
	// that we noticed so the next session activates.
	const nextState: InstallState = {
		...state,
		lastRunVersion: opts.version ?? state.lastRunVersion,
		notices: {
			...state.notices,
			[SKILL_UPLOAD_NOTICE_ID]: { noticed: true, version: opts.version },
		},
	};
	return { uploadActive: false, showNotice: true, nextState };
}

/**
 * In-process memo of the resolved rollout. Keeps a single process that invokes
 * session-start more than once (OpenClaw `gateway_start` + `session_start`) from
 * re-reading the freshly-written `noticed: true` on the second fire and
 * activating in the same wall-clock session as the notice. Resets per process
 * (each connector hook is short-lived), which is safe because connectors that
 * fire once per process are unaffected.
 *
 * Activation is therefore gated at the process boundary: for OpenClaw that means
 * a gateway restart, not a `/new` within the same running gateway. In normal use
 * the on-disk `noticed` flag only ever goes false→true (via delivery), so the
 * memo pins `uploadActive` for the run and never uploads in the notice session.
 */
let processRollout: SkillUploadRollout | undefined;

/** Test-only: clear the in-process memo between cases. */
export function resetSkillUploadRolloutForTest(): void {
	processRollout = undefined;
}

/**
 * Resolve the skill-upload rollout for this session. An explicit `upload_enabled`
 * in config wins outright and is re-read on every call (never memoized), so a
 * long-lived connector honors a mid-process opt-out/opt-in without a restart.
 * Otherwise the notice/grace state machine governs: it persists any change
 * (commit-at-scan path only) and is memoized for the rest of the process.
 * Fails-open toward NOT uploading.
 */
export async function resolveSkillUploadRollout(args: {
	sageDirPath?: string;
	configPath?: string;
	version?: string;
	logger?: Logger;
	/**
	 * Whether this call may flip `noticed: true` and surface the notice itself.
	 * Defaults to true — the connector delivers the notice synchronously in the
	 * same process/turn that runs the scan (Claude Code `systemMessage`, OpenCode
	 * toast). Pass **false** for connectors whose user-facing surface runs in a
	 * different process or turn than the scan (OpenClaw `before_prompt_build`):
	 * committing the flag here would mark the notice "shown" before the delivery
	 * surface ever reads it, so it must be deferred to
	 * {@link takePendingNotices} at delivery time. When false, this call does
	 * NOT persist the flag and reports `showNotice: false`; `uploadActive` is
	 * still derived from the on-disk flag.
	 */
	commitNotice?: boolean;
}): Promise<SkillUploadRollout> {
	const commitNotice = args.commitNotice ?? true;
	const logger = args.logger ?? nullLogger;

	// Explicit `upload_enabled` in config wins outright and involves NO notice
	// state machine — so read it on EVERY call, never memoized. This lets a
	// long-lived connector (e.g. the OpenClaw gateway) honor a mid-process
	// opt-out/opt-in without a restart, instead of staying pinned to the
	// boot-time decision.
	let explicit: { present: boolean; value: boolean };
	try {
		explicit = await readExplicitSkillUploadEnabled(args.configPath, logger);
	} catch {
		explicit = { present: false, value: false };
	}
	if (explicit.present) {
		const resolved: SkillUploadRollout = {
			uploadActive: explicit.value === true,
			showNotice: false,
			deferUnknownSkills: false,
		};
		logger.debug("Skill-upload rollout resolved", {
			explicitConfig: true,
			explicitValue: explicit.value,
			uploadActive: resolved.uploadActive,
			showNotice: false,
			deferUnknownSkills: false,
			commitNotice,
			statePersisted: false,
			version: args.version,
		});
		return resolved;
	}

	// Implicit config → the notice/grace state machine governs. Memoize (as
	// before) to keep the no-same-session-activation guard.
	if (processRollout) return processRollout;

	try {
		const state = await loadInstallState(args.sageDirPath, logger);
		const decision = decideSkillUploadRollout(state, { version: args.version });

		if (commitNotice) {
			if (decision.nextState) {
				await saveInstallState(decision.nextState, args.sageDirPath, logger);
			}
			processRollout = {
				uploadActive: decision.uploadActive,
				showNotice: decision.showNotice,
				deferUnknownSkills: decision.showNotice,
			};
		} else {
			// Delivery is deferred: don't flip the flag and don't surface at scan
			// time. `uploadActive` still reflects the on-disk flag (false until a
			// prior delivery committed it). `deferUnknownSkills` still tracks the
			// grace session (decision.showNotice) even though we don't surface the
			// notice here — otherwise the grace scan caches unknown skills as clean
			// and activation slips by a cache TTL.
			processRollout = {
				uploadActive: decision.uploadActive,
				showNotice: false,
				deferUnknownSkills: decision.showNotice,
			};
		}

		logger.debug("Skill-upload rollout resolved", {
			explicitConfig: false,
			uploadActive: processRollout.uploadActive,
			showNotice: processRollout.showNotice,
			deferUnknownSkills: processRollout.deferUnknownSkills,
			commitNotice,
			statePersisted: commitNotice && decision.nextState !== null,
			version: args.version,
		});
	} catch (e) {
		// Fail-open toward not uploading: repeat the notice, defer activation. Also
		// defer the cache so a recovered session re-scans rather than trusting a
		// clean entry written during the failure.
		logger.warn("Skill-upload rollout resolution failed; suppressing upload", {
			error: String(e),
		});
		processRollout = { uploadActive: false, showNotice: commitNotice, deferUnknownSkills: true };
	}
	return processRollout;
}

/**
 * Generic delivery-time notice resolver for connectors whose user surface runs
 * in a different process/turn than the scan (e.g. OpenClaw `before_prompt_build`).
 *
 * Registry-driven and notice-agnostic: it walks {@link NOTICES}, skips any that
 * are already shown (`noticed: true`) or not currently eligible (per each
 * notice's `isEligible`), commits `noticed: true` for the rest, and returns
 * their ids to render. Reads state fresh from disk — no in-memory hand-off — so
 * it works regardless of which process ran the scan.
 *
 * This is the counterpart to `resolveSkillUploadRollout({ commitNotice: false })`:
 * the flag flips exactly when the notice reaches the user. A connector uses
 * EITHER the commit-at-scan path (rollout, `commitNotice: true`) OR this
 * commit-at-delivery path — never both, so a notice is committed exactly once.
 *
 * Idempotent and safe to call on every turn: once a notice is shown it is
 * skipped, so steady-state turns return `[]` and write nothing.
 */
export async function takePendingNotices(args: {
	sageDirPath?: string;
	configPath?: string;
	logger?: Logger;
}): Promise<string[]> {
	const logger = args.logger ?? nullLogger;
	try {
		const state = await loadInstallState(args.sageDirPath, logger);

		const toShow: string[] = [];
		for (const notice of Object.values(NOTICES)) {
			if (state.notices[notice.id]?.noticed === true) continue;
			const eligible = notice.isEligible
				? await notice.isEligible({ configPath: args.configPath, logger })
				: true;
			if (eligible) toShow.push(notice.id);
		}
		if (toShow.length === 0) return [];

		const nextNotices = { ...state.notices };
		for (const id of toShow) nextNotices[id] = { noticed: true };
		await saveInstallState({ ...state, notices: nextNotices }, args.sageDirPath, logger);
		logger.debug("Pending notices taken for delivery", { noticeIds: toShow });
		return toShow;
	} catch (e) {
		// Fail-open toward not showing: defer to a later turn rather than risk a
		// broken render, and never let this crash the hook.
		logger.warn("takePendingNotices failed; showing no notices this turn", {
			error: String(e),
		});
		return [];
	}
}
