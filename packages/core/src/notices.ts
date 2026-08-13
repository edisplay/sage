/**
 * One-time informational notices surfaced at session start.
 *
 * This is the single place a notice is defined: its **id** (also the key under
 * `notices` in `install-state.json`) and its **message** live together in one
 * {@link NoticeDefinition}. To add a notice, add one entry here — nothing about
 * a specific feature leaks into the state machine or the formatter.
 *
 * The mechanism that decides *whether* a notice shows (e.g. the skill-upload
 * consent rollout in `install-state.ts`) is intentionally separate from *what*
 * it says. `runSessionStart` returns the ids to show; `formatNotice` renders
 * them uniformly as `ℹ️  <brand>: …`.
 */

import { defaultBranding } from "./brands.js";
import { readExplicitSkillUploadEnabled } from "./config.js";
import type { Branding, Logger } from "./types.js";

/** Context a notice's eligibility predicate may consult (all optional). */
export interface NoticeEligibilityContext {
	configPath?: string;
	logger?: Logger;
}

export interface NoticeDefinition {
	id: string;
	body: (branding: Branding) => string[];
	/**
	 * Whether this notice currently applies to the install. Absent → always
	 * eligible. Lets a notice self-describe its precondition (e.g. "only if the
	 * user hasn't explicitly opted out already") so the generic delivery path
	 * (`takePendingNotices`) needs no per-notice knowledge.
	 */
	isEligible?: (ctx: NoticeEligibilityContext) => boolean | Promise<boolean>;
}

/** Consent notice for the skill-content upload rollout. */
export const SKILL_UPLOAD_NOTICE: NoticeDefinition = {
	id: "skill_upload_v1",
	body: () => [
		"unknown skills — each skill's SKILL.md and every supporting file in its",
		"folder — will be uploaded and checked against potential malicious artifacts",
		"starting next session. To keep skill content on this machine, set",
		'"skill_check": { "upload_enabled": false } in ~/.sage/config.json.',
	],
	// Suppressed once the user has explicitly set upload_enabled either way: an
	// explicit choice needs no consent prompt (the rollout obeys it directly).
	isEligible: async ({ configPath, logger }) =>
		!(await readExplicitSkillUploadEnabled(configPath, logger)).present,
};

/** Every known notice, keyed by id. New notices are added here. */
export const NOTICES: Record<string, NoticeDefinition> = {
	[SKILL_UPLOAD_NOTICE.id]: SKILL_UPLOAD_NOTICE,
};

const INFO_ICON = "ℹ️";
/** Indent for continuation lines, aligning under the text after "ℹ️  <brand>: ". */
const CONTINUATION_INDENT = "   ";

/**
 * Render a notice as `ℹ️  <brand>: <first line>` followed by indented
 * continuation lines. The one place the notice visual shape is defined.
 */
export function formatNotice(
	notice: NoticeDefinition,
	branding: Branding = defaultBranding,
): string {
	const [first = "", ...rest] = notice.body(branding);
	const head = `${INFO_ICON}  ${branding.name}: ${first}`;
	return [head, ...rest.map((line) => `${CONTINUATION_INDENT}${line}`)].join("\n");
}

/** Render a notice by id, or an empty string if the id is unknown. */
export function formatNoticeById(id: string, branding: Branding = defaultBranding): string {
	const notice = NOTICES[id];
	return notice ? formatNotice(notice, branding) : "";
}
