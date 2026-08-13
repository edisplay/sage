/**
 * HTTP client for uploading an unknown skill to the Skill Analyzer for
 * analysis. Unlike `skill-check.ts` (which only looks skills up by
 * content-addressed id), this uploads the actual skill content as a ZIP and
 * blocks for the full verdict.
 *
 * LEGAL NOTICE: The Avast/Gen backend is provided exclusively for use within
 * the Sage project. See `clients/url-check.ts` for the full notice.
 */

import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { resolveEndpoint } from "./url-check.js";

// The proxy streams the multipart upload to the analyzer, injects the upstream
// credentials, and enforces a 330s read timeout. Allow a little more than the
// proxy's read timeout before giving up client-side so the proxy has a chance to
// return its own timeout response.
const DEFAULT_TIMEOUT_SECONDS = 340;

export type SkillAnalyzeVerdict =
	| "CRITICAL"
	| "HIGH"
	| "MEDIUM"
	| "LOW"
	| "SAFE"
	| "SKIPPED"
	| "ERROR"
	| string;

/** Parsed subset of the Skill Analyzer V2 `/analyze` response. */
export interface SkillAnalyzeResult {
	jobId?: string;
	verdict?: SkillAnalyzeVerdict;
	summary?: string;
}

/** Caller metadata sent to the analyzer as `skill_metadata`. */
export interface SkillAnalyzeMetadata {
	/** Skill slug / display name. */
	slug?: string;
	/** Content-addressed skill id — used only as the ZIP filename. */
	skillId?: string;
}

export interface SkillAnalyzeClientConfig {
	endpoint?: string;
	timeoutSeconds?: number;
	authorization?: string;
}

export class SkillAnalyzeClient {
	private readonly endpoint: string;
	private readonly timeoutMs: number;
	private readonly authorization?: string;
	private readonly logger: Logger;

	constructor(config?: SkillAnalyzeClientConfig, logger: Logger = nullLogger) {
		this.endpoint = config?.endpoint ?? resolveEndpoint("/v2/skill-analyze");
		this.timeoutMs = (config?.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
		this.authorization = config?.authorization;
		this.logger = logger;
	}

	/**
	 * Upload a skill ZIP and block for the verdict.
	 *
	 * Fails-open: returns `null` on any error (network, non-2xx, bad JSON), so a
	 * failed analysis is indistinguishable from "no opinion" to the caller and
	 * never breaks the worker.
	 */
	async analyzeZip(
		zip: Uint8Array,
		metadata: SkillAnalyzeMetadata = {},
	): Promise<SkillAnalyzeResult | null> {
		try {
			const form = new FormData();
			form.append(
				"file",
				new Blob([zip], { type: "application/zip" }),
				`${metadata.skillId || "skill"}.zip`,
			);
			form.append("delivery", "BLOCKING");
			form.append(
				"skill_metadata",
				JSON.stringify({ is_private: true, name: metadata.slug, source: "Sage" }),
			);

			const headers: Record<string, string> = { Accept: "application/json" };
			if (this.authorization) headers.Authorization = this.authorization;

			const response = await fetch(this.endpoint, {
				method: "POST",
				headers,
				body: form,
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				let body = "";
				try {
					body = (await response.text()).slice(0, 600);
				} catch {
					// Body not readable — status alone will have to do.
				}
				this.logger.warn(`SkillAnalyze HTTP error: ${response.status}`, { body });
				return null;
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parseResult(data);
		} catch (e) {
			this.logger.warn("SkillAnalyze request failed", { error: String(e) });
			return null;
		}
	}

	private parseResult(raw: Record<string, unknown>): SkillAnalyzeResult {
		return {
			jobId: typeof raw.job_id === "string" ? raw.job_id : undefined,
			verdict: typeof raw.verdict === "string" ? raw.verdict : undefined,
			summary: typeof raw.summary === "string" ? raw.summary : undefined,
		};
	}
}
