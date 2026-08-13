/**
 * Shared Layer 2 E2E helper: scan Sage's JSONL audit log for `runtime_verdict`
 * entries. Used by every connector's live suite to assert a verdict was recorded —
 * the platform-agnostic, mode-agnostic signal (the same audit log is written locally
 * and in-container). Test-only; node built-ins, no test framework (the suites own the
 * `expect()` assertions, same rule as `runDriftCheck`).
 */

import { existsSync, readFileSync } from "node:fs";

/**
 * Count `runtime_verdict` entries matching `decision` (and, if given, whose
 * `tool_input_summary` — which carries the command/url/file_path — contains `marker`).
 * Returns a count so callers can take before/after deltas: a stale entry from a prior
 * run can't mask a model that failed to invoke the tool this run. Omit `marker` to
 * match any summary. Missing file → 0; malformed lines are ignored.
 */
export function countSageVerdict(auditPath: string, decision: string, marker?: string): number {
	if (!existsSync(auditPath)) return 0;
	const markerLc = marker?.toLowerCase();
	let count = 0;
	for (const line of readFileSync(auditPath, "utf8").split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const entry = JSON.parse(trimmed) as Record<string, unknown>;
			if (entry.type !== "runtime_verdict") continue;
			if (entry.verdict !== decision) continue;
			if (markerLc) {
				const summary = String(entry.tool_input_summary ?? "").toLowerCase();
				if (!summary.includes(markerLc)) continue;
			}
			count++;
		} catch {
			// Ignore malformed lines.
		}
	}
	return count;
}

/** Options for {@link driveForFreshVerdict}. */
export interface FreshVerdictOptions<T> {
	/** Path to the Sage audit log (`audit.jsonl`). */
	auditPath: string;
	/** The verdict decision to wait for, e.g. `"deny"`. */
	decision: string;
	/** Substring that must appear in the entry's `tool_input_summary` (the canary marker). */
	marker: string;
	/** Max attempts before giving up (e.g. `CONTAINER_TOOL_ATTEMPTS`). */
	attempts: number;
	/** Invoked once per attempt to drive the agent; its return is surfaced as `last`. */
	drive: () => T | Promise<T>;
}

/**
 * Drive the agent up to `attempts` times, returning as soon as a FRESH matching
 * verdict appears (a strict increase in `countSageVerdict` over the pre-drive count,
 * so a stale entry from a prior run can't mask a model that never invoked the tool).
 *
 * Returns `{ fresh, last }` rather than asserting — the test framework stays out of
 * core (same rule as `runDriftCheck`). Callers do the `expect`/`expect.fail` with a
 * connector-specific message and the `last` drive result (e.g. an output tail). This
 * is the shared loop behind each suite's `expectFreshDeny`; "model never invoked the
 * tool" is inconclusive and surfaces as `fresh: false` for the caller to hard-fail.
 */
export async function driveForFreshVerdict<T>(
	opts: FreshVerdictOptions<T>,
): Promise<{ fresh: boolean; last: T | undefined }> {
	const before = countSageVerdict(opts.auditPath, opts.decision, opts.marker);
	let last: T | undefined;
	for (let attempt = 0; attempt < opts.attempts; attempt++) {
		last = await opts.drive();
		if (countSageVerdict(opts.auditPath, opts.decision, opts.marker) > before) {
			return { fresh: true, last };
		}
	}
	return { fresh: false, last };
}
