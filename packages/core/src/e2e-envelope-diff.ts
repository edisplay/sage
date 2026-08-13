/**
 * Structural envelope diffing for the Layer 2 E2E drift loop (see e2e/README.md).
 *
 * The live run captures the real host hook payload (via the capture sink in
 * e2e-capture.ts) and diffs its *shape* — top-level key set + value types — against
 * the committed Layer 1 fixture. It is deliberately NOT a value diff: tool_input
 * contents are model-driven and would flake. A missing/renamed key or a type
 * mismatch is real host drift (fail); a brand-new key is a field to triage (warn).
 *
 * Shared across connector test suites (Claude Code, Copilot/VS Code, …) so the
 * diff logic — and the drift-loop orchestration around it (`runDriftCheck`) — is
 * defined exactly once. Node-fs only, no third-party deps.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/** One capture record written by `captureHookInput`. */
export interface CaptureRecord {
	event: string;
	raw: Record<string, unknown>;
	normalized: Record<string, unknown>;
}

export interface EnvelopeDiffOptions {
	/**
	 * Source-key → canonical-key remapping applied before comparison, so fields
	 * that occupy the same host "slot" fold together. Claude Code, for example,
	 * normalizes a plain-string `tool_response` to `tool_output`; both are the one
	 * response slot, so it passes `{ tool_output: "tool_response" }`.
	 */
	foldKeys?: Record<string, string>;
	/**
	 * Keys whose *type* is not compared (presence only). Use for slots whose type
	 * is legitimately tool-dependent (e.g. a response that's a string for one tool
	 * and an object for another).
	 */
	presenceOnlyKeys?: readonly string[];
}

export interface EnvelopeDiff {
	missing: string[];
	extra: string[];
	typeMismatch: string[];
}

/** Coarse runtime type tag used for envelope comparison. */
export function valueType(value: unknown): string {
	if (Array.isArray(value)) return "array";
	if (value === null) return "null";
	return typeof value;
}

/** Top-level key → value type, with any `foldKeys` remapping applied. */
export function envelopeShape(
	payload: Record<string, unknown>,
	options: EnvelopeDiffOptions = {},
): Map<string, string> {
	const fold = options.foldKeys ?? {};
	const shape = new Map<string, string>();
	for (const [key, value] of Object.entries(payload)) {
		shape.set(fold[key] ?? key, valueType(value));
	}
	return shape;
}

/**
 * Structural envelope diff. `missing`/`typeMismatch` are real host drift; `extra`
 * is a new host field to triage. Keys listed in `presenceOnlyKeys` are checked for
 * presence but not type.
 */
export function diffEnvelope(
	captured: Record<string, unknown>,
	fixture: Record<string, unknown>,
	options: EnvelopeDiffOptions = {},
): EnvelopeDiff {
	const presenceOnly = new Set(options.presenceOnlyKeys ?? []);
	const cShape = envelopeShape(captured, options);
	const fShape = envelopeShape(fixture, options);
	const missing = [...fShape.keys()].filter((k) => !cShape.has(k));
	const extra = [...cShape.keys()].filter((k) => !fShape.has(k));
	const typeMismatch = [...fShape.entries()]
		.filter(([k, t]) => !presenceOnly.has(k) && cShape.has(k) && cShape.get(k) !== t)
		.map(([k, t]) => `${k} (fixture=${t}, captured=${cShape.get(k)})`);
	return { missing, extra, typeMismatch };
}

/** True if the diff found any real drift (missing key or type mismatch). */
export function hasEnvelopeDrift(diff: EnvelopeDiff): boolean {
	return diff.missing.length > 0 || diff.typeMismatch.length > 0;
}

/**
 * Build a fixture-update candidate from a live capture: keep the captured shape
 * but reset the host-volatile fields (session/transcript ids, timing, …) to the
 * committed fixture's placeholder values, so a human reviewing the proposal sees
 * only the genuine structural change.
 */
export function buildProposedFixture(
	captured: Record<string, unknown>,
	fixture: Record<string, unknown>,
	volatileFields: readonly string[],
): Record<string, unknown> {
	const proposed = { ...captured };
	for (const field of volatileFields) {
		if (field in proposed && field in fixture) {
			proposed[field] = fixture[field];
		}
	}
	return proposed;
}

/**
 * Read the last capture record in a JSONL capture file that satisfies `match`,
 * or null if the file is absent or has no matching record. Last-wins so a fresh
 * drive's record supersedes any stale ones. Torn/partial lines are skipped.
 */
export function readLastCaptureRecord(
	filePath: string,
	match: (record: CaptureRecord) => boolean,
): CaptureRecord | null {
	let text: string;
	try {
		text = readFileSync(filePath, "utf-8");
	} catch {
		return null; // no capture file produced
	}
	let last: CaptureRecord | null = null;
	for (const line of text.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const record = JSON.parse(trimmed) as CaptureRecord;
			if (match(record)) last = record;
		} catch {
			// skip a torn/partial line (e.g. a concurrent writer)
		}
	}
	return last;
}

export interface RunDriftCheckOptions {
	/** The captured payload to diff — the raw wire form, or the normalized form. */
	captured: Record<string, unknown>;
	/** Path to the committed Layer 1 fixture JSON. */
	fixturePath: string;
	/** Human label for warnings, e.g. "PostToolUse" or "OpenCode tool call". */
	label: string;
	/** `pinned` only fails on drift; `latest` also writes a regenerated candidate. */
	mode: "pinned" | "latest";
	/** Host-volatile fields reset to the fixture's placeholders in the candidate. */
	volatileFields: readonly string[];
	/** Where a `latest`-mode candidate is written (parent dirs created as needed). */
	proposedPath: string;
	/** Connector-specific key folding / presence-only handling for the diff. */
	diffOptions?: EnvelopeDiffOptions;
	/** Sink for triage/candidate notices; defaults to console.warn. */
	log?: (message: string) => void;
}

export interface DriftCheckResult {
	diff: EnvelopeDiff;
	/** True if the diff found real drift (a missing key or a type mismatch). */
	drifted: boolean;
}

/**
 * One envelope's worth of the Layer 2 drift loop, shared across connector suites:
 * load the committed fixture, structurally diff the captured envelope, warn on new
 * host fields (triage), and in `latest` mode write a regenerated fixture candidate.
 * Returns the diff so the caller can assert with a connector-specific message —
 * this keeps the test framework out of core. The caller still owns clearing the
 * capture file, driving the tool, reading the record, and value-pinning fields.
 */
export function runDriftCheck(options: RunDriftCheckOptions): DriftCheckResult {
	const fixture = JSON.parse(readFileSync(options.fixturePath, "utf-8")) as Record<string, unknown>;
	const diff = diffEnvelope(options.captured, fixture, options.diffOptions);
	const warn = options.log ?? console.warn;

	if (diff.extra.length) {
		warn(
			`[drift] ${options.label}: host sent new field(s) not in the fixture (triage): ${diff.extra.sort().join(", ")}`,
		);
	}

	const drifted = hasEnvelopeDrift(diff);
	// In `latest` mode, regenerate the candidate whenever the captured shape differs at
	// all — including additive-only drift (new host fields), which is green (the suite
	// asserts only on `missing`/`typeMismatch`). The candidate is the artifact the
	// review-PR path commits, so the bump can carry a grown fixture even when nothing
	// failed. `drifted` is unchanged so the caller's assertion still gates on real drift.
	const shapeChanged = drifted || diff.extra.length > 0;
	if (shapeChanged && options.mode === "latest") {
		mkdirSync(dirname(options.proposedPath), { recursive: true });
		writeFileSync(
			options.proposedPath,
			`${JSON.stringify(buildProposedFixture(options.captured, fixture, options.volatileFields), null, "\t")}\n`,
		);
		warn(`[drift] wrote regenerated fixture candidate to ${options.proposedPath}`);
	}

	return { diff, drifted };
}

/**
 * `runDriftCheck` plus the assertion every connector suite repeated verbatim: fail on real
 * drift (a missing fixture key or a type mismatch; additive-only drift stays a warning).
 * Throws a plain Error labelled by connector — keeping the test framework out of core, the
 * same rule as `driveForFreshVerdict` — so each suite collapses its ~4-line read-diff-assert
 * tail to one call. Returns the `DriftCheckResult` for callers that want to inspect it.
 */
export function assertNoEnvelopeDrift(options: RunDriftCheckOptions): DriftCheckResult {
	const result = runDriftCheck(options);
	const { missing, typeMismatch } = result.diff;
	if (missing.length > 0 || typeMismatch.length > 0) {
		throw new Error(
			`${options.label} envelope drifted from the committed fixture — ` +
				`missing: [${missing.join(", ")}], typeMismatch: [${typeMismatch.join(", ")}]`,
		);
	}
	return result;
}
