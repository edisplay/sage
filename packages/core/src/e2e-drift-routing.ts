/**
 * Routing for the Layer 2 `latest`-mode drift loop (see e2e/README.md).
 *
 * A weekly job resolves each agent's newest stable version, builds at it, and runs the
 * same suite as the PR gate. This maps the three observable signals — resolved-vs-pinned
 * version, suite green/red, and whether the captured envelope shape changed — onto the
 * action the job should take. Pure and total (no I/O); the actuators (open PR, notify,
 * auto-merge) live in CI and consume the `action`. Locally, `e2e/route.mjs` prints it as
 * a dry-run. Kept framework-free so it sits beside `runDriftCheck` in core/testing.
 */

export type DriftAction =
	| "steady"
	| "infra-alarm"
	| "auto-bump-pr"
	| "review-pr"
	| "drift-alarm"
	| "build-alarm";

export interface DriftRoutingInputs {
	/** The version pinned in `agents.json`. */
	pinned: string;
	/** The newest stable version resolved host-side for this run. */
	resolved: string;
	/** Whether the suite passed (after its own model-retry budget). */
	suiteGreen: boolean;
	/** Whether the captured envelope shape differed from the committed fixture. */
	shapeChanged: boolean;
	/**
	 * The image build failed, so the suite never ran (the agent couldn't be installed at
	 * `resolved`). Distinct from a red suite: nothing was observed about Sage's behaviour,
	 * and the cause is often transient (network, registry-mirror lag, or an install-format
	 * change), so it routes to its own `build-alarm` rather than a drift/infra alarm.
	 */
	buildFailed?: boolean;
}

export interface DriftRouting {
	action: DriftAction;
	reason: string;
}

/** How the resolved version compares to the pinned one. `unknown` = order undeterminable. */
export type VersionDelta = "same" | "newer" | "older" | "unknown";

/** Date-stamped tag prefix (Cursor, e.g. `2026.06.19-…`). Leading-zero segments make this an
 * invalid semver, so it can't collide with an npm/VS Code numeric version. */
const DATE_STAMPED_RE = /^\d{4}\.\d{2}\.\d{2}/;

/**
 * Clean numeric dotted version ("2.1.169") → segments, or null if any segment isn't an integer.
 * Deliberately NOT `isNewerVersion` (version-check.ts): that coerces non-integer segments to 0
 * (so it can never report "unrecognized" — we need the null to fall through to `unknown`) and
 * truncates a date-stamped tag like `2026.06.19-20-…` to `[2026,6,19]` via parseInt, losing the
 * sub-day ordering Cursor needs. The strict null guard here is the genuine new behaviour.
 */
function numericSegments(version: string): number[] | null {
	const parts = version.split(".");
	const nums = parts.map((p) => (/^\d+$/.test(p) ? Number(p) : Number.NaN));
	return nums.some(Number.isNaN) ? null : nums;
}

/**
 * Compare a resolved version against the pinned one WITHOUT a per-channel comparator, by
 * detecting the format: numeric dotted versions (npm — claude/copilot/opencode/openclaw; and
 * VS Code) compare segment-by-segment; date-stamped tags (Cursor, e.g. `2026.06.19-…`)
 * compare lexically, which is chronological. Anything else is `unknown`.
 *
 * The point is to distinguish a forward upgrade from a channel rollback/yank (resolved OLDER
 * than pinned) or mirror lag, so the router never auto-bumps to an older or unorderable
 * version. `unknown` is the fail-safe — the caller treats it as "do not auto-bump".
 *
 * NOTE: format is detected from the string, not `agents.json` channel.type. That's safe for the
 * six current channels (a date-stamped tag is invalid semver, so it can't be a real npm version).
 * It is best-effort by design: a scheme this comparator can't order (e.g. a pre-release tag like
 * `v1.2.3-beta.4`, or any mixed/novel format) falls through to `unknown` → infra-alarm — a safe
 * stop, never an accidental bump. Adding an agent whose channel uses such a scheme therefore
 * requires extending this comparator (and likely passing channel.type explicitly to disambiguate).
 */
export function resolvedDelta(pinned: string, resolved: string): VersionDelta {
	if (pinned === resolved) return "same";
	const np = numericSegments(pinned);
	const nr = numericSegments(resolved);
	if (np && nr) {
		const len = Math.max(np.length, nr.length);
		for (let i = 0; i < len; i++) {
			const a = nr[i] ?? 0;
			const b = np[i] ?? 0;
			if (a !== b) return a > b ? "newer" : "older";
		}
		return "same"; // numerically equal despite differing text (e.g. 1.1 vs 1.1.0)
	}
	if (DATE_STAMPED_RE.test(pinned) && DATE_STAMPED_RE.test(resolved)) {
		return resolved > pinned ? "newer" : "older";
	}
	return "unknown";
}

/**
 * Map a `latest`-mode run's signals onto a routing action. Total over all inputs:
 *
 * | build | resolved vs pinned | suite | shape changed | action       |
 * |-------|--------------------|-------|---------------|--------------|
 * | fail  | —                  | —     | —             | build-alarm  |
 * | ok    | older / unknown    | —     | —             | infra-alarm  |
 * | ok    | same               | green | no            | steady       |
 * | ok    | same               | green | yes           | review-pr    |
 * | ok    | same               | red   | —             | infra-alarm  |
 * | ok    | newer              | green | no            | auto-bump-pr |
 * | ok    | newer              | green | yes           | review-pr    |
 * | ok    | newer              | red   | —             | drift-alarm  |
 *
 * "newer/older/same" is derived from {@link resolvedDelta} (format-aware), not a raw
 * `resolved !== pinned` — so a rollback/yank (resolved older) or an unorderable version is
 * routed to an alarm instead of an accidental downgrade bump. A build failure short-circuits
 * everything (the suite never ran); it is its own alarm because the usual cause is transient
 * (network, mirror lag, install-format change) — rerun before assuming the new version broke Sage.
 */
export function classifyDrift(input: DriftRoutingInputs): DriftRouting {
	const { pinned, resolved, suiteGreen, shapeChanged, buildFailed } = input;
	const delta = resolvedDelta(pinned, resolved);

	if (buildFailed) {
		return {
			action: "build-alarm",
			reason:
				delta === "newer"
					? `build failed at newer ${resolved} (pinned ${pinned}) — could not install/build the agent; likely transient (network, mirror lag, or an install-format change). Rerun before treating as drift.`
					: `build failed at ${resolved} (pinned ${pinned}) — could not install/build the agent; likely network, registry-mirror, or env. Rerun before alarming.`,
		};
	}

	// Never auto-bump to an older version (channel rollback/yank, mirror lag) or one whose
	// order we can't determine — flag it for a human instead.
	if (delta === "older" || delta === "unknown") {
		return {
			action: "infra-alarm",
			reason:
				delta === "older"
					? `resolved ${resolved} is OLDER than pinned ${pinned} — channel rollback/yank or mirror lag; not bumping. Rerun before acting.`
					: `could not order resolved ${resolved} vs pinned ${pinned} (unrecognized version scheme) — not bumping; needs a human.`,
		};
	}

	// delta is "same" or "newer" here — "older"/"unknown" already returned above.
	if (!suiteGreen) {
		return delta === "newer"
			? {
					action: "drift-alarm",
					reason: `suite red at newer ${resolved} (pinned ${pinned}) — real drift; needs a Sage change`,
				}
			: {
					action: "infra-alarm",
					reason: `suite red at pinned ${pinned} with no version change — infra/contract rot`,
				};
	}

	if (delta === "same") {
		return shapeChanged
			? {
					action: "review-pr",
					reason: `green at pinned ${pinned} but the envelope shape grew — refresh the fixture`,
				}
			: { action: "steady", reason: `green at pinned ${pinned}; no version or shape change` };
	}

	return shapeChanged
		? {
				action: "review-pr",
				reason: `green at newer ${resolved} (pinned ${pinned}) with an envelope shape change — regenerate fixture + bump`,
			}
		: {
				action: "auto-bump-pr",
				reason: `green at newer ${resolved} (pinned ${pinned}), no shape change — bump agents.json only`,
			};
}
