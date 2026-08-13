import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CANARY_MARKER_PATTERN, CANARY_MARKERS } from "../e2e-canary-markers.js";

// Guard against a silent coverage hole: the E2E/integration suites drive Sage with opaque
// canary markers (`diagmark_*` / `diaghost-*`) that must match a rule in threats/dummy.yaml.
// A single typo in a prompt would make the canary never match, so the deny/ask test would
// pass for the wrong reason (model refused / nothing fired) with no signal. Two guards:
//   1. every value in the CANARY_MARKERS const (the TS-side source the suites import) exists
//      in dummy.yaml — keeps the const and the detection data from diverging;
//   2. every marker LITERAL still present in test code exists too — catches the few that can't
//      use the const (e.g. the runtime CJS suite e2e-suite/index.js) and any stray re-introduced
//      literal. (Benign drift probes use different prefixes — `opencode_drift_probe_*`,
//      `sage-*-contract` — so they don't match the canary regex and aren't required to exist.)

const REPO_ROOT = join(import.meta.dirname, "..", "..", "..", "..");
const DUMMY_YAML = readFileSync(join(REPO_ROOT, "threats", "dummy.yaml"), "utf8");
// Built fresh from the shared source pattern (the `g` flag is stateful, so don't share a RegExp).
const MARKER_RE = new RegExp(CANARY_MARKER_PATTERN, "g");

const SELF = "e2e-canary-markers.test.ts";

function collectTestFiles(dir: string): string[] {
	let entries: ReturnType<typeof readdirSync>;
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
	const out: string[] = [];
	for (const entry of entries) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...collectTestFiles(full));
		// `.js` is intentional: `e2e-suite/index.js` is hand-written test SOURCE (not a build
		// output — those go to dist/) and references canary markers directly.
		else if (entry.name !== SELF && /\.(test\.ts|js)$/.test(entry.name)) out.push(full);
	}
	return out;
}

describe("canary marker registry", () => {
	it("every CANARY_MARKERS const value exists in threats/dummy.yaml", () => {
		const missing = Object.entries(CANARY_MARKERS)
			.filter(([, marker]) => !DUMMY_YAML.includes(marker))
			.map(([name, marker]) => `${name}=${marker}`);
		expect(
			missing,
			`CANARY_MARKERS entries absent from threats/dummy.yaml (typo or missing rule): ${missing.join(", ")}`,
		).toEqual([]);
	});

	it("every canary marker referenced in tests exists in threats/dummy.yaml", () => {
		const packagesDir = join(REPO_ROOT, "packages");
		const files = readdirSync(packagesDir).flatMap((pkg) =>
			collectTestFiles(join(packagesDir, pkg, "src", "__tests__")),
		);

		const referenced = new Set<string>();
		for (const file of files) {
			for (const match of readFileSync(file, "utf8").matchAll(MARKER_RE)) {
				referenced.add(match[0]);
			}
		}

		// Sanity: the scan found the suites' markers (guards against the regex/paths silently
		// matching nothing, which would make this test vacuously pass).
		expect(
			referenced.size,
			"expected to find canary markers referenced in the test suite",
		).toBeGreaterThan(0);

		// dummy.yaml stores markers in `pattern:` values (URL/domain rules append `\.test`), so a
		// substring check covers both the bare command/file markers and the URL hosts.
		const missing = [...referenced].filter((marker) => !DUMMY_YAML.includes(marker)).sort();
		expect(
			missing,
			`canary markers used in tests but absent from threats/dummy.yaml (typo or missing rule): ${missing.join(", ")}`,
		).toEqual([]);
	});
});
