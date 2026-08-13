// Local dry-run of the Layer 2 `latest`-mode routing (see e2e/README.md).
// run.sh calls this after a `latest`-mode suite with the three observable signals; it
// prints the action the weekly CI job WOULD take (open a bump PR, a review PR, or raise
// an alarm) and writes the same decision as a machine-readable artifact for CI to act on.
// The brain (classifyDrift) stays verifiable locally; the CI actuator consumes the
// artifact (no PR/alarm here — just the decision + the file).
//
// Usage: node e2e/route.mjs <agent> <pinned> <resolved> <green:true|false> <shaped:true|false> [buildFailed:true|false]
// buildFailed defaults to false; when true (the image build failed before the suite ran) it
// short-circuits to a build-alarm regardless of the green/shaped signals.
//
// Imports the built core dist directly (the `@gendigital/sage-core` workspace package
// isn't resolvable from e2e/, which is outside the package graph). run.sh guarantees the
// dist exists in `latest` mode via build_sage before any routing — including the
// build-alarm path, where the suite (and its globalSetup build) never ran.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
// pathToFileURL: import() needs a file:// URL, not a bare path — a Windows `C:\…` specifier
// otherwise throws ERR_UNSUPPORTED_ESM_URL_SCHEME in local `latest` dry-runs.
const { classifyDrift } = await import(
	pathToFileURL(join(HERE, "../packages/core/dist/e2e-testing.js")).href
);

const [, , agent, pinned, resolved, green, shaped, buildFailed] = process.argv;
// Parse the signals once; the same values feed both the decision and the artifact, so the
// CI actuator never has to re-derive anything from stdout.
const inputs = {
	pinned,
	resolved,
	suiteGreen: green === "true",
	shapeChanged: shaped === "true",
	buildFailed: buildFailed === "true",
};
const { action, reason } = classifyDrift(inputs);

// Machine-readable decision: e2e/output/routing/<agent>.json (gitignored, like all of
// output/). The weekly CI job reads these six files to open a bump/review PR or to redden
// the build on an alarm — see the routing actuator in the CI config. The stdout line below
// is the human/local-dry-run view and is intentionally kept identical.
const routingDir = join(HERE, "output", "routing");
mkdirSync(routingDir, { recursive: true });
writeFileSync(
	join(routingDir, `${agent}.json`),
	`${JSON.stringify({ agent, ...inputs, action, reason }, null, 2)}\n`,
);

process.stdout.write(`>> [latest] ${agent}: ${action} — ${reason}\n`);
