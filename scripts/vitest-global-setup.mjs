import { buildE2E } from "./build-e2e.mjs";

export function setup() {
	// e2e/run.sh builds standalone (outside the vitest process tree, which a local EDR kills)
	// and sets SAGE_E2E_SKIP_BUILD=1; honor it so the build runs exactly once. Default (no flag)
	// keeps the build-then-run-in-one-process behaviour for `pnpm test:e2e:*` and CI.
	if (process.env.SAGE_E2E_SKIP_BUILD === "1") return;
	buildE2E();
}
