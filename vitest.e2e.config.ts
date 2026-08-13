import { defineConfig } from "vitest/config";

// JUnit output is driven from the config via an env var (set by e2e/run.sh), NOT CLI flags:
// passing `--reporter=junit` through `pnpm <script>` is unsafe in both forms — with a `--`
// separator the flag leaks into vitest, which stops option parsing at `--` and silently drops
// it; without `--`, pnpm itself can consume `--reporter` as its own global flag. The env var
// sidesteps both. run.sh's tests_ran guard relies on this file actually being written.
const junitFile = process.env.SAGE_E2E_JUNIT;

export default defineConfig({
	test: {
		globalSetup: ["./scripts/vitest-global-setup.mjs"],
		silent: "passed-only", // only print console.log output if test fails
		retry: 2,
		reporters: junitFile ? ["default", "junit"] : ["default"],
		outputFile: junitFile ? { junit: junitFile } : undefined,
		include: [
			"packages/claude-code/src/__tests__/e2e.test.ts",
			"packages/openclaw/src/__tests__/e2e.test.ts",
			"packages/opencode/src/__tests__/e2e.test.ts",
			"packages/extension/src/__tests__/e2e.test.ts",
			"packages/extension/src/__tests__/e2e-copilot-cli.test.ts",
		],
	},
});
