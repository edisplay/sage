import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Builds current-branch Sage for the E2E suites — the Layer 2 container bind-mounts the
// resulting host dist, so even uncommitted changes run. Shared by two callers:
//   - vitest's globalSetup (the default: build then run, one process)
//   - e2e/run.sh, which invokes this STANDALONE before vitest (outside the vitest process
//     tree) and sets SAGE_E2E_SKIP_BUILD=1 so globalSetup is a no-op. That split is required
//     locally where endpoint security software kills the in-vitest build tree; it is a
//     no-op for CI.
// cwd-independent: every step is anchored at the repo root derived from this file's location.

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSION_DIR = join(REPO_ROOT, "packages", "extension");
const run = (cmd, cwd = REPO_ROOT) => execSync(cmd, { stdio: "inherit", cwd });

export function buildE2E() {
	// Build core first (needed by all other packages)
	run("pnpm --filter @gendigital/sage-core run build");
	// Build shared MCP package (needed by claude-code MCP server bundle)
	run("pnpm --filter @gendigital/sage-mcp run build");
	// Build claude-code and openclaw (no corepack dependency)
	run("pnpm --filter @gendigital/sage-claude-code --filter @gendigital/sage-openclaw run build");
	// Build extension manually (its build script uses corepack which may not be available)
	run("node scripts/sync-assets.mjs", EXTENSION_DIR);
	run("node esbuild.config.cjs", EXTENSION_DIR);
	// Build opencode plugin bundle used by integration tests
	run("pnpm --filter @gendigital/sage-opencode run build");
}

// `node scripts/build-e2e.mjs` runs the build directly (the run.sh standalone path).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	buildE2E();
}
