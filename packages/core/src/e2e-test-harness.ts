/**
 * Shared Layer 2 E2E harness scaffolding (see e2e/README.md).
 *
 * Every connector's containerized E2E suite needs the same container seam: the
 * `SAGE_E2E_RUNNER`/`SAGE_E2E_MODE` env switches, the `e2e/` output paths, and —
 * for gateway-style connectors — a docker-compose lifecycle (`up -d` → poll
 * `/health` → `down`). Those were copy-pasted into each suite; this centralizes
 * them so a new connector inherits the harness instead of re-deriving it.
 *
 * Also provides the native-mode seam (`SAGE_E2E_RUNNER=native`): spawn an
 * already-installed CLI binary directly, no Docker, against an isolated temp HOME
 * (`createNativeHome`/`resolveNativeAuditPath`) reusing the developer's own ambient
 * CLI auth. See e2e/README.md's "Run natively" section.
 *
 * Pair with `e2e-envelope-diff.ts` (the drift loop); both are re-exported from the
 * `@gendigital/sage-core/testing` subpath. Node built-ins + `fetch` only — no test
 * framework, so the `expect()` assertions stay in each suite (same rule as
 * `runDriftCheck`: this returns data/handles, the suite asserts).
 */

import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

/** True when the suite drives the agent inside a container (`e2e/run.sh`). */
export const IS_CONTAINER = process.env.SAGE_E2E_RUNNER === "container";

/** True when the suite drives an already-installed agent binary directly (no Docker). */
export const IS_NATIVE = process.env.SAGE_E2E_RUNNER === "native";

/** Drift-diff mode: `pinned` only fails on drift; `latest` also writes a candidate. */
export const E2E_MODE: "pinned" | "latest" =
	process.env.SAGE_E2E_MODE === "latest" ? "latest" : "pinned";

/**
 * Tool-call retry budget. Vertex-hosted models aren't perfectly reliable at emitting
 * a tool call for a given prompt, so container suites retry until the expected tool
 * appears (the "model-didn't-invoke = inconclusive FAIL" rule). Only the
 * container suites consume this, and they're skipped outside a container — so it's a
 * flat constant, not gated on IS_CONTAINER.
 */
export const CONTAINER_TOOL_ATTEMPTS = 4;

/** The shared `e2e/` paths a suite needs, derived from the repo root it computes. */
export interface E2EPaths {
	/** `e2e/compose.yml` — the docker compose file driving the containers. */
	composeFile: string;
	/** `e2e/output/capture` — the bind-mounted sink agents write hook captures to. */
	captureDir: string;
	/** `e2e/output/proposed` — where a `latest`-mode regenerated fixture is written. */
	proposedDir: string;
}

/**
 * Resolve the shared `e2e/` paths from a suite's repo root. Each suite computes its
 * own `repoRoot` (the derivation differs by module system — CJS `__dirname` vs ESM
 * `import.meta.url`), then passes it here so the `e2e/...` segments live in one place.
 */
export function e2ePaths(repoRoot: string): E2EPaths {
	return {
		composeFile: resolve(repoRoot, "e2e", "compose.yml"),
		captureDir: resolve(repoRoot, "e2e", "output", "capture"),
		proposedDir: resolve(repoRoot, "e2e", "output", "proposed"),
	};
}

/**
 * Resolve the Sage audit-log path for a connector suite. In container mode the agent's
 * HOME `.sage` is bind-mounted under `e2e/output/<…>`, so the host reads the SAME log
 * the in-container Sage wrote (full parity); `containerSegments` are the path under
 * `e2e/output/` (it varies per connector — most are `<x>-home/.sage/audit.jsonl`, but
 * copilot bind-mounts `~/.sage` directly to `copilot-sage/audit.jsonl`). Outside a
 * container the path is the developer's real `~/.sage/audit.jsonl` — no connector suite
 * runs there today; that branch is exercised only by this helper's unit test. Native-mode
 * suites (`IS_NATIVE`) do NOT use this function — they isolate to a temp HOME rather than
 * the real one, so they call `resolveNativeAuditPath` instead.
 */
export function resolveAuditPath(repoRoot: string, ...containerSegments: string[]): string {
	return IS_CONTAINER
		? join(repoRoot, "e2e", "output", ...containerSegments)
		: join(homedir(), ".sage", "audit.jsonl");
}

/**
 * Run a one-shot agent in its compose service: `docker compose -f <file> run --rm -T
 * <service> <args>`. Every container suite built this invocation inline; this is the
 * single builder (the gateway connectors use `createGatewayHarness().compose` for
 * `up`/`down`/`logs` — this covers the `run` case). `-T` disables the TTY so stdout
 * stays clean for stream-JSON parsing. Returns the raw spawn result; the suite parses.
 */
export function composeRun(
	composeFile: string,
	service: string,
	args: string[],
	options: { timeout?: number; input?: string } = {},
): SpawnSyncReturns<string> {
	return spawnSync(
		"docker",
		["compose", "-f", composeFile, "run", "--rm", "-T", service, ...args],
		{
			encoding: "utf8",
			timeout: options.timeout ?? 240_000,
			// SIGKILL instead of the default SIGTERM: docker compose politely waits for the
			// container to stop on SIGTERM, but the container may be blocked in a Vertex AI
			// HTTP call and never exit — causing spawnSync to block indefinitely past its
			// timeout budget until TC kills the whole build. SIGKILL forces docker compose to
			// exit immediately; Docker GC cleans up the orphaned container.
			killSignal: "SIGKILL",
			maxBuffer: 10 * 1024 * 1024,
			windowsHide: true,
			// spawnSync ignores `input: undefined`; an empty string closes stdin (opencode).
			input: options.input,
		},
	);
}

/**
 * `rmSync({ recursive, force })` that also swallows `EPERM`. Container bind-mounts can
 * leave root-owned files (the agent runs as root, the host cleanup runs as the dev),
 * which `force` alone does not tolerate; a failed cleanup of stale state must never
 * fail the suite.
 */
export function tolerantRm(target: string): void {
	try {
		rmSync(target, { recursive: true, force: true });
	} catch {
		// Best-effort: root-owned container leftovers, already gone, etc.
	}
}

// --- Native-mode helpers (SAGE_E2E_RUNNER=native) ---
// Spawn an already-installed CLI binary directly, no Docker. Headless CLIs (claude,
// opencode, cursor-agent, copilot) self-register on PATH via their installers (npm-global
// install, curl-script install), so unlike the GUI editor resolver in the extension
// package (which has to guess LOCALAPPDATA/ProgramFiles install locations for Cursor.app /
// Code.exe), resolution here is just an env override or a bare command name.

/** A resolved executable path, or the reason none of the candidates were runnable. */
export interface ResolvedExecutable {
	executablePath?: string;
	reason?: string;
}

/**
 * Resolve a locally-installed CLI binary for native-mode E2E: env override(s) first
 * (checked in order), then the bare command names in `defaultCandidates`.
 */
export function resolveExecutable(
	envNames: string[],
	defaultCandidates: string[],
): ResolvedExecutable {
	const envCandidates = envNames
		.map((name) => process.env[name]?.trim())
		.filter((v): v is string => Boolean(v));
	const candidates = [...new Set([...envCandidates, ...defaultCandidates])];

	for (const candidate of candidates) {
		if (canExecute(candidate)) {
			return { executablePath: candidate };
		}
	}

	const reason =
		envCandidates.length > 0
			? `none of the configured executables were runnable: ${envCandidates.join(", ")}`
			: `not found in PATH (tried: ${defaultCandidates.join(", ")})`;
	return { reason };
}

/** True if `executablePath --version` runs successfully (native-mode existence probe). */
export function canExecute(executablePath: string): boolean {
	const result = spawnNative(executablePath, ["--version"], process.env, { timeout: 20_000 });
	return !result.error && result.status === 0;
}

/** Re-serialize a value for safe inclusion in a `cmd.exe /c` command line. */
function quoteForCmd(value: string): string {
	if (!value.includes(" ") && !value.includes('"') && !value.includes("\t")) {
		return value;
	}
	return `"${value.replace(/"/g, '""')}"`;
}

/** Re-serialize `command` + `args` into one `cmd.exe /c` command line string. */
function buildCmdInvocation(command: string, args: string[]): string {
	const cmd = quoteForCmd(command);
	const argv = args.map((arg) => quoteForCmd(arg)).join(" ");
	return argv ? `${cmd} ${argv}` : cmd;
}

/**
 * Spawn a locally-installed CLI binary for native-mode E2E. On Windows, `shell: true`
 * lets `cmd.exe` resolve a bare command name to whatever its installer produced (`.exe`,
 * `.cmd`, `.bat` — npm-global installs are `.cmd` shims); this is the same
 * CVE-2024-27980-aware pattern already used in `clients/pi-deps-installer.ts` (spawning a
 * `.cmd`/`.bat` without `shell: true` throws `EINVAL` before the process starts, on Node
 * 18.20.2+/20.12.2+/21.7.3+). If that still fails, retry by re-issuing the exact command
 * line through `cmd.exe /d /s /c` directly — some shims aren't reliably resolved by
 * `shell: true` alone (this fallback is adapted from the pre-container-refactor cursor
 * headless E2E code, `buildCmdInvocation`/`quoteForCmd` above).
 */
export function spawnNative(
	bin: string,
	args: string[],
	env: NodeJS.ProcessEnv,
	options: { timeout?: number; input?: string; cwd?: string } = {},
): SpawnSyncReturns<string> {
	const isWindows = process.platform === "win32";
	const baseOptions = {
		encoding: "utf8" as const,
		timeout: options.timeout ?? 240_000,
		maxBuffer: 10 * 1024 * 1024,
		windowsHide: true,
		cwd: options.cwd,
		env,
	};
	const direct = spawnSync(bin, args, { ...baseOptions, shell: isWindows, input: options.input });
	if (!direct.error || !isWindows) {
		return direct;
	}
	return spawnSync("cmd.exe", ["/d", "/s", "/c", buildCmdInvocation(bin, args)], {
		...baseOptions,
		input: options.input,
	});
}

/** An isolated, per-run HOME for native-mode E2E — never the developer's real HOME. */
export interface NativeHome {
	/** Absolute path to the isolated temp directory. */
	path: string;
	/** Remove the temp directory (tolerant of already-gone/permission errors). */
	cleanup(): void;
}

/** Create an isolated temp HOME for a native-mode connector run. */
export function createNativeHome(prefix: string): NativeHome {
	const homePath = mkdtempSync(join(tmpdir(), `sage-e2e-${prefix}-`));
	return { path: homePath, cleanup: () => tolerantRm(homePath) };
}

/**
 * Resolve the Sage audit-log path for a native-mode connector run, given the isolated
 * temp HOME from `createNativeHome`. A sibling to `resolveAuditPath`, not an overload —
 * that function's contract (bind-mount segments under repoRoot, or the real `homedir()`)
 * doesn't fit an isolated native-mode HOME.
 */
export function resolveNativeAuditPath(nativeHome: string): string {
	return join(nativeHome, ".sage", "audit.jsonl");
}

export interface GatewayHarnessOptions {
	/** Path to `e2e/compose.yml`. */
	composeFile: string;
	/** Base URL the gateway is published at, e.g. `http://localhost:18889`. */
	host: string;
	/** Bearer token guarding the gateway (sent on the health poll). */
	token: string;
	/** Compose service name, used for `compose logs` on a health-poll timeout. */
	service: string;
}

export interface GatewayHarness {
	/** Run `docker compose -f <composeFile> <args>` with suite-tuned spawn options. */
	compose(args: string[]): SpawnSyncReturns<string>;
	/** Poll `GET <host>/health` until the gateway reports live, or throw with logs. */
	waitForHealth(timeoutMs: number): Promise<void>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Lifecycle helpers for a gateway-style connector driven over HTTP (OpenClaw today;
 * extracted ahead of the next gateway agent). The suite owns `up -d` / `down`; this
 * just provides the `compose` runner and a `/health` poll that surfaces container
 * logs on timeout.
 */
export function createGatewayHarness(opts: GatewayHarnessOptions): GatewayHarness {
	const { composeFile, host, token, service } = opts;

	function compose(args: string[]): SpawnSyncReturns<string> {
		return spawnSync("docker", ["compose", "-f", composeFile, ...args], {
			encoding: "utf8",
			timeout: 300_000,
			killSignal: "SIGKILL",
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
			maxBuffer: 10 * 1024 * 1024,
		});
	}

	async function waitForHealth(timeoutMs: number): Promise<void> {
		const deadline = Date.now() + timeoutMs;
		let lastErr = "";
		while (Date.now() < deadline) {
			try {
				const res = await fetch(`${host}/health`, {
					headers: { Authorization: `Bearer ${token}` },
				});
				if (res.ok) {
					const body = (await res.json()) as { ok?: boolean };
					if (body.ok) return;
				}
				lastErr = `status ${res.status}`;
			} catch (e) {
				lastErr = String(e);
			}
			await sleep(2000);
		}
		const logs = compose(["logs", "--no-color", "--tail", "80", service]).stdout ?? "";
		throw new Error(
			`${service} gateway did not become healthy within ${timeoutMs}ms (last: ${lastErr}).\n${logs}`,
		);
	}

	return { compose, waitForHealth };
}
