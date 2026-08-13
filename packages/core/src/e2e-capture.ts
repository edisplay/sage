/**
 * E2E hook-payload capture sink (Layer 2 drift loop — see e2e/README.md).
 *
 * A Sage connector is the only process that sees the raw hook payload a host
 * sends (the host-side E2E test only sees the agent's stdout, which never carries
 * it). To re-validate the committed Layer 1 fixtures against the real host, the
 * containerized live-E2E run captures each payload here and the host test diffs
 * it against the committed contract fixtures.
 *
 * This lives in core so every connector can reuse one implementation: the Claude
 * Code MCP server, the Cursor/VS Code/Copilot CJS hook, etc.
 *
 * It is INERT in production: it does nothing unless `SAGE_E2E_CAPTURE_DIR` is set,
 * which only happens inside the E2E container (compose sets it to a bind-mounted
 * directory the host reads back). It is fail-open — a capture error must never
 * affect a hook verdict.
 */

import { join } from "node:path";
import { appendJsonlEntry } from "./jsonl-log-writer.js";

export type HookCaptureEvent = "PreToolUse" | "PostToolUse";

export interface CaptureOptions {
	/**
	 * Namespacing prefix for the capture file name (e.g. `"vscode-"`), so several
	 * connectors sharing one `SAGE_E2E_CAPTURE_DIR` never collide. Defaults to no
	 * prefix — Claude Code keeps `pre-tool-use.jsonl` / `post-tool-use.jsonl`.
	 */
	filePrefix?: string;
}

// Generous caps: captures are tiny and the host reads the file back, so we never
// want rotation to move the line we just wrote out from under the reader.
const CAPTURE_MAX_BYTES = 10 * 1024 * 1024;
const CAPTURE_MAX_FILES = 2;

/**
 * Whether capture is active. Lets the hot-path caller skip `await`ing the no-op
 * in production (capture is off → no microtask). Read live (not cached) so tests
 * can toggle `SAGE_E2E_CAPTURE_DIR` per case.
 */
export function captureEnabled(): boolean {
	return !!process.env.SAGE_E2E_CAPTURE_DIR;
}

/**
 * Append the raw wire payload and its normalized form to the per-event capture
 * file. `raw` is recorded for forensics (and to catch wire-format drift that
 * normalization happens to absorb); `normalized` is the apples-to-apples
 * comparand for the committed (normalized) fixture.
 *
 * No-ops unless `SAGE_E2E_CAPTURE_DIR` is set. Never throws.
 */
export async function captureHookInput(
	event: HookCaptureEvent,
	raw: unknown,
	normalized: unknown,
	options: CaptureOptions = {},
): Promise<void> {
	const dir = process.env.SAGE_E2E_CAPTURE_DIR;
	if (!dir) return;

	try {
		const prefix = options.filePrefix ?? "";
		const base = event === "PreToolUse" ? "pre-tool-use.jsonl" : "post-tool-use.jsonl";
		await appendJsonlEntry(
			{
				path: join(dir, `${prefix}${base}`),
				max_bytes: CAPTURE_MAX_BYTES,
				max_files: CAPTURE_MAX_FILES,
			},
			{ event, raw, normalized },
		);
	} catch {
		// Fail-open: the capture sink is observability only and must never break a hook.
	}
}
