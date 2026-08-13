import { appendFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { driveForFreshVerdict } from "../e2e-audit-log.js";
import { resolveAuditPath, tolerantRm } from "../e2e-test-harness.js";

// Unit coverage for the shared Layer 2 helpers extracted from the connector E2E suites
// These run in `pnpm test` (no docker/agent) — the spawning helpers
// (`composeRun`, `createGatewayHarness`) are thin wrappers exercised by the live suites.

const TMP = join(import.meta.dirname, `__harness-helpers-${process.pid}`);
afterEach(() => rmSync(TMP, { recursive: true, force: true }));

function writeVerdict(path: string, verdict: string, summary: string): void {
	const line = `${JSON.stringify({ type: "runtime_verdict", verdict, tool_input_summary: summary })}\n`;
	appendFileSync(path, line);
}

describe("driveForFreshVerdict", () => {
	it("returns fresh once a matching verdict appears, after exactly that many drives", async () => {
		mkdirSync(TMP, { recursive: true });
		const auditPath = join(TMP, "audit.jsonl");
		let drives = 0;
		const result = await driveForFreshVerdict({
			auditPath,
			decision: "deny",
			marker: "canary_x",
			attempts: 5,
			drive: () => {
				drives++;
				if (drives === 3) writeVerdict(auditPath, "deny", "ran canary_x now");
				return drives;
			},
		});
		expect(result.fresh).toBe(true);
		expect(result.last).toBe(3);
		expect(drives).toBe(3); // stopped as soon as the fresh deny showed up
	});

	it("returns not-fresh after exhausting attempts when no matching verdict appears", async () => {
		mkdirSync(TMP, { recursive: true });
		const auditPath = join(TMP, "audit.jsonl");
		let drives = 0;
		const result = await driveForFreshVerdict({
			auditPath,
			decision: "deny",
			marker: "canary_x",
			attempts: 4,
			drive: () => {
				drives++;
				return drives;
			},
		});
		expect(result.fresh).toBe(false);
		expect(drives).toBe(4);
	});

	it("ignores a stale pre-existing verdict and a deny for a different marker", async () => {
		mkdirSync(TMP, { recursive: true });
		const auditPath = join(TMP, "audit.jsonl");
		writeVerdict(auditPath, "deny", "old run canary_x"); // stale: present before drives
		const result = await driveForFreshVerdict({
			auditPath,
			decision: "deny",
			marker: "canary_x",
			attempts: 2,
			// Only ever produces a deny for a DIFFERENT marker — must not count as fresh.
			drive: () => writeVerdict(auditPath, "deny", "canary_other"),
		});
		expect(result.fresh).toBe(false);
	});
});

describe("tolerantRm", () => {
	it("removes a directory tree", () => {
		mkdirSync(join(TMP, "nested"), { recursive: true });
		writeFileSync(join(TMP, "nested", "f.txt"), "x");
		tolerantRm(TMP);
		expect(existsSync(TMP)).toBe(false);
	});

	it("does not throw on a missing path", () => {
		expect(() => tolerantRm(join(TMP, "does-not-exist"))).not.toThrow();
	});
});

describe("resolveAuditPath (non-container)", () => {
	// `pnpm test` runs with SAGE_E2E_RUNNER unset → IS_CONTAINER false → the real ~/.sage.
	it("resolves to the home .sage audit log, ignoring container segments", () => {
		expect(resolveAuditPath("/repo", "copilot-sage", "audit.jsonl")).toBe(
			join(homedir(), ".sage", "audit.jsonl"),
		);
	});
});
