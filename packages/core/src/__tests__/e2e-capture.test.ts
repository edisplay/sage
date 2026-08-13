import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { captureHookInput } from "../e2e-capture.js";

describe("captureHookInput (E2E capture sink)", () => {
	let dir: string;
	const savedEnv = process.env.SAGE_E2E_CAPTURE_DIR;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "sage-capture-test-"));
	});

	afterEach(() => {
		if (savedEnv === undefined) delete process.env.SAGE_E2E_CAPTURE_DIR;
		else process.env.SAGE_E2E_CAPTURE_DIR = savedEnv;
		rmSync(dir, { recursive: true, force: true });
	});

	it("writes nothing when SAGE_E2E_CAPTURE_DIR is unset", async () => {
		delete process.env.SAGE_E2E_CAPTURE_DIR;
		await captureHookInput("PreToolUse", { tool_name: "Bash" }, { tool_name: "Bash" });
		expect(existsSync(join(dir, "pre-tool-use.jsonl"))).toBe(false);
	});

	it("appends a JSONL record with event/raw/normalized when enabled", async () => {
		process.env.SAGE_E2E_CAPTURE_DIR = dir;

		await captureHookInput(
			"PreToolUse",
			{ tool_name: "Bash", tool_input: '{"command":"echo hi"}' },
			{ tool_name: "Bash", tool_input: { command: "echo hi" } },
		);

		const file = join(dir, "pre-tool-use.jsonl");
		const lines = readFileSync(file, "utf-8").trim().split("\n");
		expect(lines).toHaveLength(1);
		const record = JSON.parse(lines[0]);
		expect(record).toEqual({
			event: "PreToolUse",
			raw: { tool_name: "Bash", tool_input: '{"command":"echo hi"}' },
			normalized: { tool_name: "Bash", tool_input: { command: "echo hi" } },
		});
	});

	it("routes Pre and Post events to separate files and appends across calls", async () => {
		process.env.SAGE_E2E_CAPTURE_DIR = dir;

		await captureHookInput("PreToolUse", { i: 1 }, { i: 1 });
		await captureHookInput("PreToolUse", { i: 2 }, { i: 2 });
		await captureHookInput("PostToolUse", { i: 3 }, { i: 3 });

		const pre = readFileSync(join(dir, "pre-tool-use.jsonl"), "utf-8").trim().split("\n");
		const post = readFileSync(join(dir, "post-tool-use.jsonl"), "utf-8").trim().split("\n");
		expect(pre).toHaveLength(2);
		expect(post).toHaveLength(1);
		expect(JSON.parse(post[0]).event).toBe("PostToolUse");
	});

	it("namespaces the capture file by filePrefix so connectors don't collide", async () => {
		process.env.SAGE_E2E_CAPTURE_DIR = dir;

		await captureHookInput("PreToolUse", { i: 1 }, { i: 1 }, { filePrefix: "vscode-" });

		expect(existsSync(join(dir, "vscode-pre-tool-use.jsonl"))).toBe(true);
		expect(existsSync(join(dir, "pre-tool-use.jsonl"))).toBe(false);
	});
});
