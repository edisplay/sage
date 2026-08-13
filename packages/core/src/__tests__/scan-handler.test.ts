import { beforeEach, describe, expect, it, vi } from "vitest";

const { runSessionStart } = vi.hoisted(() => ({ runSessionStart: vi.fn() }));

vi.mock("../session-start.js", () => ({ runSessionStart }));

import { createScanHandler, runPluginScan } from "../scan-handler.js";
import type { Logger, PluginScanResult } from "../types.js";

const logger: Logger = {
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
};

const sampleThreatResult: PluginScanResult = {
	plugin: {
		key: "evil-plugin@1.0.0",
		installPath: "/tmp/evil",
		version: "1.0.0",
		lastUpdated: "2026-01-01T00:00:00Z",
	},
	findings: [
		{
			threatId: "CLT-CMD-001",
			title: "Malicious command",
			severity: "critical",
			artifact: "rm -rf /",
			sourceFile: "/tmp/evil/index.js",
		},
	],
};

beforeEach(() => {
	runSessionStart.mockReset().mockResolvedValue({ scanResults: [], versionCheck: null });
});

describe("runPluginScan", () => {
	it("threads the trailing agentRuntimeVersion through to runSessionStart", async () => {
		await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"claude-code",
			undefined,
			undefined,
			undefined,
			"2.1.150",
		);

		expect(runSessionStart).toHaveBeenCalledWith(
			expect.objectContaining({ agentRuntime: "claude-code", agentRuntimeVersion: "2.1.150" }),
		);
	});

	it("omitting agentRuntimeVersion (no source) forwards undefined without throwing", async () => {
		await runPluginScan(logger, "session", [], "/threats", "/allow", "0.10.0", "openclaw");

		expect(runSessionStart).toHaveBeenCalledWith(
			expect.objectContaining({ agentRuntime: "openclaw", agentRuntimeVersion: undefined }),
		);
	});

	it("invokes onNotices with the result's notice ids", async () => {
		runSessionStart.mockResolvedValueOnce({
			scanResults: [],
			versionCheck: null,
			notices: ["skill_upload_v1"],
		});
		const onNotices = vi.fn();

		await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"claude-code",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			onNotices,
		);

		expect(onNotices).toHaveBeenCalledWith(["skill_upload_v1"]);
	});

	it("does not invoke onNotices when there are no notices", async () => {
		const onNotices = vi.fn();

		await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"claude-code",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			onNotices,
		);

		expect(onNotices).not.toHaveBeenCalled();
	});
});

describe("createScanHandler", () => {
	it("passes agentRuntimeVersion from options into the scan", async () => {
		const handler = createScanHandler({
			logger,
			context: "activation",
			discoverPlugins: async () => [],
			selfPrefix: "self@",
			threatsDir: "/threats",
			allowlistsDir: "/allow",
			version: "0.10.0",
			agentRuntime: "cursor",
			agentRuntimeVersion: "3.6.31",
		});

		await handler();

		expect(runSessionStart).toHaveBeenCalledWith(
			expect.objectContaining({ agentRuntime: "cursor", agentRuntimeVersion: "3.6.31" }),
		);
	});
});

describe("announce_clean_scans gate", () => {
	it("runPluginScan returns the clean banner by default", async () => {
		const msg = await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"openclaw",
		);
		expect(msg).toContain("No threats found");
	});

	it("runPluginScan returns '' on clean scan when announceCleanScans=false", async () => {
		const msg = await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"openclaw",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			false,
		);
		expect(msg).toBe("");
	});

	it("runPluginScan still returns the threat banner when announceCleanScans=false and findings exist", async () => {
		runSessionStart.mockResolvedValueOnce({
			scanResults: [sampleThreatResult],
			versionCheck: null,
		});

		const msg = await runPluginScan(
			logger,
			"session",
			[],
			"/threats",
			"/allow",
			"0.10.0",
			"openclaw",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			false,
		);
		expect(msg).toContain("Threat Detected");
		expect(msg).toContain("Malicious command");
	});

	it("createScanHandler skips onResult on empty banner when announceCleanScans=false", async () => {
		const onResult = vi.fn();
		const handler = createScanHandler({
			logger,
			context: "activation",
			discoverPlugins: async () => [],
			selfPrefix: "self@",
			threatsDir: "/threats",
			trustedDomainsDir: "/allow",
			version: "0.10.0",
			agentRuntime: "openclaw",
			onResult,
			announceCleanScans: false,
		});

		await handler();

		expect(onResult).not.toHaveBeenCalled();
	});

	it("createScanHandler still calls onResult with the threat banner when findings exist and announceCleanScans=false", async () => {
		runSessionStart.mockResolvedValueOnce({
			scanResults: [sampleThreatResult],
			versionCheck: null,
		});
		const onResult = vi.fn();
		const handler = createScanHandler({
			logger,
			context: "activation",
			discoverPlugins: async () => [],
			selfPrefix: "self@",
			threatsDir: "/threats",
			trustedDomainsDir: "/allow",
			version: "0.10.0",
			agentRuntime: "openclaw",
			onResult,
			announceCleanScans: false,
		});

		await handler();

		expect(onResult).toHaveBeenCalledTimes(1);
		expect(onResult.mock.calls[0]?.[0]).toContain("Threat Detected");
	});

	it("createScanHandler defaults announceCleanScans=true and emits the clean banner", async () => {
		const onResult = vi.fn();
		const handler = createScanHandler({
			logger,
			context: "activation",
			discoverPlugins: async () => [],
			selfPrefix: "self@",
			threatsDir: "/threats",
			trustedDomainsDir: "/allow",
			version: "0.10.0",
			agentRuntime: "openclaw",
			onResult,
		});

		await handler();

		expect(onResult).toHaveBeenCalledTimes(1);
		expect(onResult.mock.calls[0]?.[0]).toContain("No threats found");
	});
});
