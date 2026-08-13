import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { atomicWriteJson } from "../file-utils.js";
import { checkForUpdate, isNewerVersion, type VersionCheckContext } from "../version-check.js";
import { makeTmpDir } from "./test-utils.js";

describe("isNewerVersion", () => {
	it("detects newer major version", () => {
		expect(isNewerVersion("0.4.0", "1.0.0")).toBe(true);
	});

	it("detects newer minor version", () => {
		expect(isNewerVersion("0.4.0", "0.5.0")).toBe(true);
	});

	it("detects newer patch version", () => {
		expect(isNewerVersion("0.4.0", "0.4.1")).toBe(true);
	});

	it("returns false for same version", () => {
		expect(isNewerVersion("0.4.0", "0.4.0")).toBe(false);
	});

	it("returns false for older version", () => {
		expect(isNewerVersion("1.0.0", "0.9.0")).toBe(false);
	});

	it("handles v prefix", () => {
		expect(isNewerVersion("v0.4.0", "v0.5.0")).toBe(true);
	});

	it("handles partial versions", () => {
		expect(isNewerVersion("1.0", "1.1")).toBe(true);
		expect(isNewerVersion("1", "2")).toBe(true);
	});
});

describe("checkForUpdate", () => {
	const originalFetch = globalThis.fetch;
	const baseContext: VersionCheckContext = {
		agentRuntime: "cursor",
		iid: "550e8400-e29b-41d4-a716-446655440000",
	};

	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.useRealTimers();
	});

	it("returns update available when remote version is newer", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "1.0.0",
			updateAvailable: true,
		});
	});

	it("returns no update when versions match", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.4.0" }),
		});

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "0.4.0",
			updateAvailable: false,
		});
	});

	it("returns no update when local is newer", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "0.3.0" }),
		});

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "0.3.0",
			updateAvailable: false,
		});
	});

	it("returns null for dev builds", async () => {
		const result = await checkForUpdate("dev", undefined, undefined, baseContext);
		expect(result).toBeNull();
	});

	it("returns null on HTTP error", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 404,
		});

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toBeNull();
	});

	it("returns null on network error", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error"));

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toBeNull();
	});

	it("returns null when response has no version field", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ name: "@gendigital/sage-core" }),
		});

		const result = await checkForUpdate("0.4.0", undefined, undefined, baseContext);
		expect(result).toBeNull();
	});

	it("includes agent context when provided", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});

		const ctx: VersionCheckContext = {
			agentRuntime: "cursor",
			agentRuntimeVersion: "0.48.7",
			iid: "550e8400-e29b-41d4-a716-446655440000",
		};

		await checkForUpdate("0.4.0", undefined, undefined, ctx);

		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		const body = JSON.parse((fetchCall[1] as RequestInit).body as string);
		expect(body.agent.agent_runtime).toBe("cursor");
		expect(body.agent.agent_runtime_version).toBe("0.48.7");
		expect(body.identity.uuid).toBe("550e8400-e29b-41d4-a716-446655440000");
		expect(body.config).toEqual(
			expect.objectContaining({
				sensitivity: expect.any(String),
				url_check_enabled: expect.any(Boolean),
				file_check_enabled: expect.any(Boolean),
				package_check_enabled: expect.any(Boolean),
				heuristics_enabled: expect.any(Boolean),
				pi_check_enabled: expect.any(Boolean),
				community_iq_enabled: expect.any(Boolean),
				skill_check_upload_enabled: expect.any(Boolean),
			}),
		);
	});

	it("uses caller-provided active config without reading from disk", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});

		const ctx: VersionCheckContext = {
			agentRuntime: "cursor",
			iid: "550e8400-e29b-41d4-a716-446655440000",
			config: {
				sensitivity: "paranoid",
				url_check: { enabled: false, timeout_seconds: 5 },
				file_check: { enabled: true, timeout_seconds: 5 },
				package_check: { enabled: false, timeout_seconds: 5 },
				heuristics_enabled: false,
				pi_check: {
					enabled: true,
					max_content_length: 2048,
				},
				community_iq: false,
				skill_check: { enabled: true, cache_ttl_days: 1, upload_enabled: false },
			},
		};

		await checkForUpdate("0.4.0", undefined, undefined, ctx);

		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		const body = JSON.parse((fetchCall[1] as RequestInit).body as string);
		expect(body.config).toEqual({
			sensitivity: "paranoid",
			url_check_enabled: false,
			file_check_enabled: true,
			package_check_enabled: false,
			heuristics_enabled: false,
			pi_check_enabled: true,
			community_iq_enabled: false,
			skill_check_upload_enabled: false,
		});
	});

	it("uses configPath from context when active config is not provided", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});
		const dir = await makeTmpDir();
		const configPath = `${dir}/custom-config.json`;
		await atomicWriteJson(configPath, {
			sensitivity: "relaxed",
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: true },
			heuristics_enabled: true,
			pi_check: { enabled: false },
			community_iq: false,
		});

		const ctx: VersionCheckContext = {
			agentRuntime: "cursor",
			iid: "550e8400-e29b-41d4-a716-446655440000",
			configPath,
		};

		await checkForUpdate("0.4.0", undefined, undefined, ctx);

		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		const body = JSON.parse((fetchCall[1] as RequestInit).body as string);
		expect(body.config).toEqual({
			sensitivity: "relaxed",
			url_check_enabled: false,
			file_check_enabled: false,
			package_check_enabled: true,
			heuristics_enabled: true,
			pi_check_enabled: false,
			community_iq_enabled: false,
			skill_check_upload_enabled: true,
		});
	});

	it("continues without config when config loading throws (fail-open)", async () => {
		vi.resetModules();
		vi.doMock("../config.js", () => ({
			loadConfig: vi.fn().mockRejectedValue(new Error("config read failed")),
		}));
		const { checkForUpdate: freshCheckForUpdate } = await import("../version-check.js");
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ version: "1.0.0" }),
		});
		const logger = {
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		};

		const result = await freshCheckForUpdate("0.4.0", logger, undefined, {
			agentRuntime: "cursor",
			iid: "550e8400-e29b-41d4-a716-446655440000",
		});

		expect(result).toEqual({
			currentVersion: "0.4.0",
			latestVersion: "1.0.0",
			updateAvailable: true,
		});
		expect(globalThis.fetch).toHaveBeenCalledOnce();
		const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
		const body = JSON.parse((fetchCall[1] as RequestInit).body as string);
		expect(body.config).toBeUndefined();
		expect(logger.debug).toHaveBeenCalledWith(
			expect.stringContaining("Version check config load failed"),
		);
		vi.doUnmock("../config.js");
	});
});
