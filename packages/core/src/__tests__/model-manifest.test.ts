import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchModelManifest } from "../clients/model-manifest.js";
import { atomicWriteJson } from "../file-utils.js";
import { makeTmpDir } from "./test-utils.js";

const IID = "550e8400-e29b-41d4-a716-446655440000";

describe("fetchModelManifest", () => {
	const originalFetch = globalThis.fetch;

	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.useRealTimers();
	});

	function mockFetch(impl: typeof fetch): void {
		globalThis.fetch = impl as typeof globalThis.fetch;
	}

	it("returns parsed manifest on a well-formed response", async () => {
		mockFetch(
			async () =>
				new Response(
					JSON.stringify({
						schema: "v1",
						models: {
							"pi-model": {
								url: "https://example.com/pi-model-v1.tar.gz",
								sha256: "abc",
							},
						},
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				),
		);

		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "claude-code",
		});
		expect(result).toEqual({
			schema: "v1",
			models: {
				"pi-model": { url: "https://example.com/pi-model-v1.tar.gz", sha256: "abc" },
			},
		});
	});

	it("includes the standard envelope plus a models.schema field in the request body", async () => {
		let capturedBody: unknown = null;
		mockFetch(async (_url, init) => {
			capturedBody = init?.body ? JSON.parse(String(init.body)) : null;
			return new Response(JSON.stringify({ schema: "v1", models: {} }), { status: 200 });
		});

		await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "claude-code",
			agentRuntimeVersion: "1.2.3",
			versionApp: "0.8.0",
		});

		const body = capturedBody as Record<string, unknown>;
		expect(body).toBeTruthy();
		expect(body.identity).toEqual({ uuid: IID });
		expect(body.product).toMatchObject({ version_app: "0.8.0" });
		expect(body.agent).toMatchObject({ agent_runtime: "claude-code" });
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
		expect(body.models).toEqual({ schema: "v1" });
	});

	it("uses caller-provided active config without reading config file", async () => {
		let capturedBody: unknown = null;
		mockFetch(async (_url, init) => {
			capturedBody = init?.body ? JSON.parse(String(init.body)) : null;
			return new Response(JSON.stringify({ schema: "v1", models: {} }), { status: 200 });
		});

		await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "claude-code",
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
			},
		});

		const body = capturedBody as Record<string, unknown>;
		expect(body.config).toEqual({
			sensitivity: "paranoid",
			url_check_enabled: false,
			file_check_enabled: true,
			package_check_enabled: false,
			heuristics_enabled: false,
			pi_check_enabled: true,
			community_iq_enabled: false,
			skill_check_upload_enabled: true,
		});
	});

	it("uses configPath when active config is not provided", async () => {
		let capturedBody: unknown = null;
		mockFetch(async (_url, init) => {
			capturedBody = init?.body ? JSON.parse(String(init.body)) : null;
			return new Response(JSON.stringify({ schema: "v1", models: {} }), { status: 200 });
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

		await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "claude-code",
			configPath,
		});

		const body = capturedBody as Record<string, unknown>;
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

	it("returns null on HTTP error", async () => {
		mockFetch(async () => new Response("nope", { status: 502 }));
		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result).toBeNull();
	});

	it("returns null on a malformed response (missing models)", async () => {
		mockFetch(async () => new Response(JSON.stringify({ schema: "v1" }), { status: 200 }));
		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result).toBeNull();
	});

	it("returns null on a schema mismatch", async () => {
		mockFetch(
			async () => new Response(JSON.stringify({ schema: "v2", models: {} }), { status: 200 }),
		);
		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result).toBeNull();
	});

	it("skips entries missing sha256 (and keeps the rest)", async () => {
		mockFetch(
			async () =>
				new Response(
					JSON.stringify({
						schema: "v1",
						models: {
							good: { url: "https://example.com/good.tar.gz", sha256: "abc" },
							bad: { url: "https://example.com/bad.tar.gz" },
						},
					}),
					{ status: 200 },
				),
		);
		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result?.models).toEqual({
			good: { url: "https://example.com/good.tar.gz", sha256: "abc" },
		});
	});

	it("returns null when iid is empty", async () => {
		const result = await fetchModelManifest({
			iid: "",
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result).toBeNull();
	});

	it("returns null when fetch throws", async () => {
		mockFetch(async () => {
			throw new Error("network down");
		});
		const result = await fetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
		});
		expect(result).toBeNull();
	});

	it("continues without config when config loading throws (fail-open)", async () => {
		vi.resetModules();
		vi.doMock("../config.js", () => ({
			loadConfig: vi.fn().mockRejectedValue(new Error("config read failed")),
		}));
		const { fetchModelManifest: freshFetchModelManifest } = await import(
			"../clients/model-manifest.js"
		);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ schema: "v1", models: {} }),
		});
		const logger = {
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		};

		const result = await freshFetchModelManifest({
			iid: IID,
			schema: "v1",
			agentRuntime: "cursor",
			logger,
		});

		expect(result).toEqual({ schema: "v1", models: {} });
		expect(globalThis.fetch).toHaveBeenCalledOnce();
		const body = JSON.parse((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body);
		expect(body.config).toBeUndefined();
		expect(logger.debug).toHaveBeenCalledWith(
			expect.stringContaining("Model manifest config load failed"),
		);
		vi.doUnmock("../config.js");
	});

	it("skips config loading when iid is missing", async () => {
		vi.resetModules();
		vi.doMock("../config.js", () => ({
			loadConfig: vi.fn().mockRejectedValue(new Error("should not be called")),
		}));
		const { fetchModelManifest: freshFetchModelManifest } = await import(
			"../clients/model-manifest.js"
		);
		globalThis.fetch = vi.fn();

		const result = await freshFetchModelManifest({
			iid: "",
			schema: "v1",
			agentRuntime: "cursor",
		});

		expect(result).toBeNull();
		expect(globalThis.fetch).not.toHaveBeenCalled();
		vi.doUnmock("../config.js");
	});
});
