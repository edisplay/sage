import { afterEach, describe, expect, it, vi } from "vitest";
import { SkillAnalyzeClient } from "../clients/skill-analyze.js";
import { resolveEndpoint } from "../clients/url-check.js";

const V2_RESPONSE = {
	job_id: "550e8400-e29b-41d4-a716-446655440000",
	verdict: "CRITICAL",
	overall_risk_level: "CRITICAL",
	summary: "Reverse shell detected",
	detailed_analysis: "long text…",
	threat_categories: ["REMOTE_CODE_EXECUTION"],
	recommendations: ["Remove this skill"],
	custom_metadata: { slug: "evil", skill_id: "a".repeat(64) },
};

describe("SkillAnalyzeClient", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("parses a V2 analyze response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => V2_RESPONSE,
		});

		const client = new SkillAnalyzeClient();
		const result = await client.analyzeZip(new Uint8Array([1, 2, 3]), {
			slug: "evil",
			skillId: "a".repeat(64),
		});

		expect(result).not.toBeNull();
		expect(result?.jobId).toBe("550e8400-e29b-41d4-a716-446655440000");
		expect(result?.verdict).toBe("CRITICAL");
		expect(result?.summary).toBe("Reverse shell detected");
	});

	it("sends a multipart POST to the proxy with zip file and metadata", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => V2_RESPONSE,
		});
		globalThis.fetch = fetchMock;

		const client = new SkillAnalyzeClient();
		await client.analyzeZip(new Uint8Array([1, 2, 3]), { slug: "s", skillId: "b".repeat(64) });

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(resolveEndpoint("/v2/skill-analyze"));
		expect(init.method).toBe("POST");
		// The proxy injects the upstream credentials; the client sends none.
		expect(init.headers.Authorization).toBeUndefined();
		// fetch must derive the multipart boundary itself — no manual Content-Type.
		expect(init.headers["Content-Type"]).toBeUndefined();

		const body = init.body as FormData;
		expect(body).toBeInstanceOf(FormData);
		expect(body.get("delivery")).toBe("BLOCKING");
		expect(JSON.parse(body.get("skill_metadata") as string)).toEqual({
			is_private: true,
			name: "s",
			source: "Sage",
		});
		const file = body.get("file");
		expect(file).toBeInstanceOf(Blob);
		expect((file as Blob).size).toBe(3);
	});

	it("fails open (null) on non-2xx", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 413 });
		const client = new SkillAnalyzeClient();
		expect(await client.analyzeZip(new Uint8Array([1]))).toBeNull();
	});

	it("fails open (null) on network error / timeout", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("timeout"));
		const client = new SkillAnalyzeClient();
		expect(await client.analyzeZip(new Uint8Array([1]))).toBeNull();
	});

	it("honors a custom endpoint and authorization", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => V2_RESPONSE,
		});
		globalThis.fetch = fetchMock;

		const client = new SkillAnalyzeClient({
			endpoint: "https://example.test/analyze",
			authorization: "Bearer tok",
		});
		await client.analyzeZip(new Uint8Array([1]));

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("https://example.test/analyze");
		expect(init.headers.Authorization).toBe("Bearer tok");
	});
});
