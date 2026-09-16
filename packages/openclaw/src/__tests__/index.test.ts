import { describe, expect, it, vi } from "vitest";
import plugin from "../index.js";

vi.mock("@gendigital/sage-core", () => ({
	ApprovalStore: class {
		cleanup() {}
	},
	checkAllowlistMigration: vi.fn(() => Promise.resolve({ needed: false, entryTypes: [] })),
	createOperationalLogger: vi.fn(() => ({
		forComponent: vi.fn(() => ({
			debug() {},
			info() {},
			warn() {},
			error() {},
		})),
	})),
	formatAllowlistMigrationWarning: vi.fn(() => "allowlist migration warning"),
	formatConfigurationWarnings: vi.fn(() => "config warnings"),
	formatNoticeById: vi.fn(() => ""),
	getConfigurationWarningsSync: vi.fn(() => []),
	loadConfigSync: vi.fn(() => ({})),
	resolveBranding: vi.fn(() => ({ name: "Sage" })),
	takePendingNotices: vi.fn(() => Promise.resolve([])),
}));

vi.mock("../bundled-dirs.js", () => ({
	getBundledDataDirs: vi.fn(() => ({
		threatsDir: "/threats",
		trustedDomainsDir: "/trusted-domains",
	})),
}));

vi.mock("../startup-scan.js", () => ({
	createPromptContextHandler: vi.fn(
		(getSecurityFindings: () => string | null, clearFindings: () => void) =>
			(notices: string | null) => {
				const findings = getSecurityFindings();
				if (!notices && !findings) return undefined;
				if (findings) clearFindings();
				return { prependContext: [notices, findings].filter(Boolean).join("\n\n") };
			},
	),
	createSessionScanHandler: vi.fn(
		(_logger: unknown, _branding: unknown, onResult?: (msg: string) => void) => () => {
			onResult?.("session scan");
		},
	),
	createStartupScanHandler: vi.fn(
		(_logger: unknown, _branding: unknown, onResult?: (msg: string) => void) => () => {
			onResult?.("startup scan");
		},
	),
}));

vi.mock("../tool-handler.js", () => ({
	createToolCallHandler: vi.fn(() => vi.fn()),
}));

type Handler = () => unknown;

function createMockApi() {
	const handlers = new Map<string, Handler>();
	return {
		handlers,
		api: {
			logger: {
				debug() {},
				info() {},
				warn() {},
				error() {},
			},
			on(event: string, handler: Handler) {
				handlers.set(event, handler);
			},
		},
	};
}

describe("OpenClaw plugin registration", () => {
	it("surfaces context via before_prompt_build, not the removed before_agent_start hook", () => {
		const { api, handlers } = createMockApi();
		plugin.register(api);

		// before_agent_start was removed from OpenClaw (2026.9.x); registering it
		// makes the ClawHub Plugin Inspector reject the package (unknown-hook-name).
		expect(handlers.has("before_agent_start")).toBe(false);
		expect(handlers.has("before_prompt_build")).toBe(true);
	});

	it("keeps configuration warnings while replacing stale scan findings", async () => {
		const { api, handlers } = createMockApi();
		plugin.register(api);

		handlers.get("gateway_start")?.();
		handlers.get("session_start")?.();

		const result = await handlers.get("before_prompt_build")?.();
		expect(result).toEqual({ prependContext: "config warnings\n\nsession scan" });

		const secondResult = await handlers.get("before_prompt_build")?.();
		expect(secondResult).toBeUndefined();
	});
});
