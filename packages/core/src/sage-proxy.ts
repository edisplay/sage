import type { AgentRuntime, Config } from "./types.js";

export type SageHostOs = "WINDOWS" | "MACOS" | "LINUX" | string;

export function mapSageHostOs(platform: NodeJS.Platform): SageHostOs {
	switch (platform) {
		case "win32":
			return "WINDOWS";
		case "darwin":
			return "MACOS";
		case "linux":
			return "LINUX";
		default:
			return platform;
	}
}

export function mapSageHostArchitecture(arch: NodeJS.Architecture): string {
	return arch.toUpperCase();
}

export interface SageUserConfig {
	sensitivity: string;
	url_check_enabled: boolean;
	file_check_enabled: boolean;
	package_check_enabled: boolean;
	heuristics_enabled: boolean;
	pi_check_enabled: boolean;
	community_iq_enabled: boolean;
	skill_check_upload_enabled: boolean;
}

export type SageUserConfigInput = Pick<
	Config,
	| "sensitivity"
	| "url_check"
	| "file_check"
	| "package_check"
	| "heuristics_enabled"
	| "pi_check"
	| "community_iq"
	| "skill_check"
>;

export function buildSageUserConfig(config: SageUserConfigInput): SageUserConfig {
	return {
		sensitivity: config.sensitivity,
		url_check_enabled: config.url_check.enabled,
		file_check_enabled: config.file_check.enabled,
		package_check_enabled: config.package_check.enabled,
		heuristics_enabled: config.heuristics_enabled,
		pi_check_enabled: config.pi_check.enabled,
		community_iq_enabled: config.community_iq,
		// Optional-chained + defaulted: real callers pass a loadConfig result (skill_check
		// always present via the schema default), but this feeds fail-open telemetry, so a
		// partial config must never crash the envelope build.
		skill_check_upload_enabled: config.skill_check?.upload_enabled ?? true,
	};
}

export interface SageProxyEnvelope {
	identity: {
		uuid: string;
	};
	product: {
		version_app: string;
	};
	platform: {
		os: SageHostOs;
		architecture: string;
	};
	agent: {
		agent_runtime: AgentRuntime | string;
		agent_runtime_version: string | undefined;
	};
	config?: SageUserConfig;
}

export function buildSageProxyEnvelope(args: {
	iid: string;
	versionApp: string;
	agentRuntime: AgentRuntime | string;
	agentRuntimeVersion?: string;
	platformOs?: SageHostOs;
	platformArchitecture?: string;
	config?: SageUserConfigInput;
}): SageProxyEnvelope {
	return {
		identity: { uuid: args.iid },
		product: { version_app: args.versionApp },
		platform: {
			os: args.platformOs ?? mapSageHostOs(process.platform),
			architecture: args.platformArchitecture ?? mapSageHostArchitecture(process.arch),
		},
		agent: {
			agent_runtime: args.agentRuntime,
			agent_runtime_version: args.agentRuntimeVersion,
		},
		...(args.config ? { config: buildSageUserConfig(args.config) } : {}),
	};
}
