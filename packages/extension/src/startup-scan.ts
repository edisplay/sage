import { homedir } from "node:os";
import { join } from "node:path";

import {
	type Branding,
	createScanHandler as coreScanHandler,
	defaultBranding,
	type Logger,
	type SkillRoot,
} from "@gendigital/sage-core";
import * as vscode from "vscode";
import { resolveAgentRuntimeVersion } from "./agent_runtime_version.js";
import { discoverExtensionPlugins, discoverLooseSkillFolders } from "./plugin-discovery.js";

/** A skill directory family: the `.dir` it lives in and the `tag` it keys under. */
interface SkillFamily {
	dir: string;
	tag: string;
}

/**
 * Skill directory families per host, resolved at both scopes:
 *   - `personal`: `~/<dir>/skills` (user profile, shared across projects)
 *   - `project`:  `<workspace>/<dir>/skills` (per open workspace folder)
 *
 */
const SKILL_FAMILIES: Record<
	"cursor" | "vscode",
	{ personal: SkillFamily[]; project: SkillFamily[] }
> = {
	cursor: {
		personal: [
			{ dir: ".cursor", tag: "cursor" },
			{ dir: ".agents", tag: "agents" },
			{ dir: ".claude", tag: "claude" },
			{ dir: ".codex", tag: "codex" },
		],
		project: [
			{ dir: ".cursor", tag: "cursor" },
			{ dir: ".agents", tag: "agents" },
			{ dir: ".claude", tag: "claude" },
			{ dir: ".codex", tag: "codex" },
		],
	},
	vscode: {
		personal: [
			{ dir: ".copilot", tag: "copilot" },
			{ dir: ".claude", tag: "claude" },
			{ dir: ".agents", tag: "agents" },
		],
		project: [
			{ dir: ".github", tag: "github" },
			{ dir: ".claude", tag: "claude" },
			{ dir: ".agents", tag: "agents" },
		],
	},
};

function resolveSkillRoots(hostName: string): SkillRoot[] {
	const families = hostName === "Cursor" ? SKILL_FAMILIES.cursor : SKILL_FAMILIES.vscode;

	const roots: SkillRoot[] = families.personal.map(({ dir, tag }) => ({
		dir: join(homedir(), dir, "skills"),
		tag,
		scope: "personal",
	}));

	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		for (const { dir, tag } of families.project) {
			roots.push({ dir: join(root, dir, "skills"), tag, scope: "project" });
		}
	}
	return roots;
}

export function createExtensionScanHandler(
	context: vscode.ExtensionContext,
	hostName: string,
	logger: Logger,
	branding: Branding = defaultBranding,
	onResult?: (msg: string) => void,
	onNotices?: (noticeIds: string[]) => void,
	announceCleanScans = true,
): () => Promise<void> {
	const extensionsDir =
		hostName === "Cursor"
			? join(homedir(), ".cursor", "extensions")
			: join(homedir(), ".vscode", "extensions");

	const skillRoots = resolveSkillRoots(hostName);

	const threatsDir = join(context.extensionPath, "resources", "threats");
	const trustedDomainsDir = join(context.extensionPath, "resources", "trusted-domains");
	const version =
		((context.extension.packageJSON as Record<string, unknown>).version as string) ?? "0.0.0";
	const selfPrefix = `${(context.extension.packageJSON as Record<string, unknown>).name}@`;
	const agentRuntime = hostName === "Cursor" ? "cursor" : "vscode";

	return coreScanHandler({
		logger,
		context: "activation",
		discoverPlugins: async () => {
			const [extensions, skills] = await Promise.all([
				discoverExtensionPlugins(logger, extensionsDir, branding),
				discoverLooseSkillFolders(logger, skillRoots, branding),
			]);
			return [...extensions, ...skills];
		},
		selfPrefix,
		threatsDir,
		trustedDomainsDir,
		version,
		agentRuntime,
		agentRuntimeVersion: resolveAgentRuntimeVersion(agentRuntime),
		branding,
		onResult,
		onNotices,
		modelDownloadWorkerPath: context.asAbsolutePath(join("dist", "model-download-worker.cjs")),
		skillUploadWorkerPath: context.asAbsolutePath(join("dist", "skill-upload-worker.cjs")),
		style: "compact",
		announceCleanScans,
	});
}
