import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { withFileLock } from "./file-utils.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

export const CONFIG_DEFAULTS_FILENAME = "config.default.json";
/** Bump whenever the serialized defaults shape or values change. */
export const CONFIG_DEFAULTS_SCHEMA_VERSION = 2;

export type ConfigDefaults = Config & { schema_version: number };

/** Versioned, fully-defaulted config object with portable `~/.sage/...` paths. */
export function buildConfigDefaults(): ConfigDefaults {
	return {
		schema_version: CONFIG_DEFAULTS_SCHEMA_VERSION,
		...ConfigSchema.parse({}),
	};
}

/** Canonical on-disk form: 2-space indent with a trailing newline. */
export function serializeConfigDefaults(): string {
	return `${JSON.stringify(buildConfigDefaults(), null, 2)}\n`;
}

function readSchemaVersion(raw: string): number | null {
	try {
		const data = JSON.parse(raw) as unknown;
		if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
		const version = (data as Record<string, unknown>).schema_version;
		return typeof version === "number" && Number.isInteger(version) ? version : null;
	} catch {
		return null;
	}
}

export async function deployConfigDefaults(
	sageDirPath: string,
	logger: Logger = nullLogger,
): Promise<void> {
	const targetPath = join(sageDirPath, CONFIG_DEFAULTS_FILENAME);
	const defaults = serializeConfigDefaults();

	try {
		await mkdir(sageDirPath, { recursive: true, mode: 0o700 });
		// recursive mkdir does not update an existing directory's mode.
		await chmod(sageDirPath, 0o700);

		let existing: string | null = null;
		try {
			existing = await readFile(targetPath, "utf-8");
		} catch {
			// Missing or unreadable defaults are refreshed below.
		}

		if (existing) {
			const existingVersion = readSchemaVersion(existing);
			if (existingVersion !== null && existingVersion > CONFIG_DEFAULTS_SCHEMA_VERSION) {
				logger.warn("Deployed config defaults are newer, update your installation", {
					path: targetPath,
					existingVersion,
					supportedVersion: CONFIG_DEFAULTS_SCHEMA_VERSION,
				});
				return;
			}
			if (existing === defaults) return;
		}

		await withFileLock(targetPath, async () => {
			await writeFile(targetPath, defaults, { encoding: "utf-8", mode: 0o600 });

			logger.debug("Deployed config defaults", {
				path: targetPath,
				schemaVersion: CONFIG_DEFAULTS_SCHEMA_VERSION,
			});
		});
	} catch (err) {
		logger.debug("Failed to deploy config defaults", { path: targetPath, error: String(err) });
	}
}
