import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
	AMSI_DETECTION_NAMES,
	amsiReportingData,
	buildDetectionNameCatalog,
	formatReportingDetectionName,
	isCanonicalDetectionName,
	PACKAGE_DETECTION_NAMES,
	PI_DETECTION_NAME,
} from "../detection-names.js";
import { loadThreats } from "../threat-loader.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");

describe("canonical detection names", () => {
	it("loads authored heuristic names unchanged", async () => {
		const threats = await loadThreats(THREATS_DIR);
		const namesById = new Map(threats.map((threat) => [threat.id, threat.detectionName]));

		expect(namesById.get("CLT-CMD-001")).toBe("CMD:SageCommand-A [Heur]");
		expect(namesById.get("CLT-WIN-CMD-027")).toBe("CMD:SageWindowsCommand-AA [Heur]");
		expect(namesById.get("CLT-URL-005")).toBe("FN:SageUrl-E [Heur]");
		expect(namesById.get("CLT-PI-010")).toBe("Other:SagePromptInjection-J [Heur]");
		expect(namesById.get("DUMMY-CMD-DENY-001")).toBe("CMD:SageTestCommandDeny-A [Tst]");
	});

	it("keeps every shipped and synthetic name canonical and unique", async () => {
		const threats = await loadThreats(THREATS_DIR);
		const catalog = buildDetectionNameCatalog(threats);
		const names = catalog.map((entry) => entry.detectionName);

		expect(threats.length).toBeGreaterThan(0);
		expect(names.every(isCanonicalDetectionName)).toBe(true);
		expect(new Set(names).size).toBe(names.length);
	});

	it("keeps every explicit synthetic mapping canonical", () => {
		const names = [
			PI_DETECTION_NAME,
			...Object.values(PACKAGE_DETECTION_NAMES),
			...Object.values(AMSI_DETECTION_NAMES),
		];
		expect(names.every(isCanonicalDetectionName)).toBe(true);
	});

	it("uses a distinct identity for ML prompt-injection signals", () => {
		expect(PI_DETECTION_NAME).toBe("Other:SagePromptInjectionML-A [Susp]");
	});

	it("adds reporting metadata without changing the canonical name", () => {
		expect(formatReportingDetectionName(PI_DETECTION_NAME, "ml", "pi-model:v2")).toBe(
			"Other:SagePromptInjectionML-A [Susp]|sgml:pi-model:v2|sage",
		);
		expect(
			formatReportingDetectionName(
				"Other:SageAmsiDetected-A [Heur]",
				"amsi",
				amsiReportingData(0x8000),
			),
		).toBe("Other:SageAmsiDetected-A [Heur]|sgam:AMSI_DETECTED:8000|sage");
		expect(
			formatReportingDetectionName("CMD:SageCommand-A [Heur]", "heuristics", "CLT-CMD-001:3"),
		).toBe("CMD:SageCommand-A [Heur]|sghe:CLT-CMD-001:3|sage");
		expect(
			formatReportingDetectionName("Other:SagePackageMalicious-A [Trj]", "package", "fizbuzz:1.2"),
		).toBe("Other:SagePackageMalicious-A [Trj]|sgpk:fizbuzz:1.2|sage");

		expect(PI_DETECTION_NAME).toBe("Other:SagePromptInjectionML-A [Susp]");
	});
});
