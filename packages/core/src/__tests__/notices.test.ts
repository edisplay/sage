import { describe, expect, it } from "vitest";
import { defaultBranding } from "../brands.js";
import {
	formatNotice,
	formatNoticeById,
	NOTICES,
	type NoticeDefinition,
	SKILL_UPLOAD_NOTICE,
} from "../notices.js";

const twoLine: NoticeDefinition = {
	id: "test_notice_v1",
	body: (b) => [`hello from ${b.name}`, "second line"],
};

describe("formatNotice", () => {
	it("prefixes the first line with the info icon + brand and indents the rest", () => {
		const out = formatNotice(twoLine, defaultBranding);
		const lines = out.split("\n");
		expect(lines[0]).toBe(`ℹ️  ${defaultBranding.name}: hello from ${defaultBranding.name}`);
		expect(lines[1]).toBe("   second line");
	});

	it("handles a single-line body", () => {
		const out = formatNotice({ id: "x", body: () => ["only line"] });
		expect(out).toBe(`ℹ️  ${defaultBranding.name}: only line`);
	});
});

describe("formatNoticeById", () => {
	it("renders a registered notice", () => {
		expect(formatNoticeById(SKILL_UPLOAD_NOTICE.id)).toBe(formatNotice(SKILL_UPLOAD_NOTICE));
	});

	it("returns an empty string for an unknown id", () => {
		expect(formatNoticeById("does_not_exist")).toBe("");
	});
});

describe("NOTICES registry", () => {
	it("keys each notice by its own id", () => {
		for (const [key, notice] of Object.entries(NOTICES)) {
			expect(key).toBe(notice.id);
		}
	});

	it("includes the skill-upload consent notice", () => {
		expect(NOTICES[SKILL_UPLOAD_NOTICE.id]).toBe(SKILL_UPLOAD_NOTICE);
	});
});

describe("SKILL_UPLOAD_NOTICE eligibility", () => {
	it("is eligible when upload_enabled is not explicitly configured", async () => {
		// No config file at this path → not explicitly set → eligible.
		expect(await SKILL_UPLOAD_NOTICE.isEligible?.({ configPath: "/does/not/exist.json" })).toBe(
			true,
		);
	});
});
