import { describe, expect, it } from "vitest";
import { toCursorPermission } from "../sage-hook";

describe("Cursor hook response compatibility", () => {
	it("promotes ask preToolUse verdicts to deny because Cursor does not enforce ask", async () => {
		expect(toCursorPermission("preToolUse", "ask")).toBe("deny");
	});

	it("promotes ask beforeReadFile verdicts to deny because Cursor only supports allow or deny", async () => {
		expect(toCursorPermission("beforeReadFile", "ask")).toBe("deny");
	});

	it("leaves supported ask hook verdicts unchanged", async () => {
		expect(toCursorPermission("beforeShellExecution", "ask")).toBe("ask");
	});
});
