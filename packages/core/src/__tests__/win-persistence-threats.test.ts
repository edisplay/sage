import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows persistence threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects reg add Run key (WIN-PERSIST-001)", () => {
		expect(
			matchCommand(
				engine,
				'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v evil /d "C:\\evil.exe"',
			),
		).toContain("CLT-WIN-PERSIST-001");
	});

	it("detects reg add RunOnce key (WIN-PERSIST-001)", () => {
		expect(
			matchCommand(
				engine,
				"reg ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v payload /d cmd.exe",
			),
		).toContain("CLT-WIN-PERSIST-001");
	});

	it("detects reg.exe add Run key (WIN-PERSIST-001)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(
			matchCommand(
				engine,
				'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v evil /d "C:\\evil.exe"',
			),
		).toContain("CLT-WIN-PERSIST-001");
	});

	it("detects sc create (WIN-PERSIST-002)", () => {
		expect(matchCommand(engine, 'sc create evilsvc binpath= "C:\\evil.exe"')).toContain(
			"CLT-WIN-PERSIST-002",
		);
	});

	it("detects sc config (WIN-PERSIST-002)", () => {
		expect(matchCommand(engine, 'sc config legitsvc binpath= "C:\\evil.exe"')).toContain(
			"CLT-WIN-PERSIST-002",
		);
	});

	it("detects sc.exe create (WIN-PERSIST-002)", () => {
		expect(matchCommand(engine, 'sc.exe create evilsvc binpath= "C:\\evil.exe"')).toContain(
			"CLT-WIN-PERSIST-002",
		);
	});

	it("detects schtasks /create (WIN-PERSIST-003)", () => {
		expect(
			matchCommand(engine, 'schtasks /Create /tn "EvilTask" /tr "C:\\evil.exe" /sc onlogon'),
		).toContain("CLT-WIN-PERSIST-003");
	});

	it("detects schtasks.exe /create (WIN-PERSIST-003)", () => {
		expect(
			matchCommand(engine, 'schtasks.exe /Create /tn "EvilTask" /tr "C:\\evil.exe" /sc onlogon'),
		).toContain("CLT-WIN-PERSIST-003");
	});

	it("detects New-ScheduledTask (WIN-PERSIST-004)", () => {
		expect(
			matchCommand(
				engine,
				"New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'evil.exe')",
			),
		).toContain("CLT-WIN-PERSIST-004");
	});

	it("detects Set-ItemProperty Run key (WIN-PERSIST-005)", () => {
		expect(
			matchCommand(
				engine,
				"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\' -Name evil -Value 'C:\\evil.exe'",
			),
		).toContain("CLT-WIN-PERSIST-005");
	});

	it("detects New-Service (WIN-PERSIST-006)", () => {
		expect(
			matchCommand(engine, "New-Service -Name evilsvc -BinaryPathName 'C:\\evil.exe'"),
		).toContain("CLT-WIN-PERSIST-006");
	});

	it("detects Startup folder path (WIN-PERSIST-007)", () => {
		expect(
			matchCommand(
				engine,
				'copy evil.exe "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe"',
			),
		).toContain("CLT-WIN-PERSIST-007");
	});

	// --- Negative cases ---

	it("does not match reg query", () => {
		const ids = matchCommand(
			engine,
			"reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		);
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	it("does not match sc query", () => {
		const ids = matchCommand(engine, "sc query wuauserv");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	it("does not match schtasks /query", () => {
		const ids = matchCommand(engine, "schtasks /Query /tn MyTask");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-PERSIST"))).toEqual([]);
	});

	it("does not match a quoted mention of reg add Run (WIN-PERSIST-001 FP)", () => {
		const ids = matchCommand(engine, 'echo "reg add HKCU\\...\\Run\\ ... is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-PERSIST-001");
	});

	it("does not match a quoted mention of sc create (WIN-PERSIST-002 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "sc create evilsvc binpath= ... is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-002");
	});

	it("does not match a quoted mention of schtasks /Create (WIN-PERSIST-003 FP)", () => {
		const ids = matchCommand(engine, 'echo "schtasks /Create /tn EvilTask is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-PERSIST-003");
	});

	it("does not match New-ScheduledTaskAction alone (WIN-PERSIST-004 FP)", () => {
		// Had no boundary at all, so it matched inside this distinct, real
		// cmdlet even when New-ScheduledTask itself was never called.
		const ids = matchCommand(engine, "New-ScheduledTaskAction -Execute 'notepad.exe'");
		expect(ids).not.toContain("CLT-WIN-PERSIST-004");
	});

	it("does not match a quoted mention of New-ScheduledTask (WIN-PERSIST-004 FP)", () => {
		const ids = matchCommand(engine, 'echo "run New-ScheduledTask to persist"');
		expect(ids).not.toContain("CLT-WIN-PERSIST-004");
	});

	it("does not match Set-ItemPropertyValue alone (WIN-PERSIST-005 FP)", () => {
		// Had no boundary at all, so it matched inside this distinct, real
		// cmdlet even when Set-ItemProperty itself was never called.
		const ids = matchCommand(
			engine,
			"Set-ItemPropertyValue -Path 'HKCU:\\Software\\Run\\' -Name x -Value y",
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-005");
	});

	it("does not match a quoted mention of New-Service (WIN-PERSIST-006 FP)", () => {
		const ids = matchCommand(engine, 'echo "New-Service creates a persistent service"');
		expect(ids).not.toContain("CLT-WIN-PERSIST-006");
	});

	// --- WMI event subscription persistence (PERSIST-008) ---

	it("detects CommandLineEventConsumer (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(
				engine,
				'Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{Name="Evil"; CommandLineTemplate="cmd.exe /c calc.exe"}',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("detects ActiveScriptEventConsumer (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(
				engine,
				'Set-WmiInstance -Class ActiveScriptEventConsumer -Arguments @{Name="Evil"; ScriptText="malicious"}',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("detects a lowercase WMI class name (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(engine, "set-wmiinstance -class commandlineeventconsumer -arguments @{}"),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("does not match Get-WmiObject __EventFilter (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "Get-WmiObject -Class __EventFilter");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a longer identifier containing the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "MyCommandLineEventConsumerFactory.Create()");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a compound identifier containing the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "Get-Content CommandLineEventConsumer-notes.md");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a filename mentioning the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "CommandLineEventConsumer.md");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a grep for the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, 'grep "CommandLineEventConsumer" src/');
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a grep for a parenthesized class name (WIN-PERSIST-008 neg)", () => {
		// The `(` excluded from NOT_AFTER_TEXT_CMD's tail span (for the subshell
		// fix below) would otherwise also break this span, since a ( glued
		// directly to the opening quote can only be prose/data, never a real
		// subshell open -- those are always `$(` or a bare `(` after
		// whitespace/a boundary, never immediately after a quote character.
		const ids = matchCommand(engine, 'grep "(CommandLineEventConsumer)" src/');
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("still false-positives on a class name in parens deeper inside quoted prose (WIN-PERSIST-008, known gap)", () => {
		// Documented, accepted residual: unlike the case above, this ( isn't
		// glued to the opening quote, so it's indistinguishable from a real
		// subshell open without actual quote-state tracking this engine
		// doesn't have. Locks in the boundary of the fix, not a desired result.
		expect(matchCommand(engine, 'grep "the (CommandLineEventConsumer) tool" src/')).toContain(
			"CLT-WIN-PERSIST-008",
		);
	});

	it("does not match findstr for the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "findstr CommandLineEventConsumer session.log");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match a grep with a long flag chain before the class name (WIN-PERSIST-008 neg)", () => {
		// NOT_AFTER_TEXT_CMD's gap cap was 200 chars; a real, longer flag chain
		// before the identifier fell outside it and false-positived. Raised to
		// 500 -- this command's gap is ~270 chars, comfortably inside the new
		// cap and outside the old one.
		const ids = matchCommand(
			engine,
			"grep --include=*.log --include=*.txt --include=*.md --include=*.ps1 " +
				"--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor " +
				"--exclude-dir=dist --exclude-dir=build --exclude-dir=coverage " +
				"-rn --color=never --line-number --with-filename --binary-files=without-match " +
				"CommandLineEventConsumer /var/log/",
		);
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match Select-String for the class name (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(
			engine,
			'Select-String -Pattern "CommandLineEventConsumer" -Path C:\\logs\\app.log',
		);
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match findstr dispatched through cmd /c (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, "cmd /c findstr CommandLineEventConsumer session.log");
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match Select-String dispatched through powershell -Command (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(
			engine,
			'powershell -Command "Select-String -Pattern CommandLineEventConsumer -Path C:\\logs\\app.log"',
		);
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("does not match grep behind a sudo wrapper (WIN-PERSIST-008 neg)", () => {
		const ids = matchCommand(engine, 'sudo grep -rn "CommandLineEventConsumer" /var/log');
		expect(ids.filter((id) => id === "CLT-WIN-PERSIST-008")).toEqual([]);
	});

	it("still detects the real invocation dispatched through cmd /c (WIN-PERSIST-008)", () => {
		// Proves the dispatch-awareness fix doesn't overreach: cmd /c in front
		// of the REAL invocation (not a denylisted text command) must still fire.
		expect(
			matchCommand(engine, "cmd /c Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{}"),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("still detects the real invocation after an unrelated grep, same command line (WIN-PERSIST-008)", () => {
		expect(
			matchCommand(
				engine,
				"grep -rn foo file.txt; Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{}",
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("still detects the real invocation after a benign mention, same command line (WIN-PERSIST-008)", () => {
		// Proves the guard suppresses per occurrence, not per line: the first
		// mention (right after Write-Host) is suppressed, but the second
		// (right after Set-WmiInstance, past the `;` boundary) still fires.
		expect(
			matchCommand(
				engine,
				'Write-Host "mentions CommandLineEventConsumer"; Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{}',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("still detects the real invocation wrapped in a subshell after a text command (WIN-PERSIST-008)", () => {
		// `(` is a command boundary for {{CMD_POS}}, so it must also bound the
		// NOT_AFTER_TEXT_CMD guard's tail span -- otherwise Write-Host in front
		// of the subshell would misattribute the real invocation inside it and
		// suppress a genuine detection.
		expect(
			matchCommand(
				engine,
				"Write-Host $(Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{})",
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	it("still detects a real invocation substituted inside a quoted string (WIN-PERSIST-008)", () => {
		// The quote-glued-paren exemption only exempts a ( immediately preceded
		// by a quote char -- here it's preceded by `$`, so it's still treated
		// as a boundary and this stays a real detection, not suppressed.
		expect(
			matchCommand(
				engine,
				'echo "$(Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{})"',
			),
		).toContain("CLT-WIN-PERSIST-008");
	});

	// NOT_AFTER_TEXT_CMD nests {{CMD_POS}} inside a variable-length lookbehind
	// -- the first time a macro does that. Every repetition is unambiguous by
	// construction, so long adversarial input must not make it backtrack
	// exponentially, same concern as CLT-CMD-009's dedicated timing test.
	it("evaluates NOT_AFTER_TEXT_CMD in linear time against adversarial input (WIN-PERSIST-008)", () => {
		const started = performance.now();
		const inputs = [
			`grep ${"-rn ".repeat(300)}CommandLineEventConsumer`,
			`Write-Host ${"a ".repeat(300)}CommandLineEventConsumer`,
			`sudo grep ${"-x".repeat(2000)} CommandLineEventConsumer`,
			`cmd /c findstr ${"y ".repeat(300)}CommandLineEventConsumer`,
			`powershell -Command "Select-String ${"z ".repeat(300)}CommandLineEventConsumer"`,
			// Stresses the new quote-glued-paren alternative specifically: a long
			// run of near-miss `"(` sequences (quote satisfies the lookbehind but
			// isn't followed by a boundary char, so each one is a fresh
			// backtrack attempt) ahead of the identifier.
			`grep ${'"('.repeat(2000)}CommandLineEventConsumer`,
			`Write-Host ${'"('.repeat(2000)}CommandLineEventConsumer`,
		];
		for (const input of inputs) matchCommand(engine, input);
		expect(performance.now() - started).toBeLessThan(1000);
	});

	// --- Additional FP coverage ---

	it("does not match reg query RunOnce (001 FP)", () => {
		const ids = matchCommand(
			engine,
			"reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\",
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-001");
	});

	it("does not match sc query service (002 FP)", () => {
		const ids = matchCommand(engine, "sc query wuauserv");
		expect(ids).not.toContain("CLT-WIN-PERSIST-002");
	});

	it("does not match schtasks /Delete (003 FP)", () => {
		const ids = matchCommand(engine, "schtasks /Delete /tn OldTask /f");
		expect(ids).not.toContain("CLT-WIN-PERSIST-003");
	});

	it("does not match Get-ScheduledTask (004 FP)", () => {
		const ids = matchCommand(engine, "Get-ScheduledTask -TaskName MyTask");
		expect(ids).not.toContain("CLT-WIN-PERSIST-004");
	});

	it("does not match Get-ItemProperty Run key (005 FP)", () => {
		const ids = matchCommand(
			engine,
			"Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'",
		);
		expect(ids).not.toContain("CLT-WIN-PERSIST-005");
	});

	it("does not match Get-Service (006 FP)", () => {
		const ids = matchCommand(engine, "Get-Service -Name wuauserv");
		expect(ids).not.toContain("CLT-WIN-PERSIST-006");
	});
});
