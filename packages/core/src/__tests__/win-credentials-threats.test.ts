import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows credential threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects cmdkey /add (WIN-CRED-001)", () => {
		expect(matchCommand(engine, "cmdkey /add:server /user:admin /pass:secret123")).toContain(
			"CLT-WIN-CRED-001",
		);
	});

	it("detects cmdkey.exe /add (WIN-CRED-001)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(matchCommand(engine, "cmdkey.exe /add:server /user:admin /pass:secret123")).toContain(
			"CLT-WIN-CRED-001",
		);
	});

	it("detects ConvertTo-SecureString -AsPlainText (WIN-CRED-002)", () => {
		expect(matchCommand(engine, "ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force")).toContain(
			"CLT-WIN-CRED-002",
		);
	});

	it("detects type .env (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "type .env")).toContain("CLT-WIN-CRED-003");
	});

	it("detects type .env.local (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "type .env.local")).toContain("CLT-WIN-CRED-003");
	});

	it("detects Get-Content .credentials (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "Get-Content C:\\Users\\user\\.credentials")).toContain(
			"CLT-WIN-CRED-003",
		);
	});

	it("detects grouped Get-Content .env.production (WIN-CRED-003)", () => {
		expect(matchCommand(engine, "(Get-Content .env.production)")).toContain("CLT-WIN-CRED-003");
	});

	it("detects [Environment]::SetEnvironmentVariable with Password (WIN-CRED-004)", () => {
		expect(
			matchCommand(
				engine,
				"[Environment]::SetEnvironmentVariable('DB_Password', 'secret', 'User')",
			),
		).toContain("CLT-WIN-CRED-004");
	});

	it("detects $env:ApiKey assignment (WIN-CRED-005)", () => {
		expect(matchCommand(engine, "$env:ApiKey = 'sk-1234567890'")).toContain("CLT-WIN-CRED-005");
	});

	it("detects $env:Password assignment (WIN-CRED-005)", () => {
		expect(matchCommand(engine, "$env:Password = 'hunter2'")).toContain("CLT-WIN-CRED-005");
	});

	it("detects mimikatz (WIN-CRED-006)", () => {
		expect(matchCommand(engine, "mimikatz.exe")).toContain("CLT-WIN-CRED-006");
	});

	it("detects sekurlsa:: (WIN-CRED-006)", () => {
		expect(matchCommand(engine, "sekurlsa::logonpasswords")).toContain("CLT-WIN-CRED-006");
	});

	// --- Negative cases ---

	it("does not match type for normal file", () => {
		const ids = matchCommand(engine, "type readme.txt");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	it("does not match $env:PATH assignment", () => {
		const ids = matchCommand(engine, "$env:PATH = 'C:\\bin;' + $env:PATH");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	it("does not match Get-Content for normal file", () => {
		const ids = matchCommand(engine, "Get-Content C:\\logs\\app.log");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CRED"))).toEqual([]);
	});

	// --- Registry hive export (CRED-007) ---

	it("detects reg save HKLM\\SAM (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SAM C:\\temp\\sam.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("detects reg.exe save HKLM\\SAM (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg.exe save HKLM\\SAM C:\\temp\\sam.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("detects reg save HKLM\\SYSTEM (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SYSTEM C:\\temp\\system.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("detects reg save HKLM\\SECURITY (WIN-CRED-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SECURITY C:\\temp\\security.hiv")).toContain(
			"CLT-WIN-CRED-007",
		);
	});

	it("does not match reg save for other hives (WIN-CRED-007)", () => {
		const ids = matchCommand(engine, "reg save HKCU\\Software C:\\temp\\software.hiv");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-007")).toEqual([]);
	});

	// --- LSASS credential dumping (CRED-008) ---

	it("detects procdump lsass (WIN-CRED-008)", () => {
		expect(matchCommand(engine, "procdump -ma lsass.exe lsassdump.dmp")).toContain(
			"CLT-WIN-CRED-008",
		);
	});

	it("detects procdump64 lsass (WIN-CRED-008)", () => {
		expect(matchCommand(engine, "procdump64 -ma lsass.exe C:\\temp\\lsass.dmp")).toContain(
			"CLT-WIN-CRED-008",
		);
	});

	it("detects rundll32 comsvcs MiniDump (WIN-CRED-008)", () => {
		expect(
			matchCommand(
				engine,
				"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full",
			),
		).toContain("CLT-WIN-CRED-008");
	});

	it("does not match procdump for other processes (WIN-CRED-008)", () => {
		const ids = matchCommand(engine, "procdump -ma myapp.exe appdump.dmp");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-008")).toEqual([]);
	});

	// --- WLAN password extraction (CRED-009) ---

	it("detects netsh wlan show profiles key=clear (WIN-CRED-009)", () => {
		expect(matchCommand(engine, "netsh wlan show profiles name=MyWifi key=clear")).toContain(
			"CLT-WIN-CRED-009",
		);
	});

	it("detects netsh.exe wlan show profiles key=clear (WIN-CRED-009)", () => {
		expect(matchCommand(engine, "netsh.exe wlan show profiles name=MyWifi key=clear")).toContain(
			"CLT-WIN-CRED-009",
		);
	});

	it("does not match netsh wlan show profiles without key=clear (WIN-CRED-009)", () => {
		const ids = matchCommand(engine, "netsh wlan show profiles");
		expect(ids.filter((id) => id === "CLT-WIN-CRED-009")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match cmdkey /list (001 FP)", () => {
		const ids = matchCommand(engine, "cmdkey /list");
		expect(ids).not.toContain("CLT-WIN-CRED-001");
	});

	it("does not match ConvertTo-SecureString without -AsPlainText (002 FP)", () => {
		const ids = matchCommand(engine, "ConvertTo-SecureString (Read-Host -AsSecureString)");
		expect(ids).not.toContain("CLT-WIN-CRED-002");
	});

	it("does not match type for .txt file (003 FP)", () => {
		const ids = matchCommand(engine, "type config.txt");
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("does not match Get-Content for .log file (003 FP)", () => {
		const ids = matchCommand(engine, "Get-Content app.log");
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("does not treat --type plus os.environ as reading an env file (003 FP)", () => {
		const ids = matchCommand(
			engine,
			"jira issue create --type STask --body 'Components read os.environ[\"PROJECT_ID\"] instead of taking params'",
		);
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("does not match [Environment]::GetEnvironmentVariable (004 FP)", () => {
		const ids = matchCommand(engine, "[Environment]::GetEnvironmentVariable('PATH')");
		expect(ids).not.toContain("CLT-WIN-CRED-004");
	});

	it("does not match $env:GOPATH assignment (005 FP)", () => {
		const ids = matchCommand(engine, "$env:GOPATH = '/home/user/go'");
		expect(ids).not.toContain("CLT-WIN-CRED-005");
	});

	it("does not match $env:NODE_ENV assignment (005 FP)", () => {
		const ids = matchCommand(engine, "$env:NODE_ENV = 'production'");
		expect(ids).not.toContain("CLT-WIN-CRED-005");
	});

	it("does not match reg query HKLM\\SAM (007 FP)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SAM");
		expect(ids).not.toContain("CLT-WIN-CRED-007");
	});

	// --- CLT-WIN-CRED-010: Windows copy/move of secret files ---

	it("detects copy .env C:\\tmp\\ (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "copy .env C:\\tmp\\")).toContain("CLT-WIN-CRED-010");
	});

	it("detects xcopy .ssh\\id_rsa C:\\tmp\\ (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "xcopy .ssh\\id_rsa C:\\tmp\\")).toContain("CLT-WIN-CRED-010");
	});

	it("detects xcopy.exe .ssh\\id_rsa C:\\tmp\\ (WIN-CRED-010)", () => {
		// xcopy is a real standalone binary (unlike copy/mklink, cmd builtins
		// with no .exe form), so {{NOT_FILENAME}} needs the optional suffix.
		expect(matchCommand(engine, "xcopy.exe .ssh\\id_rsa C:\\tmp\\")).toContain("CLT-WIN-CRED-010");
	});

	it("detects robocopy .aws\\credentials (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "robocopy . C:\\tmp\\ .aws\\credentials")).toContain(
			"CLT-WIN-CRED-010",
		);
	});

	it("detects robocopy.exe .aws\\credentials (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "robocopy.exe . C:\\tmp\\ .aws\\credentials")).toContain(
			"CLT-WIN-CRED-010",
		);
	});

	it("detects Copy-Item .npmrc C:\\tmp\\ (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "Copy-Item .npmrc C:\\tmp\\")).toContain("CLT-WIN-CRED-010");
	});

	it("detects Move-Item .env C:\\tmp\\ (WIN-CRED-010)", () => {
		expect(matchCommand(engine, "Move-Item .env C:\\tmp\\")).toContain("CLT-WIN-CRED-010");
	});

	it("does not match copy my-master.key C:\\tmp\\ (WIN-CRED-010 FP — substring)", () => {
		expect(matchCommand(engine, "copy my-master.key C:\\tmp\\")).not.toContain("CLT-WIN-CRED-010");
	});

	it("does not match copy README.md C:\\tmp\\ (WIN-CRED-010 FP)", () => {
		expect(matchCommand(engine, "copy README.md C:\\tmp\\")).not.toContain("CLT-WIN-CRED-010");
	});

	it("does not match a prose mention of cmdkey /add (001 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "cmdkey /add:server /user:admin is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-001");
	});

	it("does not match a prose mention of ConvertTo-SecureString (002 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "ConvertTo-SecureString with -AsPlainText is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-002");
	});

	it("does not match a prose mention of type .env (003 FP)", () => {
		const ids = matchCommand(engine, 'echo "type .env is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CRED-003");
	});

	it("detects a grouped Get-Content invocation (003)", () => {
		// The `(` before Get-Content is itself a valid CMD_POS boundary.
		expect(matchCommand(engine, "(Get-Content .env.production)")).toContain("CLT-WIN-CRED-003");
	});

	it("does not match a prose mention of SetEnvironmentVariable (004 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "[Environment]::SetEnvironmentVariable Password is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-004");
	});

	it("still detects Invoke-Mimikatz, a compound name (006)", () => {
		// Neither CMD_POS nor NOT_COMPOUND_LEFT could be used here without
		// breaking this -- see the rule comment in win-credentials.yaml.
		expect(
			matchCommand(engine, 'Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"'),
		).toContain("CLT-WIN-CRED-006");
	});

	it("does not match a search-command mention of mimikatz (006 FP)", () => {
		const ids = matchCommand(engine, "grep -i mimikatz /var/log/security-advisory.txt");
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match a search-command mention of a parenthesized mimikatz (006 FP)", () => {
		// A ( glued directly to the opening quote can only be prose/data, never
		// a real subshell open -- see the win-persistence-threats.test.ts
		// counterpart for the full rationale.
		const ids = matchCommand(engine, 'grep -i "(mimikatz)" /var/log/security-advisory.txt');
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match a grep with a long flag chain before mimikatz (006 FP)", () => {
		// NOT_AFTER_TEXT_CMD's gap cap was 200 chars; a real, longer flag chain
		// before the identifier fell outside it and false-positived. Raised to
		// 500 -- see the win-persistence-threats.test.ts counterpart.
		const ids = matchCommand(
			engine,
			"grep --include=*.log --include=*.txt --include=*.md --include=*.ps1 " +
				"--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor " +
				"--exclude-dir=dist --exclude-dir=build --exclude-dir=coverage " +
				"-rn --color=never --line-number --with-filename --binary-files=without-match " +
				"mimikatz /var/log/security-advisory.txt",
		);
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match a prose mention of Mimikatz (006 FP)", () => {
		const ids = matchCommand(engine, 'echo "this repo does not contain Mimikatz"');
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match findstr for mimikatz dispatched through cmd /c (006 FP)", () => {
		const ids = matchCommand(engine, "cmd /c findstr mimikatz security-advisory.txt");
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match Select-String for mimikatz dispatched through powershell -Command (006 FP)", () => {
		const ids = matchCommand(
			engine,
			'powershell -Command "Select-String -Pattern mimikatz -Path .\\security-advisory.txt"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match lowercase select-string for mimikatz (006 FP, case_insensitive)", () => {
		// {{NOT_AFTER_TEXT_CMD}}'s denylist is fixed-case; the rule must
		// compile case-insensitive or this suppression only covers the
		// macro's exact casing (Select-String), not real-world variants.
		const ids = matchCommand(
			engine,
			'powershell -Command "select-string -Pattern mimikatz -Path .\\security-advisory.txt"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("does not match grep for mimikatz behind a sudo wrapper (006 FP)", () => {
		const ids = matchCommand(engine, "sudo grep -i mimikatz /var/log/security-advisory.txt");
		expect(ids).not.toContain("CLT-WIN-CRED-006");
	});

	it("still detects the real invocation dispatched through cmd /c (006)", () => {
		expect(matchCommand(engine, "cmd /c Invoke-Mimikatz -Command privilege::debug")).toContain(
			"CLT-WIN-CRED-006",
		);
	});

	it("still detects the real invocation wrapped in a subshell after a text command (006)", () => {
		// `(` is a command boundary for {{CMD_POS}}, so it must also bound the
		// NOT_AFTER_TEXT_CMD guard's tail span -- otherwise Write-Host in front
		// of the subshell would misattribute the real invocation inside it and
		// suppress a genuine detection.
		expect(matchCommand(engine, "Write-Host $(mimikatz.exe)")).toContain("CLT-WIN-CRED-006");
	});

	it("does not match a prose mention of reg save HKLM\\SAM (007 FP)", () => {
		const ids = matchCommand(engine, 'echo "reg save HKLM\\SAM is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CRED-007");
	});

	it("detects rundll32.exe with an .exe suffix (008)", () => {
		// NOT_FILENAME rejects a trailing dot, so the optional .exe suffix
		// must be consumed ahead of it, same as CLT-MITRE-096 (tscon).
		expect(
			matchCommand(
				engine,
				"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full",
			),
		).toContain("CLT-WIN-CRED-008");
	});

	it("does not match a prose mention of procdump lsass (008 FP)", () => {
		const ids = matchCommand(engine, 'echo "procdump -ma lsass.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CRED-008");
	});

	it("does not match a prose mention of rundll32 comsvcs MiniDump (008 FP)", () => {
		const ids = matchCommand(engine, 'echo "rundll32 comsvcs.dll MiniDump is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CRED-008");
	});

	it("does not match a prose mention of netsh wlan show profiles (009 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "netsh wlan show profiles key=clear is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CRED-009");
	});

	it("does not match a prose mention of copy .env (010 FP)", () => {
		const ids = matchCommand(engine, 'echo "copy .env C:\\tmp\\ is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CRED-010");
	});
});
