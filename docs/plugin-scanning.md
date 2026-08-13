# Plugin Scanning

Sage scans other installed plugins for threats at every session start. Each plugin's files are run through the same threat definitions and URL checks used for runtime tool interception, and any skill packages (bundled with a plugin or installed as personal skills) are checked against the Sage skill-check service.

## Skill Checking and Upload

Discovered skills are first checked by content-addressed **skill ID** (no content leaves the machine). When a skill is **unknown** to the backend and `skill_check.upload_enabled` is enabled (the default), its contents — `SKILL.md` and the files/scripts inside the skill's own folder — are uploaded to a Gen Digital analysis service for a verdict. Uploads are deduplicated by skill ID (each unknown skill is uploaded at most once), path/symlink containment is enforced during packaging (only files inside the skill's own directory are included), and verdicts arrive asynchronously and surface on a later session.

**These uploads may include personal skills you authored, which can contain arbitrary personal information.** See [Privacy › What Data Is Sent](user-guide.md#what-data-is-sent) for the full disclosure, and [`skill_check`](user-guide.md#skill_check) to switch to lookup-only mode (`upload_enabled: false`) or disable skill checking entirely.

## Where Sage Looks

Sage discovers two kinds of things to scan on each host: **plugins/extensions** (the host's own extension mechanism) and **loose skill packages** (any folder containing a `SKILL.md`). The skill locations follow each host's own documented conventions, so Sage scans the same paths the agent itself loads from — nothing more. Directories that don't exist are skipped silently, and discovery fails open (a per-root error is skipped rather than blocking the session).

Paths use `~` for the user profile. **Personal** roots live under the user profile (shared across projects); **project** roots live inside the open workspace/project directory. Each table links the upstream documentation for the skill paths so you can confirm Sage looks where the host actually loads from.

### Claude Code

| Kind | Location |
|------|----------|
| Plugins | `~/.claude/plugins/installed_plugins.json` |
| Skills (personal) | `~/.claude/skills/` |
| Skills (project) | `<project>/.claude/skills/` |

Documentation: <https://code.claude.com/docs/en/skills>

### Cursor

| Kind | Location |
|------|----------|
| Extensions | `~/.cursor/extensions/` |
| Skills (personal) | `~/.cursor/skills/`, `~/.agents/skills/`, `~/.claude/skills/`, `~/.codex/skills/` |
| Skills (project) | `<workspace>/.cursor/skills/`, `<workspace>/.agents/skills/`, `<workspace>/.claude/skills/`, `<workspace>/.codex/skills/` |

Documentation: <https://cursor.com/docs/skills>

### VS Code (GitHub Copilot)

| Kind | Location |
|------|----------|
| Extensions | `~/.vscode/extensions/` |
| Skills (personal) | `~/.copilot/skills/`, `~/.claude/skills/`, `~/.agents/skills/` |
| Skills (project) | `<workspace>/.github/skills/`, `<workspace>/.claude/skills/`, `<workspace>/.agents/skills/` |

Documentation: <https://code.visualstudio.com/docs/agent-customization/agent-skills>

### OpenClaw

| Kind | Location |
|------|----------|
| Extensions | `~/.openclaw/extensions/` |
| Skills (personal) | `~/.agents/skills/`, `~/.openclaw/skills/` |

Documentation: <https://docs.openclaw.ai/tools/skills>

**Known limitation:** OpenClaw documents six skill sources by priority: (1) `<workspace>/skills`, (2) `<workspace>/.agents/skills`, (3) `~/.agents/skills`, (4) `~/.openclaw/skills`, (5) bundled skills, (6) extra dirs + plugin skills. Sage scans the two personal roots (3) and (4), plus plugin-embedded skills via the extension scan above (6). The **workspace-relative roots (1) and (2) are not scanned** — the OpenClaw plugin API never hands the plugin a workspace path (scan events take no arguments; tool context exposes only a session key). Bundled skills (5) sit inside the trusted install.

### OpenCode

| Kind | Location |
|------|----------|
| npm plugins | listed in `~/.config/opencode/opencode.json` (global) and `<project>/opencode.json` (project); resolved from `~/.cache/opencode/node_modules/` |
| Local plugins | `~/.config/opencode/plugins/` (global) and `<project>/.opencode/plugins/` (`.js`/`.ts` files) |
| Skills (personal) | `~/.config/opencode/skills/`, `~/.claude/skills/`, `~/.agents/skills/` |
| Skills (project) | `<project>/.opencode/skills/`, `<project>/.claude/skills/`, `<project>/.agents/skills/` |

Documentation: <https://opencode.ai/docs/skills/>

> **Why multiple families per host?** Editors increasingly load skills from several vendors' conventions at once (a host's own `.<host>/skills`, plus Claude's `.claude/skills` and the cross-agent `.agents/skills`). Sage scans every load path the host honors so a malicious skill can't hide in a compatibility directory.

## How It Works

1. At session start, Sage reads the list of installed plugins
2. Each plugin's source files are scanned against threat definitions
3. URLs found in plugin code are checked against URL reputation
4. Results are cached locally and only re-checked when a plugin changes
5. Findings are logged to the audit log with `type: "plugin_scan"`

## Audit Log Entry

```json
{
  "type": "plugin_scan",
  "timestamp": "2026-02-09T10:30:00Z",
  "plugin_key": "example-plugin@marketplace",
  "findings_count": 1,
  "findings": [
    {
      "threat_id": "CLT-CMD-001",
      "title": "Pipe to shell",
      "severity": "warning",
      "confidence": 0.9,
      "artifact": "curl ... | bash",
      "source_file": "setup.sh"
    }
  ]
}
```

> **Note:** Claude Code does not currently provide a hook for plugin installation events. The session-start approach ensures all plugins are scanned before each session begins.

## OpenCode-specific behavior

- **Trigger:** scan runs on the first `session.updated` event per session and is deduplicated by session ID
- **Cache:** results are stored at `~/.sage/plugin_scan_cache.json` and reused until a plugin's content changes
- **Self-protection:** Sage skips its own package (`@gendigital/sage-opencode`) when enumerating plugins
- **Findings surfacing:** any findings are injected as a `<system-reminder>` into the first user message of the session so the agent surfaces them to the user; nothing is appended to system prompts or assistant turns
