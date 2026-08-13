# Sage E2E (Layer 2 — containerized live agents)

Runs the **real** agent CLIs with the **current-branch** Sage (bind-mounted as a plugin)
inside containers, to verify the three things a deterministic contract test can't:

1. **Wiring** — the host fires Sage's hook and honors a `deny` verdict.
2. **Tool-name drift** — the agent's advertised tools still cover every name Sage guards.
3. **Payload drift** — the hook payload the host sends still matches the committed Layer 1 fixture.

The test runner is vitest on the host (`packages/<agent>/src/__tests__/e2e.test.ts`); the
container is only the agent sandbox. These suites are gated on `SAGE_E2E_RUNNER`, set to
either `container` (this file's main focus — via `run.sh`) or `native` (no Docker — see "Run
natively" below; wiring-only, no drift/tool-catalog checks, and no `openclaw`). The Cursor/VS
Code desktop Extension Host (Layer 3) is a separate case — it runs against an installed GUI
binary via `pnpm test:e2e:cursor` / `:vscode`. For the layer model and rationale, see the
**E2E architecture** section of `docs/developer-guide.md`.

## Prerequisites

- Docker (with `docker compose`) and `pnpm` on the host.
- `e2e/.env` — copy `e2e/.env.example` and fill it in. Requires `BASE_IMAGE` (the base
  Node.js image to build from; the registry host is kept out of VCS) plus the per-agent
  auth below.

## Run

```bash
cp e2e/.env.example e2e/.env
e2e/run.sh claude        # one agent
e2e/run.sh all           # every agent
```

`run.sh` builds the base + agent image, then runs the suite in container mode (vitest's
`globalSetup` builds current-branch Sage first). JUnit + artifacts land in `e2e/output/`
(gitignored).

| Agent | `e2e/run.sh` | Auth in `e2e/.env` |
|-------|--------------|--------------------|
| Claude Code | `claude` | Vertex ADC |
| OpenCode | `opencode` | Vertex ADC |
| OpenClaw | `openclaw` | Vertex ADC + `OPENCLAW_IMAGE` (the gateway image to build FROM) |
| Copilot CLI | `copilot` | `GITHUB_TOKEN` (or `GH_TOKEN` / `COPILOT_GITHUB_TOKEN`) |
| Cursor (`agent` CLI) | `cursor` | `CURSOR_API_KEY` |
| VS Code (Xvfb) | `vscode` | none |

### Vertex ADC (claude, opencode, openclaw)

Set in `e2e/.env`: `CLAUDE_CODE_USE_VERTEX=1`, `ANTHROPIC_VERTEX_PROJECT_ID`,
`CLOUD_ML_REGION`, and the `ANTHROPIC_DEFAULT_*_MODEL` overrides (full Vertex model ids — the
`haiku` alias doesn't resolve on Vertex). Locally, set `SAGE_E2E_GCP_ADC` to your gcloud ADC
file (mounted read-only); in CI on a GCE VM leave it unset (the build agent's attached
service account is picked up from the metadata server).

> The container must reach the GCE metadata server (`169.254.169.254`) — fine on a GCE VM
> with default networking; otherwise use host networking or a mounted short-lived key.

## Run natively (no Docker)

The same claude/opencode/cursor/copilot suites also run directly against an already-installed
binary — useful for fast local iteration or a machine without Docker/WSL2 (e.g. bare
Windows). `openclaw` has no native path — it's a gateway image, not a standalone binary.

```bash
SAGE_E2E_RUNNER=native pnpm test:e2e:claude
SAGE_E2E_RUNNER=native pnpm test:e2e:opencode
SAGE_E2E_RUNNER=native pnpm test:e2e:cursor
SAGE_E2E_RUNNER=native pnpm test:e2e:copilot-cli
```

**Prerequisites:** the CLI installed and already authenticated exactly as you'd normally use
it — no `e2e/.env`, no Vertex setup. Each suite resolves the binary from PATH (or an env
override — `SAGE_CLAUDE_PATH`, `SAGE_OPENCODE_PATH`/`OPENCODE_E2E_BIN`,
`SAGE_CURSOR_AGENT_PATH`/`SAGE_AGENT_PATH`, `SAGE_COPILOT_PATH`) and skips cleanly with a
`console.warn` if it isn't found.

**Isolation + auth:** every run is isolated to a fresh temp `HOME` (never your real `~/.sage`,
`~/.cursor`, `~/.copilot`) while reusing your ambient login — each connector copies forward
only the specific auth file it needs (opencode's `~/.config/opencode/model.json`, copilot's
`~/.copilot/config.json`) rather than the whole real `HOME`. Cursor and copilot also always
symlink the real `~/Library` into the isolated HOME on macOS, regardless of any env-var key —
both touch the keychain unconditionally (cursor for its own session bookkeeping; copilot to
resolve the token behind the copied config's logged-in-user reference). Without `~/Library`,
cursor pops a "Keychain Not Found" dialog, and copilot falls back to inferring the GitHub host
from the current repo's git remote — which fails outright if that remote is an internal GHE
mirror rather than github.com (confirmed on an internally-mirrored repo). **claude is the
exception**: if `~/.claude/.credentials.json` doesn't exist
(auth lives in the OS keychain instead — common on macOS), the suite falls back to running
against your **real** `~/.claude` rather than an isolated one, since a keychain-based session
can't be relocated to a temp HOME. Prefer env-var auth (`ANTHROPIC_API_KEY`, Vertex, or your
usual corporate proxy vars — all pass through either way) if you want full isolation.

**Known limitation — claude + an already-installed Sage plugin:** if `claude` already has
Sage installed from the plugin marketplace (likely, if you use Sage day-to-day) **and**
enterprise/managed settings pin the plugin list, Claude Code silently ignores `--plugin-dir`
and loads the cached marketplace version instead of your current branch — confirmed on a
managed install, reproducible with a bare `claude --plugin-dir <repo> ...` outside this suite
entirely. This is a Claude Code policy decision, not something Sage's test code can work
around. The native claude suite detects this (`plugin_errors` on the `system/init` message)
and fails loudly with an explicit message rather than silently testing the wrong plugin
version — if you hit it, native claude E2E isn't usable on that machine; container mode is
unaffected (its image has no pre-installed marketplace plugin to conflict with).

**Scope:** native mode covers the wiring assertions (benign-allow + canary-deny) only — the
drift-diff and tool-catalog-drift checks below stay container-only, since the capture sink
they read from (`SAGE_E2E_CAPTURE_DIR`) is never wired up outside a container. No version
pinning either — native mode runs whatever version you have installed, unlike the pinned
Docker images.

**Windows:** this is the first Windows-facing E2E code path in this project — no Windows E2E
CI exists for any layer today (including the desktop GUI Layer 3). Verify locally on Windows
before relying on it there; the CLI-spawn path uses `shell: true` on `win32` (the
CVE-2024-27980-aware pattern already used in `packages/core/src/clients/pi-deps-installer.ts`)
with a `cmd.exe` fallback for edge cases.

## Modes

`SAGE_E2E_MODE` (default `pinned`):

- `pinned` — build at the `agents.json` version and fail on drift (PR gate / local default).
- `latest` — resolve the newest stable version host-side, build at it, and **route** the
  outcome (fail-open per agent) instead of gating. Writes `e2e/output/proposed/<…>.json` (a
  regenerated fixture candidate, on additive shape change) and `e2e/output/routing/<agent>.json`
  (the `classifyDrift` decision). The weekly CI job consumes the routing artifacts to
  open bump/review PRs or raise alarms; locally it just writes the files and prints the decision.

## CI

`run.sh` is the single entry point — CI calls it directly rather than through
`pnpm test:e2e:*`.

### Builds

| Build | Trigger | Mode | Agents |
|-------|---------|------|--------|
| `E2E: <agent>` (six builds) | every PR (default branch + `pull/*`) | `pinned` | one per build |
| `E2E weekly drift (latest)` | Monday 09:00, every week | `latest` | all six |

Both run on bare VM build agents (Docker + host node/pnpm — no Docker image wrapping the
build step itself). CI writes `e2e/.env` from its own configuration parameters (never
reading the repo file), then calls `e2e/run.sh`.

### Weekly drift job

1. Bootstraps node/pnpm on the bare agent, then `pnpm install`.
2. Writes `e2e/.env` from CI parameters (registry, Vertex project, model aliases, secrets).
3. Sets `SAGE_E2E_MODE=latest` and runs `e2e/run.sh all` — resolves + builds + runs all six agents.
4. Reads the six `e2e/output/routing/<agent>.json` artifacts and acts on each:
   - `steady` — nothing.
   - `auto-bump-pr` — creates branch `e2e/bump-<agent>-<resolved>`, commits `agents.json` bump,
     opens a PR, and enables auto-merge (the PR gate at pinned mode is what actually confirms it).
   - `review-pr` — bumps `agents.json` too if `resolved != pinned`, applies the regenerated
     fixture candidate(s) from `e2e/output/proposed/` onto their committed path via
     `node e2e/apply-proposed-fixture.mjs <agent>`, commits whatever changed, opens a PR
     labelled `needs-human-review` (no auto-merge — a human reviews the fixture diff).
   - `drift-alarm / infra-alarm / build-alarm` — logs the alarm and exits 1 after all agents run.

A build failure inside `run.sh` (the image never built) is fail-open: routed as `build-alarm`
so the run continues to the remaining agents rather than aborting.

### Secrets and params

Non-secret values (`BASE_IMAGE`, the Vertex project, model aliases, `NPM_REGISTRY`,
`OPENCLAW_IMAGE`, `VSCODE_APT_MIRROR`) are plain CI configuration parameters. Two secrets
are stored in the CI secret store:

| Secret | What |
|--------|------|
| Cursor API key | Cursor backend API key (Cursor uses its own backend, not Vertex) |
| Copilot GitHub token | GitHub token with a Copilot entitlement (distinct from the CI bot's token) |

Vertex auth (claude, opencode, openclaw) uses the build agent's attached GCE service account
via the metadata server — no key file needed in CI. A separate CI bot GitHub token is used
for commit-status publishing on the PR gate builds and for opening bump/review PRs from the
weekly job.

## What the suite checks

**Tool-catalog drift** — where a host lists its tools without a model in the loop, the suite
diffs that catalog against Sage's guarded set (fails if a guarded name vanished, warns on new
ones). Only Claude Code exposes one; the rest fall back to a per-tool-name canary matrix plus
the deterministic `tool-names-contract` pin:

| Agent | Model-free catalog |
|-------|--------------------|
| Claude Code | Yes — `system/init.tools` in `stream-json` |
| Copilot CLI / OpenCode / Cursor | No — live per-name matrix + `tool-names-contract` pin |
| VS Code | No — synthetic matrix + `tool-names-contract` pin (Copilot Chat can't load headless) |

**Payload drift** — the connector captures each hook payload (`SAGE_E2E_CAPTURE_DIR`, set only
inside the container) to `/capture` → `e2e/output/capture/`, namespaced per connector. The
suite structurally diffs the captured envelope (key set + value types — `tool_input` *contents*
are model-driven and not diffed) against the committed Layer 1 fixture: fails on a
missing/renamed field, warns on a new one, and value-pins `tool_name`.

## Adding a connector

Each connector's Layer 2 suite is its own file but shares the harness in
`@gendigital/sage-core/testing`. When you add an agent:

- **Tool-name map (Layer 1):** snapshot the connector's agent→canonical map (or guarded
  set) and pin it in a `tool-names-contract` test.
- **Envelope fixture (Layer 1):** commit the host's hook payload under
  `packages/<pkg>/src/__tests__/fixtures/contract/`.
- **Volatile fields:** each connector defines its own `*_VOLATILE_FIELDS` constant (e.g.
  `VOLATILE_ENVELOPE_FIELDS`, `COPILOT_VOLATILE_FIELDS`, `CURSOR_VOLATILE_FIELDS`) — the
  per-run-varying keys (session/conversation ids, timestamps, cwd) reset to the fixture's
  placeholders when a `latest`-mode candidate is written. A field that varies but is omitted
  surfaces as false drift.
- **Proposed-fixture path:** give the agent's `proposedPath` an `<agent>/` prefix followed by
  its fixture's own repo-relative path (e.g. `join(PROPOSED_DIR, "cursor", path.relative(REPO_ROOT,
  CURSOR_FIXTURE_PATH))`). The weekly actuator's `review-pr` step (`e2e/apply-proposed-fixture.mjs`)
  copies whatever exists under that subdirectory onto the same relative path from the repo root —
  no separate config to update.
- **Reuse the shared harness, don't re-roll it:** `composeRun` (one-shot `docker compose run`),
  `driveForFreshVerdict` (retry-until-fresh-deny, behind each `expectFreshDeny`),
  `resolveAuditPath`, `tolerantRm`, and `assertNoEnvelopeDrift` (the drift tail's
  fail-on-drift assertion). The routing brain is `classifyDrift` (unit-tested per row in
  `e2e-drift-routing.ts`). For a native-mode counterpart: `resolveExecutable`/`canExecute`
  (binary discovery + existence probe), `spawnNative` (the Windows-safe direct spawn),
  `createNativeHome` (isolated temp HOME lifecycle), and `resolveNativeAuditPath`.

## Implementation notes

- Sage is bind-mounted read-only at `/sage` and used as `--plugin-dir`; never baked into the image.
- opencode and cursor run as the host user with a bind-mounted HOME (`e2e/output/<agent>-home/`),
  so the host reads `~/.sage` back (audit log, scan cache) for full-parity asserts; claude and
  copilot captures land root-owned (host reads only).
- copilot and opencode keep HOME exec-able (image overlay or bind mount, not tmpfs).
- VS Code: the `@vscode/test-electron` `runTests()` runs in-container under Xvfb (as root,
  `--no-sandbox`); the host launches it and reads `vscode-results.json` back. It drives Sage's
  hook with synthetic canary payloads — no model, no auth. Real Copilot Chat drift is Layer 3.
