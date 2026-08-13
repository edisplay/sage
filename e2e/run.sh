#!/usr/bin/env bash
#
# Sage E2E runner (Layer 2). Builds the current-branch Sage on the host, builds
# the pinned agent image, then runs the agent's vitest E2E suite in CONTAINER
# mode. Identical entry point locally and in CI (only secret injection and the
# open-PR step differ).
#
#   e2e/run.sh [claude|copilot|opencode|cursor|openclaw|vscode|all]   (default: claude)
#
# Prereqs: Docker, and e2e/.env holding the agent's auth (copy .env.example):
#   claude/opencode/openclaw → Vertex ADC vars; copilot → GITHUB_TOKEN;
#   cursor → CURSOR_API_KEY (Cursor's own backend, not Vertex).
#   openclaw additionally needs OPENCLAW_IMAGE (the gateway image to build FROM).
#   vscode → none (wiring-only Extension Host under Xvfb; no model/auth — see README).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
AGENT="${1:-claude}"
case "$AGENT" in
claude | copilot | opencode | cursor | openclaw | vscode | all) ;;
*)
	echo "error: unknown agent '$AGENT' (expected: claude|copilot|opencode|cursor|openclaw|vscode|all)" >&2
	exit 2
	;;
esac
# Drift-diff mode: `pinned` fails on drift (PR/local default); `latest`
# also writes the regenerated fixture to output/proposed/ for review (the bump-PR
# step itself is CI-only). Override: `SAGE_E2E_MODE=latest e2e/run.sh`.
SAGE_E2E_MODE="${SAGE_E2E_MODE:-pinned}"

if [ ! -f "$HERE/.env" ]; then
	echo "error: missing $HERE/.env — copy e2e/.env.example and fill it in" >&2
	exit 1
fi

# Load local config/secrets (BASE_IMAGE, Vertex project/region, per-agent tokens).
# Container mode authenticates via Vertex ADC — no ANTHROPIC_API_KEY is used here (native
# mode is the exception; see e2e/README.md). BASE_IMAGE keeps the registry host out of
# version control; it is required for the build.
set -a
# shellcheck disable=SC1091
. "$HERE/.env"
set +a
: "${BASE_IMAGE:?set BASE_IMAGE in e2e/.env (the base Node.js image to build from)}"

# Run bind-mount-writing agents (opencode) as the host user so files in the mounted
# HOME (~/.sage, scan cache) are host-owned — the suite reads AND deletes them.
export SAGE_E2E_UID="$(id -u)"
export SAGE_E2E_GID="$(id -g)"

# Read a pinned agent version from agents.json (e.g. `agent_version claude`).
agent_version() {
	node -e "process.stdout.write(require('$HERE/agents.json')['$1'].version)"
}

# The version to actually build. `pinned` mode → agents.json. `latest` mode → newest
# stable resolved host-side from the agent's channel (resolve-version.mjs), falling back
# to the pinned version (with a warning) if resolution fails — one flaky endpoint must
# not abort the weekly all-agents run (fail-open, matching Sage's convention).
resolved_version() {
	local agent="$1" pinned="$2" resolved
	if [ "$SAGE_E2E_MODE" != latest ]; then
		echo "$pinned"
		return
	fi
	if resolved="$(node "$HERE/resolve-version.mjs" "$agent")"; then
		echo "$resolved"
	else
		echo ">> latest: $agent — resolve failed, falling back to pinned $pinned" >&2
		echo "$pinned"
	fi
}

# Build the shared base image. Idempotent (docker layer cache); built once per
# invocation (the dispatcher below), so `all` doesn't rebuild it per agent.
build_base() {
	echo ">> building base image (sage-e2e-base:latest)"
	docker build -f "$HERE/Dockerfile.base" --build-arg "BASE_IMAGE=$BASE_IMAGE" -t sage-e2e-base:latest "$HERE"
}

# Build current-branch Sage on the host ONCE, before any suite — same steps as vitest's
# globalSetup but run OUTSIDE the vitest process tree. Required locally where endpoint
# security software kills the in-vitest build tree mid-run; run_suite then sets SAGE_E2E_SKIP_BUILD=1 so
# globalSetup is a no-op (build happens exactly once). The container bind-mounts this dist.
# It also guarantees @gendigital/sage-core's dist (its first step) for route.mjs, which the
# build-alarm path (route_build_failed) needs even when an agent's suite never ran.
build_sage() {
	echo ">> building current-branch Sage (host, outside vitest)"
	( cd "$REPO_ROOT" && node scripts/build-e2e.mjs )
}

# output/capture is the writable bind mount agents write hook captures to (must
# exist before compose mounts it); output/proposed receives the regenerated
# fixture in `latest` mode; output/routing receives the per-agent routing decision
# (route.mjs) the weekly CI job acts on. All of output/ is gitignored.
ensure_output_dirs() {
	mkdir -p "$HERE/output/capture" "$HERE/output/proposed" "$HERE/output/routing" \
		"$HERE/output/copilot-plugin" "$HERE/output/copilot-sage" "$HERE/output/opencode-home" \
		"$HERE/output/cursor-home" "$HERE/output/openclaw-home/.openclaw/extensions" \
		"$HERE/output/vscode-home"
}

# The version resolved for the in-flight agent, stashed by build_agent so the post-suite
# routing (route_latest) can compare it against the pin. Agents build+run sequentially,
# so this is fresh per agent even under `all`.
LATEST_RESOLVED=""

# Build one agent's image (base must exist). The compose build arg is the uppercased
# <AGENT>_VERSION (CLAUDE_VERSION / COPILOT_VERSION), which also tags the image — so
# overriding it for `latest` mode needs no compose change.
build_agent() {
	local agent="$1" pinned version
	pinned="$(agent_version "$agent")"
	version="$(resolved_version "$agent" "$pinned")"
	LATEST_RESOLVED="$version"
	export "$(echo "$agent" | tr '[:lower:]' '[:upper:]')_VERSION=$version"
	if [ "$SAGE_E2E_MODE" = latest ]; then
		echo ">> latest: $agent resolved $version (pinned $pinned)"
		# Clear this agent's stale proposals so post-suite shape-change detection is fresh.
		# Each suite writes its candidate(s) under output/proposed/<agent>/ (mirroring the
		# committed fixture's own repo-relative path), so clearing is scoped to just this
		# agent's subtree — no risk of touching another agent's pending candidate.
		# Fail loudly if the clear fails: build_agent runs under `if build_agent` (errexit off),
		# so a silently-surviving stale fixture would set shapeChanged=true and mis-route to
		# review-pr. A clear failure here is a local-env problem (permission/corruption) that
		# would recur every time, not the per-agent transient flake the latest-mode fail-open
		# absorbs — so abort the whole run rather than emit a mislabeled route.
		rm -rf "$HERE/output/proposed/$agent" || {
			echo ">> FATAL: could not clear $HERE/output/proposed/$agent — check permissions; aborting run" >&2
			exit 1
		}
	fi
	echo ">> building $agent agent image ($agent@$version)"
	docker compose -f "$HERE/compose.yml" build "$agent"
}

# True if the agent's JUnit report records at least one test. A 0-test run is a silent skip
# (e.g. SAGE_E2E_RUNNER not 'container', so every describe.skipIf bailed) — the caller fails.
tests_ran() {
	local xml="$HERE/output/$1-e2e.xml" n
	[ -f "$xml" ] || return 1
	n="$(grep -oE 'tests="[0-9]+"' "$xml" | head -1)" # first <testsuites tests="N">
	n="${n//[^0-9]/}"                                 # strip to the integer (portable; no 2nd grep)
	[ "${n:-0}" -gt 0 ]
}

# Run one agent's E2E suite in container mode (base + image + dirs must exist).
# vitest's globalSetup builds current-branch Sage on the host before any test, so
# the container reads fresh bind-mounted dist — even uncommitted changes run.
#
# In `latest` mode this never aborts: the suite's pass/fail is a routing signal, not a
# gate, so we capture it, print the would-be routing decision (route_latest), and return
# 0 so the all-agents run continues. In `pinned` mode the exit code propagates (PR gate).
run_suite() {
	local agent="$1" script="$2" rc=0
	echo ">> running $agent E2E suite in container mode (SAGE_E2E_MODE=$SAGE_E2E_MODE)"
	# Remove any stale JUnit from a prior run so tests_ran below validates ONLY this run's
	# report. Without this, a run that exits 0 but emits no fresh file (e.g. reporter/config
	# drift) would let tests_ran read the old report and mask a silent 0-test skip.
	rm -f "$HERE/output/$agent-e2e.xml"
	# Reporters/outputFile come from vitest.e2e.config.ts via SAGE_E2E_JUNIT (NOT CLI flags —
	# see the config for why `pnpm <script> -- --reporter=junit` silently writes nothing).
	( cd "$REPO_ROOT" && SAGE_E2E_RUNNER=container SAGE_E2E_MODE="$SAGE_E2E_MODE" SAGE_E2E_SKIP_BUILD=1 \
		SAGE_E2E_JUNIT="$HERE/output/$agent-e2e.xml" \
		pnpm "$script" ) || rc=$?
	# Loud-fail a silent skip: SAGE_E2E_RUNNER is always `container` here, so a 0-test run
	# means every describe.skipIf misfired (or the suite is empty). Treat it as a failure —
	# in pinned mode it fails the PR gate; in latest mode route_latest routes it as a red suite.
	if [ "$rc" -eq 0 ] && ! tests_ran "$agent"; then
		echo ">> ERROR: $agent E2E reported 0 tests run (SAGE_E2E_RUNNER misconfigured or suite empty)" >&2
		rc=1
	fi
	if [ "$SAGE_E2E_MODE" = latest ]; then
		route_latest "$agent" "$rc"
		return 0
	fi
	return "$rc"
}

# Dry-run of the weekly drift routing for one `latest`-mode agent: feed the three signals
# (resolved-vs-pinned, suite green/red, envelope shape changed) to route.mjs, which prints
# the action CI would take. No PR/notification locally — just the decision.
route_latest() {
	local agent="$1" rc="$2" green shaped
	[ "$rc" -eq 0 ] && green=true || green=false
	# Candidates now nest under output/proposed/<agent>/ (mirroring the fixture's own path),
	# so a flat `ls *.json` wouldn't see them — check recursively, scoped to this agent.
	if find "$HERE/output/proposed/$agent" -type f 2>/dev/null | grep -q .; then shaped=true; else shaped=false; fi
	node "$HERE/route.mjs" "$agent" "$(agent_version "$agent")" "$LATEST_RESOLVED" "$green" "$shaped" false
}

# A `latest`-mode build that never produced an image: the suite never ran, so route a
# build-alarm (buildFailed=true short-circuits the suite/shape signals). build_agent sets
# LATEST_RESOLVED before the build attempt, so the alarm still names resolved-vs-pinned.
route_build_failed() {
	local agent="$1"
	node "$HERE/route.mjs" "$agent" "$(agent_version "$agent")" "$LATEST_RESOLVED" false false true
}

# Build one agent and run its suite. In `latest` mode this is fail-open end to end: a build
# failure becomes a build-alarm and the run continues to the next agent (the weekly job must
# survive one agent's flaky install/mirror); run_suite already fail-opens the suite result.
# In `pinned` mode (the PR gate) `set -e` lets either a build or a suite failure abort.
run_agent() {
	local agent="$1" script="$2"
	if [ "$SAGE_E2E_MODE" = latest ]; then
		# `if build_agent` disables set -e inside it, so a failed docker build is captured
		# here as a routing signal instead of aborting the whole run.
		if build_agent "$agent"; then
			run_suite "$agent" "$script"
		else
			echo ">> latest: $agent — BUILD FAILED at ${LATEST_RESOLVED:-?} (pinned $(agent_version "$agent"))" >&2
			route_build_failed "$agent"
		fi
		return 0
	fi
	build_agent "$agent"
	run_suite "$agent" "$script"
}

# copilot's pnpm e2e script is "copilot-cli" (the others match the agent name).
run_claude() {
	run_agent claude test:e2e:claude
}
run_copilot() {
	run_agent copilot test:e2e:copilot-cli
}
run_opencode() {
	run_agent opencode test:e2e:opencode
}
run_cursor() {
	run_agent cursor test:e2e:cursor
}
# OpenClaw is a long-lived gateway, not a one-shot CLI: build the pinned image here,
# but the vitest suite owns the gateway lifecycle (compose up -d → poll /health →
# drive → down) in container mode, so run_agent stays symmetric with the others.
run_openclaw() {
	# Fail-open in latest mode: a missing OPENCLAW_IMAGE must route a per-agent build-alarm and
	# let the all-agents run continue — not abort it (set -e) before the next agent. In pinned
	# mode (the PR gate) it stays a hard error.
	if [ -z "${OPENCLAW_IMAGE:-}" ]; then
		if [ "$SAGE_E2E_MODE" = latest ]; then
			LATEST_RESOLVED="$(agent_version openclaw)"
			echo ">> latest: openclaw — OPENCLAW_IMAGE unset; routing build-alarm and continuing" >&2
			route_build_failed openclaw
			return 0
		fi
		echo "error: set OPENCLAW_IMAGE in e2e/.env (the OpenClaw image to build FROM, no tag)" >&2
		exit 1
	fi
	run_agent openclaw test:e2e:openclaw
}
# VS Code is wiring-only (Extension Host under Xvfb): the image carries VS Code + Xvfb,
# the suite drives the Sage dev extension in-container and writes results back. No model
# or auth — so no secret prerequisites (unlike the other agents).
run_vscode() {
	run_agent vscode test:e2e:vscode
}

# Shared one-time setup, then dispatch (base image + output dirs built once).
# openclaw is FROM the official OpenClaw image, not sage-e2e-base, so an openclaw-only
# run skips the base build (it's still needed for `all`, which includes the others).
[ "$AGENT" = openclaw ] || build_base
ensure_output_dirs
# Build host Sage once, outside vitest (see build_sage); run_suite sets SAGE_E2E_SKIP_BUILD=1.
# This also satisfies route.mjs's need for core's dist in `latest` mode (incl. the build-alarm
# path for an agent whose suite never ran), since build_sage builds core first.
build_sage
case "$AGENT" in
claude)
	run_claude
	;;
copilot)
	run_copilot
	;;
opencode)
	run_opencode
	;;
cursor)
	run_cursor
	;;
openclaw)
	run_openclaw
	;;
vscode)
	run_vscode
	;;
all)
	run_claude
	run_copilot
	run_opencode
	run_cursor
	run_openclaw
	run_vscode
	;;
esac
