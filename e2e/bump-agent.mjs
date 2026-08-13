// Surgically bump one agent's pinned version in e2e/agents.json, used by the weekly drift
// actuator in CI for the auto-bump-pr / review-pr routing actions. Keyed on
// agent + the current (pinned) version so ONLY that agent's version string changes — agents.json
// formatting (tabs, inline `channel` objects) is preserved with no JSON reflow, keeping the
// bump PR's diff to a single line. Fails loudly if the agent's pinned value isn't what's
// expected (safety: the file isn't where the routing decision thought it was).
//
// Usage: node e2e/bump-agent.mjs <agent> <pinned> <resolved> [agents.json path]
// The optional path overrides the default (e2e/agents.json) — used by the unit test.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [, , agent, pinned, resolved, fileArg] = process.argv;
if (!agent || !pinned || !resolved) {
	process.stderr.write("usage: node e2e/bump-agent.mjs <agent> <pinned> <resolved> [path]\n");
	process.exit(2);
}

const file = fileArg || join(dirname(fileURLToPath(import.meta.url)), "agents.json");
const text = readFileSync(file, "utf8");

// Validate against the parsed structure FIRST: confirm THIS agent's version is exactly
// `pinned`. Without this, a plain text indexOf for `"version": "<pinned>"` after the agent
// key would land on a LATER agent's block if the target agent's version differs but some
// other agent happens to carry `<pinned>` — silently bumping the wrong agent. (We still do
// the surgical text edit below to preserve formatting; the parse is only the guard + locator.)
const data = JSON.parse(text);
const current = data[agent]?.version;
if (current === undefined) {
	process.stderr.write(`bump-agent: no "${agent}" agent in ${file}\n`);
	process.exit(1);
}
if (current !== pinned) {
	process.stderr.write(
		`bump-agent: "${agent}" version is "${current}", not the expected pinned "${pinned}" — refusing to bump (the routing decision is stale or names the wrong agent)\n`,
	);
	process.exit(1);
}

// Now that the agent's version is confirmed == pinned, the first `"version": "<pinned>"`
// at/after the agent key is that agent's own line (version is the first field in the block).
const key = `"version": "${pinned}"`;
const at = text.indexOf(key, text.indexOf(`"${agent}"`));
if (at < 0) {
	process.stderr.write(`bump-agent: no ${key} for "${agent}" in ${file}\n`);
	process.exit(1);
}
writeFileSync(file, text.slice(0, at) + `"version": "${resolved}"` + text.slice(at + key.length));
process.stdout.write(`bumped ${agent}: ${pinned} -> ${resolved}\n`);
