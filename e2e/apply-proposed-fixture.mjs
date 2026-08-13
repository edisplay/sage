// Applies a `latest`-mode drift run's regenerated fixture candidate(s) onto the real committed
// fixture(s) for one agent — the review-pr half the weekly drift actuator runs. Each connector
// suite writes its candidate under e2e/output/proposed/<agent>/<same path its real fixture has,
// relative to the repo root> — so applying it is just "copy that subtree onto the repo root."
// No per-agent table: the directory structure alone says which agent a candidate belongs to and
// where it goes, so nothing needs to be kept in sync when a new connector is added beyond the
// one line it already needs for its own fixture path.
//
// Pure file mutation + stdout, same convention as bump-agent.mjs: no git here. Recursively
// copies every file under e2e/output/proposed/<agent>/ to the same relative path under the repo
// root (byte-for-byte — fixtures are already tab-indented JSON in the right format) and prints
// each destination (repo-root-relative) to stdout, one per line, for the caller to `git add`.
//
// Fails loud (exit 1) if the agent has zero candidates: review-pr is only ever routed when a
// candidate was written, so finding none — whether from a genuine inconsistency or a
// misspelled/unknown agent name — is always worth failing on; the error names the exact path it
// looked under either way. Also fails loud if a candidate's destination directory doesn't exist
// (a stale repo-relative path, e.g. after a fixture directory move).
//
// Usage: node e2e/apply-proposed-fixture.mjs <agent> [proposedDir] [repoRoot]
// The two optional overrides mirror bump-agent.mjs's convention — used by the unit test to
// redirect both roots to temp dirs so the real committed fixtures are never touched.
import { copyFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const [, , agent, proposedDirArg, repoRootArg] = process.argv;
if (!agent) {
	process.stderr.write("usage: node e2e/apply-proposed-fixture.mjs <agent> [proposedDir] [repoRoot]\n");
	process.exit(2);
}

const HERE = dirname(fileURLToPath(import.meta.url));
const repoRoot = repoRootArg || join(HERE, "..");
const proposedDir = proposedDirArg || join(HERE, "output", "proposed");
const agentDir = join(proposedDir, agent);

// Manual recursive walk: fs.readdirSync's own `recursive` option needs Node 20.1+, but this
// repo's engines floor is >=18.
function collectFiles(dir, base) {
	if (!existsSync(dir)) return [];
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		// Never follow: a symlink here could point outside the sandboxed proposed dir, and
		// copyFileSync follows symlinks when reading — this is untrusted live-capture output.
		if (entry.isSymbolicLink()) {
			process.stderr.write(`apply-proposed-fixture: skipping symlink ${join(dir, entry.name)} — untrusted proposed output\n`);
			continue;
		}
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...collectFiles(full, base));
		else out.push(relative(base, full));
	}
	return out;
}

// Belt-and-suspenders: the walk above can't actually produce an escaping path (POSIX directory
// entries can't contain "/" or be "..", so relative(base, full) can never leave `base`), but
// assert it anyway rather than trust that invariant silently forever.
function escapesRoot(rel) {
	return isAbsolute(rel) || rel.split(sep).includes("..");
}

const relFiles = collectFiles(agentDir, agentDir);
if (relFiles.length === 0) {
	process.stderr.write(
		`apply-proposed-fixture: found no regenerated fixture candidates for "${agent}" under ${agentDir} — ` +
			"review-pr is only routed when a candidate was written, so this is a real inconsistency.\n",
	);
	process.exit(1);
}

for (const rel of relFiles) {
	if (escapesRoot(rel)) {
		process.stderr.write(`apply-proposed-fixture: refusing to apply "${agent}"/${rel} — escapes the repo root\n`);
		process.exit(1);
	}
	const destPath = join(repoRoot, rel);
	if (!existsSync(dirname(destPath))) {
		process.stderr.write(
			`apply-proposed-fixture: destination dir ${dirname(destPath)} doesn't exist for "${agent}"/${rel} — the proposed-path convention may be stale\n`,
		);
		process.exit(1);
	}
	copyFileSync(join(agentDir, rel), destPath);
	// Emit POSIX-style separators so the output is identical across platforms and
	// feeds straight into `git add` (git uses forward slashes everywhere).
	const relPosix = rel.split(sep).join("/");
	process.stdout.write(`${relPosix}\n`);
	process.stderr.write(`apply-proposed-fixture: ${agent}: ${relPosix}\n`);
}
