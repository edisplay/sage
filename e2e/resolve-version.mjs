// Host-side stable-version resolver for the Layer 2 `latest` mode.
// Resolves the newest stable release for a given agent from its distribution channel
// and prints it to stdout; run.sh feeds it back as the <AGENT>_VERSION build arg.
//
// Resolving on the host (not via @latest in the Dockerfile) prevents Docker from
// serving stale cached layers and gives run.sh the version for drift routing.
//
// Usage: node e2e/resolve-version.mjs <agent>  → prints version, exits non-zero on error.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const AGENTS = JSON.parse(readFileSync(join(HERE, "agents.json"), "utf8"));

const agent = process.argv[2];
const entry = AGENTS[agent];
if (!entry) {
	process.stderr.write(`resolve-version: unknown agent '${agent}'\n`);
	process.exit(2);
}

const channel = entry.channel ?? {};

const RESOLVE_TIMEOUT_MS = 30_000;

// Wraps fetch with an AbortController deadline covering both connection and body reads.
// `init` passes extra request options (e.g. an Authorization header for auth retries).
async function fetchWithTimeout(url, handleResponse, init = {}) {
	const controller = new AbortController();
	const id = setTimeout(() => controller.abort(), RESOLVE_TIMEOUT_MS);
	try {
		return await handleResponse(await fetch(url, { ...init, signal: controller.signal }));
	} finally {
		clearTimeout(id);
	}
}

// npm packages (claude/copilot/opencode): `dist-tags.latest` gives the stable release,
// honoring the ambient registry config — so a configured mirror is queried, not public npm.
function resolveNpm(pkg) {
	if (!pkg) throw new Error(`agent '${agent}' has channel.type=npm but no 'package'`);
	return execFileSync("npm", ["view", pkg, "dist-tags.latest"], {
		encoding: "utf8",
		timeout: RESOLVE_TIMEOUT_MS,
	}).trim();
}

// VS Code's update service returns stable builds newest-first; [0] is the latest.
async function resolveVsCodeStable() {
	return fetchWithTimeout(
		"https://update.code.visualstudio.com/api/releases/stable",
		async (res) => {
			if (!res.ok) throw new Error(`VS Code releases API: HTTP ${res.status}`);
			const versions = await res.json();
			const latest = Array.isArray(versions) ? versions[0] : undefined;
			if (typeof latest !== "string") throw new Error("VS Code releases API: unexpected shape");
			return latest;
		},
	);
}

// Cursor's install script is regenerated per release with the version hard-coded into
// the lab download URL (downloads.cursor.com/lab/<version>/…) — it is latest-only, so
// the embedded version IS the newest stable. Scrape it out.
async function resolveCursorInstall(url) {
	return fetchWithTimeout(url ?? "https://cursor.com/install", async (res) => {
		if (!res.ok) throw new Error(`cursor install script: HTTP ${res.status}`);
		const script = await res.text();
		const match = script.match(/lab\/(\d{4}\.\d{2}\.\d{2}-[\d-]+-[0-9a-f]+)\//);
		if (!match) throw new Error("cursor install script: no lab/<version>/ URL found");
		return match[1];
	});
}

// Docker-image agents (openclaw): resolve from the registry the Dockerfile builds FROM, not npm.
// Where the image is mirrored, it arrives only via a manual sync, so the buildable set of
// versions is exactly the registry's tags. npm can run ahead of those tags, producing false
// drift alarms.

// A tag we treat as a release: dot-separated numbers with an optional -<n> revision (2026.7.1,
// 2026.7.1-2). Excludes latest/nightly/rc/sha tags — the tag analogue of npm dist-tags.latest.
const RELEASE_TAG = /^\d+(?:\.\d+)*(?:-\d+)?$/;

// Numeric, component-wise tag compare (split on . and -, 0-fill the shorter). A trailing -<n>
// revision sorts ABOVE its base (2026.7.1-2 > 2026.7.1), matching how a republished revision is
// treated as newer. Returns <0 / 0 / >0, usable directly as an Array#sort comparator.
function compareTags(a, b) {
	const pa = a.split(/[.-]/).map(Number);
	const pb = b.split(/[.-]/).map(Number);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
		const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (diff !== 0) return diff;
	}
	return 0;
}

// Exchange a registry's WWW-Authenticate Bearer challenge for an anonymous pull token.
async function fetchBearerToken(challenge) {
	if (!challenge || !/^Bearer /i.test(challenge)) {
		throw new Error(`unexpected auth challenge: ${challenge ?? "(none)"}`);
	}
	const params = {};
	for (const m of challenge.slice("Bearer ".length).matchAll(/(\w+)="([^"]*)"/g)) {
		params[m[1]] = m[2];
	}
	if (!params.realm) throw new Error(`auth challenge has no realm: ${challenge}`);
	const url = new URL(params.realm);
	if (params.service) url.searchParams.set("service", params.service);
	if (params.scope) url.searchParams.set("scope", params.scope);
	return fetchWithTimeout(url.href, async (res) => {
		if (!res.ok) throw new Error(`token endpoint HTTP ${res.status}`);
		const body = await res.json();
		const token = body.token ?? body.access_token;
		if (!token) throw new Error("token endpoint returned no token");
		return token;
	});
}

// Newest release tag of a Docker image (`<host>/<repo>`, no tag/digest) via Registry v2 API.
// GET /v2/<repo>/tags/list, retried with a Bearer token when the registry answers 401.
async function resolveDockerRegistryLatest(imageRef) {
	const slash = imageRef.indexOf("/");
	if (slash < 0) throw new Error(`image ref '${imageRef}' has no registry host`);
	if (imageRef.includes("@")) throw new Error(`image ref '${imageRef}' must not include a digest (@sha256:…) — pass the bare image, no tag`);
	const host = imageRef.slice(0, slash);
	const repo = imageRef.slice(slash + 1);
	const tagsUrl = `https://${host}/v2/${repo}/tags/list`;

	const readTags = async (res) => {
		if (!res.ok) throw new Error(`${tagsUrl}: HTTP ${res.status}`);
		const { tags } = await res.json();
		if (!Array.isArray(tags)) throw new Error(`${tagsUrl}: response has no 'tags' array`);
		return tags;
	};
	const tags = await fetchWithTimeout(tagsUrl, async (res) => {
		if (res.status !== 401) return readTags(res);
		res.body?.cancel().catch(() => {}); // drop the challenge body before the authed retry
		const token = await fetchBearerToken(res.headers.get("www-authenticate"));
		return fetchWithTimeout(tagsUrl, readTags, { headers: { authorization: `Bearer ${token}` } });
	});

	const releases = tags.filter((t) => RELEASE_TAG.test(t));
	if (releases.length === 0) throw new Error(`no release tags among: ${tags.join(", ") || "(none)"}`);
	return releases.sort(compareTags).at(-1);
}

try {
	let version;
	switch (channel.type) {
		case "npm":
			version = resolveNpm(entry.package);
			break;
		case "vscode-stable":
			version = await resolveVsCodeStable();
			break;
		case "cursor-install":
			version = await resolveCursorInstall(channel.url);
			break;
		case "docker-registry": {
			const imageRef = process.env[channel.imageEnv];
			if (!imageRef) {
				throw new Error(
					`channel.type=docker-registry needs env ${channel.imageEnv} (the registry image, no tag)`,
				);
			}
			version = await resolveDockerRegistryLatest(imageRef);
			break;
		}
		default:
			throw new Error(`agent '${agent}' has no resolvable channel (got '${channel.type}')`);
	}
	if (!version) throw new Error(`empty version resolved for '${agent}'`);
	process.stdout.write(`${version}\n`);
} catch (err) {
	process.stderr.write(`resolve-version: ${agent}: ${err.message}\n`);
	process.exit(1);
}
