/**
 * Host-volatile envelope fields per connector — the top-level keys each host populates per
 * call (session/transcript ids, cwd, timing). They carry placeholder values in the committed
 * contract fixtures; the Layer 2 drift loop resets them to those placeholders when proposing a
 * fixture update (`buildProposedFixture`), so a reviewer sees only genuine structural change.
 *
 * Single-sourced here (imported by each connector's E2E suite) and asserted to be a subset of
 * the committed fixture's keys by e2e-envelope-fixtures.test.ts — so a rename in the fixture
 * without updating the list (or vice versa) fails at Layer 1 instead of silently leaving a live
 * volatile value baked into a proposed fixture.
 *
 * (Claude Code keeps its own VOLATILE_ENVELOPE_FIELDS in claude-code/.../contract-fixtures.ts,
 * which predates this module and is shared with its integration tests; it's asserted there.)
 */
export const ENVELOPE_VOLATILE_FIELDS = {
	cursor: ["session_id", "conversation_id", "tool_use_id", "cwd"],
	// Copilot 1.0.63 sends session_id, a per-call timestamp, and cwd; no tool_use_id.
	copilot: ["session_id", "timestamp", "cwd"],
	openclaw: ["sessionKey"],
	opencode: ["sessionID", "callID"],
} as const;
