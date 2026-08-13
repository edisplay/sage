/**
 * Barrel for the `@gendigital/sage-core/testing` subpath: the Layer 2 E2E drift loop
 * (`e2e-envelope-diff.ts`), the audit-log verdict scanner (`e2e-audit-log.ts`), the
 * shared container/gateway harness scaffolding (`e2e-test-harness.ts`), the canary marker
 * constants (`e2e-canary-markers.ts`), and per-connector volatile envelope fields
 * (`e2e-envelope-fixtures.ts`). Test-only; node + fetch, no test framework.
 */

export * from "./e2e-audit-log.js";
export * from "./e2e-canary-markers.js";
export * from "./e2e-drift-routing.js";
export * from "./e2e-envelope-diff.js";
export * from "./e2e-envelope-fixtures.js";
export * from "./e2e-test-harness.js";
