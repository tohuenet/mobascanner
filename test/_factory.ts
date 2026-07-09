/**
 * Tiny typed factory for synthetic `Finding` objects used across the tests.
 *
 * Every required field gets a sane default; pass a partial to override only the
 * fields a given test cares about. Kept dependency-free — no test framework, no
 * source imports beyond the domain type.
 */
import type { Finding } from "../lib/types";

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-default",
    scanId: "scan-default",
    scannerId: "web.test",
    scannerName: "Test Scanner",
    severity: "info",
    confidence: "medium",
    title: "Test finding",
    description: "",
    location: {},
    createdAt: 0,
    ...overrides,
  };
}
