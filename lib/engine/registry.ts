/**
 * Global scanner registry — every adapter registers itself once at module load.
 * Lookups are by stable id (e.g. "web.headers", "source.semgrep").
 */

import type { Scanner } from "./scanner";

const registry = new Map<string, Scanner>();

export function registerScanner(scanner: Scanner): void {
  if (registry.has(scanner.id)) {
    // Hot-reload friendly: replace silently rather than throw.
    registry.set(scanner.id, scanner);
    return;
  }
  registry.set(scanner.id, scanner);
}

export function getScanner(id: string): Scanner | undefined {
  return registry.get(id);
}

export function listScanners(): Scanner[] {
  return [...registry.values()];
}

export function listScannersByKind(kind: Scanner["kind"]): Scanner[] {
  return listScanners().filter((s) => s.kind === kind);
}
