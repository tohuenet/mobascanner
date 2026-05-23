"use client";

/**
 * FindingsTab — the primary tab. Thin wrapper that delegates to the existing
 * FindingsList, which already owns its own search / severity / scanner filter
 * UI. Lives in its own component so future filter/saved-view state can hang
 * off the tab without cluttering the parent.
 */

import { FindingsList } from "../FindingsList";
import type { Finding } from "@/lib/types";

export function FindingsTab({ findings }: { findings: Finding[] }) {
  return <FindingsList findings={findings} />;
}
