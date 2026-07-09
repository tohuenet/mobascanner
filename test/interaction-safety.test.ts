/**
 * Regression tests for the SPA interaction safety blocklist
 * (`lib/scanners/web/_interaction.ts` → `isDestructiveText`).
 *
 * These predicates decide whether the crawler is allowed to click a control.
 * A regression here could log the scanner out mid-scan, delete data, or spend
 * money — so the true/false boundaries are locked in.
 */
import { test } from "node:test";
import assert from "node:assert";
import { isDestructiveText } from "../lib/scanners/web/_interaction";

test("isDestructiveText: true for destructive / irreversible controls", () => {
  for (const s of ["Log out", "Delete account", "Transfer funds", "Buy now", "Reset password", "Confirm"]) {
    assert.strictEqual(isDestructiveText(s), true, `expected destructive: ${s}`);
  }
});

test("isDestructiveText: false for safe navigational controls", () => {
  for (const s of ["Open menu", "Show more", "Load more", "Details"]) {
    assert.strictEqual(isDestructiveText(s), false, `expected safe: ${s}`);
  }
});
