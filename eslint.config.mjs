import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Harness/tooling scratch: git worktrees and agent artifacts under .claude
    // are not project source and must never be linted (a duplicate source tree
    // there otherwise double-counts every finding).
    ".claude/**",
  ]),
]);

export default eslintConfig;
