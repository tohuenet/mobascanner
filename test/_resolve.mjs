import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
export function resolve(specifier, context, next) {
  if (/^\.\.?\//.test(specifier) && !/\.[cm]?[jt]sx?$/i.test(specifier)) {
    for (const ext of [".ts", ".tsx", ".js", ".mjs"]) {
      try {
        const u = new URL(specifier + ext, context.parentURL);
        if (existsSync(fileURLToPath(u))) return next(specifier + ext, context);
      } catch { /* keep trying */ }
    }
  }
  return next(specifier, context);
}
