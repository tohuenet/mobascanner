/**
 * JWT cookie analyzer — operates over the SiteMap's full Set-Cookie history
 * (every cookie observed during crawl, across every navigation hop) plus the
 * user-supplied bearer token. Falls back to a single seed-URL fetch if no
 * SiteMap exists.
 *
 * Detects:
 *   - alg=none (token is forgeable)
 *   - empty signature segment
 *   - missing exp claim (token never expires)
 *   - long exp (>30 days from now)
 *   - kid header value containing path-traversal characters
 *   - PII fields in payload
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

function b64urlDecode(s: string): string {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  try { return Buffer.from(s, "base64").toString("utf8"); } catch { return ""; }
}

interface ParsedJwt { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string; raw: string }

function parseJwt(token: string): ParsedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const headerStr = b64urlDecode(parts[0]);
  const payloadStr = b64urlDecode(parts[1]);
  if (!headerStr || !payloadStr) return null;
  try {
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);
    return { header, payload, signature: parts[2], raw: token };
  } catch { return null; }
}

const JWT_LIKE = /\b([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)\b/g;
const COOKIE_NV = /^([A-Za-z0-9_-]+)=([^;]+)/;

function* extractTokensFromSetCookies(setCookies: string[]): Generator<{ source: string; token: string }> {
  for (const raw of setCookies) {
    const m = COOKIE_NV.exec(raw);
    if (!m) continue;
    const name = m[1];
    const value = m[2];
    if (!value.includes(".")) continue;
    // Cookie value itself a JWT?
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value)) {
      yield { source: `Set-Cookie:${name}`, token: value };
      continue;
    }
    // Cookie value contains a JWT inside (rare but possible).
    for (const tm of value.matchAll(JWT_LIKE)) {
      yield { source: `Set-Cookie:${name}`, token: tm[1] };
    }
  }
}

export const jwtScanner: Scanner = {
  id: "web.jwt",
  name: "JWT Inspector (per-cookie)",
  kind: "web",
  description: "Parses every JWT observed in Set-Cookie across the crawl plus user-supplied bearer tokens. Flags alg=none, empty sig, missing/long exp, kid traversal, PII in payload.",
  defaultEnabled: true,

  async tool() {
    return {
      id: "web.jwt", name: "JWT Inspector", kind: "web", backend: "builtin", status: "available",
      description: "Per-cookie JWT structural analyzer over the full crawl history.",
    };
  },

  async run(ctx) {
    const url = safeUrl(ctx.target.value);
    if (!url) return;

    // Source 1: SiteMap setCookies (preferred — every cookie observed).
    const map = await loadSiteMap(ctx.scanId);
    const setCookies: string[] = [];
    if (map) {
      for (const p of map.pages) {
        if (p.setCookies) setCookies.push(...p.setCookies);
      }
    } else {
      // Fallback: hit the seed once.
      const session = new BrowsingSession(url.origin, {
        ...(ctx.target.auth?.headers ?? {}),
        ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
      });
      try {
        const r = await session.fetch(url.toString(), { signal: ctx.signal });
        setCookies.push(...r.allSetCookies);
      } catch { /* tolerate */ }
    }

    const sources: { source: string; token: string }[] = [];
    for (const t of extractTokensFromSetCookies(setCookies)) sources.push(t);
    if (ctx.target.auth?.bearerToken) sources.push({ source: "auth.bearerToken", token: ctx.target.auth.bearerToken });

    // Dedup by token value.
    const dedup = new Map<string, { source: string; token: string }>();
    for (const s of sources) if (!dedup.has(s.token)) dedup.set(s.token, s);

    if (!dedup.size) {
      await ctx.progress(1, "no JWTs in scope");
      return;
    }

    for (const { source, token } of dedup.values()) {
      const jwt = parseJwt(token);
      if (!jwt) continue;
      const baseLoc = { url: url.toString(), snippet: source };
      const evidence = {
        source,
        header: jwt.header,
        payload: { ...(jwt.payload as Record<string, unknown>) },
        rawHeader: token.split(".")[0],
      };

      if ((jwt.header.alg as string)?.toLowerCase() === "none") {
        await ctx.emit(draft({
          severity: "critical", confidence: "high",
          title: `JWT uses alg=none (${source})`,
          description: "Token declares alg=none. If the server accepts it, anyone can forge tokens with arbitrary claims.",
          ruleId: "jwt/alg-none", cwe: ["CWE-347"], owasp: ["A07:2021"],
          location: baseLoc, evidence,
          remediation: "Reject alg=none server-side. Pin the expected algorithm and verify with a key bound to that algorithm.",
        }));
      }
      if (!jwt.signature) {
        await ctx.emit(draft({
          severity: "high", confidence: "high",
          title: `JWT has empty signature (${source})`,
          description: "JWT signature segment is empty — likely accepted unsigned.",
          ruleId: "jwt/empty-sig", cwe: ["CWE-347"],
          location: baseLoc, evidence,
        }));
      }
      const exp = jwt.payload.exp;
      if (exp === undefined) {
        await ctx.emit(draft({
          severity: "medium", confidence: "high",
          title: `JWT missing 'exp' claim (${source})`,
          description: "Token never expires — increases impact of any leak.",
          ruleId: "jwt/no-exp", cwe: ["CWE-613"],
          location: baseLoc, evidence,
        }));
      } else if (typeof exp === "number" && exp - Math.floor(Date.now() / 1000) > 60 * 60 * 24 * 30) {
        await ctx.emit(draft({
          severity: "low", confidence: "medium",
          title: `JWT exp is more than 30 days out (${source})`,
          description: "Long-lived tokens widen the breach window.",
          ruleId: "jwt/long-exp", location: baseLoc, evidence,
        }));
      }
      const kid = jwt.header.kid as string | undefined;
      if (kid && /[\\/]|\.\./.test(kid)) {
        await ctx.emit(draft({
          severity: "high", confidence: "medium",
          title: `JWT kid contains path-traversal characters (${source})`,
          description: `kid="${kid}". If the server resolves keys by file path, this enables key-confusion / file injection.`,
          ruleId: "jwt/kid-traversal", cwe: ["CWE-22"], location: baseLoc, evidence,
        }));
      }
      const piiKeys = ["email", "phone", "phone_number", "ssn", "address", "national_id"];
      const leakedPii = piiKeys.filter((k) => k in jwt.payload);
      if (leakedPii.length) {
        await ctx.emit(draft({
          severity: "low", confidence: "medium",
          title: `JWT payload contains PII fields (${source})`,
          description: `Payload includes: ${leakedPii.join(", ")}. JWT payloads are base64-decoded by anyone holding the token.`,
          ruleId: "jwt/pii", cwe: ["CWE-359"], location: baseLoc, evidence,
        }));
      }
    }
    await ctx.progress(1, `${dedup.size} unique JWT(s) parsed`);
  },
};
