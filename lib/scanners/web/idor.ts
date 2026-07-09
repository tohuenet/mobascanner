/**
 * IDOR / sequential-ID enumerator.
 *
 * Walks the SiteMap looking for URLs that contain numeric segments
 * (`/users/123`, `/orders/4519`) or numeric query params (`?id=42`).
 * For each, requests the same URL with id ± offset and checks whether the
 * response is significantly different (different content, different
 * embedded primary-key, different status family).
 *
 * Heuristics, not proofs:
 *   - If id+1 returns 200 with markedly different body → likely IDOR.
 *   - If id+offset returns same 200 page → consistent (probably not IDOR
 *     OR the auth layer doesn't gate this object).
 *   - If id+offset returns 401/403 → access-control IS gating, no IDOR.
 *
 * We deliberately keep the offsets small (±1, ±2, ±10, ±100) so the test
 * stays a probe rather than a scrape.
 */

import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

const PATH_NUMERIC = /\/(\d{1,9})(?=\/|$|\?)/;

interface Candidate { url: URL; pivot: { kind: "path" | "query"; key?: string; original: number; segmentIndex?: number } }

function findCandidates(url: URL): Candidate[] {
  const out: Candidate[] = [];
  // Path-segment numeric ids
  const segs = url.pathname.split("/");
  for (let i = 0; i < segs.length; i++) {
    if (/^\d{1,9}$/.test(segs[i])) {
      out.push({ url, pivot: { kind: "path", original: Number(segs[i]), segmentIndex: i } });
    }
  }
  // Numeric query params commonly used for ids
  for (const [k, v] of url.searchParams.entries()) {
    if (/^\d{1,9}$/.test(v) && /(^|_|-)(id|user|account|order|invoice|num|nr|ref)$/i.test(k)) {
      out.push({ url, pivot: { kind: "query", key: k, original: Number(v) } });
    }
  }
  return out;
}

function buildVariant(c: Candidate, offset: number): URL {
  const u = new URL(c.url.toString());
  if (c.pivot.kind === "path") {
    const segs = u.pathname.split("/");
    segs[c.pivot.segmentIndex!] = String(c.pivot.original + offset);
    u.pathname = segs.join("/");
  } else {
    u.searchParams.set(c.pivot.key!, String(c.pivot.original + offset));
  }
  return u;
}

/**
 * Distinct-content detection for IDOR.
 *
 * The whole-page similarity approach (length + head-prefix) fails when two
 * pages share a layout shell — almost any record-detail page does. Instead
 * we compute the *unique middle*: strip the longest common prefix and the
 * longest common suffix, and check whether what's left differs meaningfully
 * on both sides.
 *
 * Returns:
 *   - `distinct: true`  → both responses have non-trivial unique content
 *                         and that content differs (clearly different objects).
 *   - `distinct: false` → either responses are identical-ish, or the variant
 *                         is just a generic 404-shaped page (small unique part).
 */
function distinctContent(baseline: string, variant: string): { distinct: boolean; uniqueLen: number } {
  if (!baseline || !variant) return { distinct: false, uniqueLen: 0 };
  if (baseline === variant) return { distinct: false, uniqueLen: 0 };

  let prefix = 0;
  const minLen = Math.min(baseline.length, variant.length);
  while (prefix < minLen && baseline[prefix] === variant[prefix]) prefix++;

  let suffix = 0;
  const a = baseline, b = variant;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  ) suffix++;

  const baseUnique = baseline.slice(prefix, baseline.length - suffix);
  const varUnique = variant.slice(prefix, variant.length - suffix);

  const distinct =
    baseUnique.length >= 4 &&
    varUnique.length >= 4 &&
    baseUnique !== varUnique;

  return { distinct, uniqueLen: Math.max(baseUnique.length, varUnique.length) };
}

export const idorScanner: Scanner = {
  id: "web.idor",
  name: "IDOR / Sequential ID Enumerator",
  kind: "web",
  description: "Probes URLs with numeric ids by requesting id±{1,2,10,100} and flagging endpoints that return different objects without an auth check.",
  defaultEnabled: false,

  async tool() {
    return {
      id: "web.idor", name: "IDOR Enumerator", kind: "web", backend: "builtin", status: "available",
      description: "Sequential-id IDOR probe.",
    };
  },

  async run(ctx) {
    const seed = safeUrl(ctx.target.value);
    if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.log("info", "no SiteMap — run web.crawler first"); await ctx.progress(1, "skipped"); return; }

    const session = new BrowsingSession(seed.origin, {
      ...(ctx.target.auth?.headers ?? {}),
      ...(ctx.target.auth?.bearerToken ? { Authorization: `Bearer ${ctx.target.auth.bearerToken}` } : {}),
    });

    // Collect candidates from sitemap pages.
    const candidates: Candidate[] = [];
    const seenUrls = new Set<string>();
    for (const p of map.pages) {
      const u = safeUrl(p.url); if (!u) continue;
      if (seenUrls.has(u.toString())) continue; seenUrls.add(u.toString());
      candidates.push(...findCandidates(u));
    }
    if (!candidates.length) {
      await ctx.log("info", "no numeric-id endpoints found in sitemap");
      await ctx.progress(1, "no candidates");
      return;
    }

    const offsets = [1, -1, 2, -2, 10, 100];
    const total = candidates.length * (1 + offsets.length); // baseline + variants
    let done = 0;

    for (const c of candidates.slice(0, 25)) {
      if (ctx.signal.aborted) break;
      let baseline; try { baseline = await session.fetch(c.url.toString(), { signal: ctx.signal }); }
      catch { continue; }
      done += 1;
      if (baseline.res.status >= 400) continue; // can't compare

      // Self-baseline: fetch the SAME url again. If it already differs from
      // itself in the unique-middle (a per-request CSRF token / nonce /
      // timestamp in the body), then EVERY id — even a non-existent one — will
      // look "distinct" and the signal is worthless. Skip this candidate.
      let baseline2; try { baseline2 = await session.fetch(c.url.toString(), { signal: ctx.signal }); }
      catch { continue; }
      if (distinctContent(baseline.body, baseline2.body).distinct) {
        await ctx.log("info", `${c.url}: response varies between identical requests — skipping IDOR (non-deterministic body)`);
        continue;
      }

      // Garbage-id control: a wildly out-of-range id that should NOT exist. If
      // it ALSO returns distinct 2xx content, the endpoint serves content for
      // ANY id (a public listing / echo), which is not owner-scoped access.
      const controlUrl = buildVariant(c, 10_000_000);
      let control; try { control = await session.fetch(controlUrl.toString(), { signal: ctx.signal }); } catch { control = null; }
      if (control && control.res.status >= 200 && control.res.status < 300 && distinctContent(baseline.body, control.body).distinct) {
        await ctx.log("info", `${c.url}: a bogus id also returns distinct content — endpoint echoes arbitrary ids, not IDOR`);
        continue;
      }

      const variants: { offset: number; status: number; body: string; distinct: boolean; uniqueLen: number }[] = [];
      for (const off of offsets) {
        if (ctx.signal.aborted) break;
        const variantUrl = buildVariant(c, off);
        let v;
        try { v = await session.fetch(variantUrl.toString(), { signal: ctx.signal }); }
        catch { done += 1; continue; }
        done += 1;
        if (done % 8 === 0) await ctx.progress(done / total, `${variantUrl}`);
        const d = distinctContent(baseline.body, v.body);
        variants.push({ offset: off, status: v.res.status, body: v.body, distinct: d.distinct, uniqueLen: d.uniqueLen });
      }

      // IDOR signal: ≥2 variants return 2xx with content distinctly different
      // from baseline (different unique-middle), AND no variant returned 401/403
      // (which would prove auth IS gating the endpoint).
      const anyGated = variants.some((v) => v.status === 401 || v.status === 403);
      const distinctSuccess = variants.filter((v) => v.status >= 200 && v.status < 300 && v.distinct);
      if (!anyGated && distinctSuccess.length >= 2) {
        await ctx.emit(draft({
          severity: "high",
          confidence: "medium",
          title: c.pivot.kind === "query"
            ? `Possible IDOR on ${c.url.pathname}?${c.pivot.key}=${c.pivot.original}`
            : `Possible IDOR on ${c.url.pathname}`,
          description: `Numeric id ${c.pivot.original} is used in the URL. Sibling ids (${distinctSuccess.map((v) => c.pivot.original + v.offset).join(", ")}) return distinct content with no auth challenge — the endpoint appears to read objects by id without checking ownership.`,
          ruleId: "idor/sequential-id",
          cwe: ["CWE-639"],
          owasp: ["A01:2021"],
          location: { url: c.url.toString(), snippet: c.pivot.kind === "path" ? "path segment" : `?${c.pivot.key}=` },
          evidence: {
            baseline: { url: c.url.toString(), status: baseline.res.status, len: baseline.body.length },
            variants: distinctSuccess.map((v) => ({
              offset: v.offset,
              targetId: c.pivot.original + v.offset,
              status: v.status,
              len: v.body.length,
              uniqueLen: v.uniqueLen,
              snippet: truncate(v.body, 200),
            })),
          },
          remediation: "Enforce per-object authorization. Check that the requesting user owns / has access to the object id before serving. Prefer opaque ids (UUID/ULID) over sequential integers.",
          references: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        }));
      }
    }
    await ctx.progress(1, `${done} IDOR probes`);
  },
};
