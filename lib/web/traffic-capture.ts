/**
 * HTTP traffic capture — every request/response pair the scan makes is
 * appended to `data/scans/<id>/traffic.har` (HAR 1.2 spec).
 *
 * Why: post-scan triage is enormously easier when you can re-play any
 * request in Burp Repeater style. Also feeds /api/scans/[a]/diff/[b] when
 * comparing how the target's responses changed between scans.
 *
 * Storage: append-only JSONL of `{request, response, timing}` entries; we
 * convert to a real HAR document on demand via `traffic-to-har.ts`.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

interface CapturedEntry {
  startedAt: number;
  durationMs: number;
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response: { status: number; statusText: string; headers: Record<string, string>; bodyLen: number; bodySnippet: string };
  scannerId?: string;
}

let currentScanId: string | null = null;

export function startTrafficCapture(scanId: string) { currentScanId = scanId; }
export function endTrafficCapture() { currentScanId = null; }

export async function captureEntry(scannerId: string | null, entry: CapturedEntry) {
  if (!currentScanId) return;
  const file = path.join(process.cwd(), "data", "scans", currentScanId, "traffic.jsonl");
  try { await fs.mkdir(path.dirname(file), { recursive: true }); } catch { /* ignore */ }
  const line = JSON.stringify({ ...entry, scannerId }) + "\n";
  try { await fs.appendFile(file, line, "utf8"); } catch { /* tolerate */ }
}

/** Convert the captured JSONL into HAR 1.2 format on demand. */
export async function exportHar(scanId: string): Promise<string> {
  const file = path.join(process.cwd(), "data", "scans", scanId, "traffic.jsonl");
  let raw = "";
  try { raw = await fs.readFile(file, "utf8"); } catch { return JSON.stringify({ log: { version: "1.2", creator: { name: "moba-scanner", version: "0.1" }, entries: [] } }, null, 2); }
  const entries = raw.split("\n").filter(Boolean).map((line) => {
    try { return JSON.parse(line) as CapturedEntry & { scannerId?: string }; } catch { return null; }
  }).filter((x): x is CapturedEntry & { scannerId?: string } => Boolean(x));

  const har = {
    log: {
      version: "1.2",
      creator: { name: "moba-scanner", version: "0.1" },
      entries: entries.map((e) => ({
        startedDateTime: new Date(e.startedAt).toISOString(),
        time: e.durationMs,
        request: {
          method: e.request.method,
          url: e.request.url,
          httpVersion: "HTTP/1.1",
          headers: Object.entries(e.request.headers).map(([name, value]) => ({ name, value })),
          queryString: (() => {
            try { return [...new URL(e.request.url).searchParams.entries()].map(([name, value]) => ({ name, value })); }
            catch { return []; }
          })(),
          cookies: [], headersSize: -1, bodySize: e.request.body?.length ?? 0,
          ...(e.request.body ? { postData: { mimeType: e.request.headers["content-type"] ?? "text/plain", text: e.request.body } } : {}),
        },
        response: {
          status: e.response.status,
          statusText: e.response.statusText,
          httpVersion: "HTTP/1.1",
          headers: Object.entries(e.response.headers).map(([name, value]) => ({ name, value })),
          cookies: [], headersSize: -1, bodySize: e.response.bodyLen,
          content: { size: e.response.bodyLen, mimeType: e.response.headers["content-type"] ?? "text/plain", text: e.response.bodySnippet },
          redirectURL: e.response.headers["location"] ?? "",
        },
        cache: {},
        timings: { send: 0, wait: e.durationMs, receive: 0 },
        _scannerId: e.scannerId,
      })),
    },
  };
  return JSON.stringify(har, null, 2);
}
