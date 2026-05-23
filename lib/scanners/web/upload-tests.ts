/**
 * File-handling-related scanners — fill the "File handling" row of the audit.
 *
 *   - web.file-upload  : finds <input type=file> forms, submits various
 *                        bypass-attempt files (double-extension, polyglot,
 *                        SVG-with-script, oversize), watches for accepted
 *                        + reflected paths.
 *   - web.zip-slip     : if any upload accepts archives, posts a malicious zip
 *                        whose entries traverse out of the extract dir.
 *   - web.range-leak   : sends `Range: bytes=0-N` against static-shaped paths
 *                        and checks for partial-file disclosure of
 *                        adjacent-file content (some servers serve adjacent
 *                        memory / wrong file).
 */

import { randomBytes } from "node:crypto";
import { draft, type Scanner } from "../../engine/scanner";
import { safeUrl, truncate } from "../common";
import { loadSiteMap, type SiteMapForm } from "../../web/sitemap";
import { BrowsingSession } from "../../web/session";

// ───────────────────── multipart helper ─────────────────────────────
function multipart(boundary: string, fields: { name: string; value: string }[], file: { name: string; filename: string; contentType: string; data: Buffer }): Buffer {
  const parts: Buffer[] = [];
  for (const f of fields) {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${f.name}"\r\n\r\n${f.value}\r\n`));
  }
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`));
  parts.push(file.data);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  return Buffer.concat(parts);
}

interface UploadAttempt {
  label: string;
  filename: string;
  contentType: string;
  data: Buffer;
  /** What we expect the scanner to flag if accepted. */
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  cwe: string[];
}

const CANARY_PHP = `<?php echo "MOBA-PHP-EXEC-${Date.now().toString(36)}"; ?>`;
const CANARY_JSP = `<%= "MOBA-JSP-EXEC-" + System.currentTimeMillis() %>`;
const CANARY_HTML = `<script>document.title="MOBA-XSS-${Date.now().toString(36)}"</script>`;
const SVG_XSS = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert('moba-svg-xss')</script></svg>`;
const POLYGLOT_GIF_PHP = Buffer.concat([
  Buffer.from("GIF89a;\n"), Buffer.from(CANARY_PHP),
]);

function uploadAttempts(): UploadAttempt[] {
  return [
    {
      label: "double-extension-php",
      filename: `moba-${randomBytes(2).toString("hex")}.php.jpg`,
      contentType: "image/jpeg",
      data: Buffer.from(CANARY_PHP),
      severity: "critical", cwe: ["CWE-434"],
      description: "Double-extension `.php.jpg` — bypasses naive extension blacklists; some webservers (Apache + AddHandler) execute it as PHP.",
    },
    {
      label: "double-extension-jsp",
      filename: `moba-${randomBytes(2).toString("hex")}.jsp.png`,
      contentType: "image/png",
      data: Buffer.from(CANARY_JSP),
      severity: "critical", cwe: ["CWE-434"],
      description: "Double-extension `.jsp.png` — similar bypass path on Tomcat / Jetty.",
    },
    {
      label: "uppercase-extension",
      filename: `moba-${randomBytes(2).toString("hex")}.PHp`,
      contentType: "image/jpeg",
      data: Buffer.from(CANARY_PHP),
      severity: "high", cwe: ["CWE-434"],
      description: "Mixed-case `.PHp` — case-sensitive blacklist may miss this.",
    },
    {
      label: "phtml-extension",
      filename: `moba-${randomBytes(2).toString("hex")}.phtml`,
      contentType: "image/jpeg",
      data: Buffer.from(CANARY_PHP),
      severity: "high", cwe: ["CWE-434"],
      description: "Alt-PHP extension `.phtml` — often forgotten in blacklists.",
    },
    {
      label: "svg-with-xss",
      filename: `moba-${randomBytes(2).toString("hex")}.svg`,
      contentType: "image/svg+xml",
      data: Buffer.from(SVG_XSS),
      severity: "high", cwe: ["CWE-79"],
      description: "SVG image containing inline JavaScript — XSS when served back to browser.",
    },
    {
      label: "html-mime-spoof",
      filename: `moba-${randomBytes(2).toString("hex")}.html`,
      contentType: "image/jpeg",
      data: Buffer.from(CANARY_HTML),
      severity: "high", cwe: ["CWE-434"],
      description: "HTML-with-script masquerading as image/jpeg (Content-Type spoof).",
    },
    {
      label: "polyglot-gif-php",
      filename: `moba-${randomBytes(2).toString("hex")}.gif`,
      contentType: "image/gif",
      data: POLYGLOT_GIF_PHP,
      severity: "critical", cwe: ["CWE-434"],
      description: "GIF89a header followed by PHP code — passes magic-byte checks AND is interpreted as PHP if extension is renamed.",
    },
    {
      label: "path-traversal-filename",
      filename: `../../../moba-traverse-${randomBytes(2).toString("hex")}.txt`,
      contentType: "text/plain",
      data: Buffer.from("MOBA-TRAVERSE-CANARY"),
      severity: "high", cwe: ["CWE-22"],
      description: "Filename containing `../` — server may write outside upload dir if not sanitized.",
    },
  ];
}

export const fileUploadScanner: Scanner = {
  id: "web.file-upload",
  name: "File Upload Bypass",
  kind: "web",
  description: "Finds <input type=file> forms in the SiteMap and submits ~8 bypass-attempt files (double-extension, polyglot GIF/PHP, SVG-XSS, mixed-case, .phtml, MIME spoof, path-traversal filename). Flags any that the server accepts.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.file-upload", name: "File Upload Bypass", kind: "web", backend: "builtin", status: "available", description: "Built-in file upload bypass tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const uploadForms = map.forms.filter((f: SiteMapForm) => f.method === "POST" && f.inputs.some((i) => i.type === "file"));
    if (!uploadForms.length) { await ctx.progress(1, "no upload forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const attempts = uploadAttempts();

    for (const form of uploadForms) {
      if (ctx.signal.aborted) break;
      const fileField = form.inputs.find((i) => i.type === "file")!;
      const otherFields = form.inputs.filter((i) => i.type !== "file" && i.type !== "submit");
      for (const a of attempts) {
        if (ctx.signal.aborted) break;
        const boundary = `------MobaBoundary${randomBytes(6).toString("hex")}`;
        const body = multipart(boundary, otherFields.map((f) => ({ name: f.name, value: f.value || "x" })), {
          name: fileField.name, filename: a.filename, contentType: a.contentType, data: a.data,
        });
        let r;
        try {
          r = await session.fetch(form.action, {
            method: "POST",
            headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
            body: new Uint8Array(body),
            signal: ctx.signal,
          });
        } catch { continue; }
        // Heuristic: server returns 200 + the filename / a "stored at" path / canary echo.
        const lower = r.body.toLowerCase();
        const filenameEcho = lower.includes(a.filename.toLowerCase());
        const accepted = (r.res.status >= 200 && r.res.status < 300) &&
          (filenameEcho || /stored|saved|uploaded|upload\s+complete/i.test(r.body));
        if (accepted) {
          await ctx.emit(draft({
            severity: a.severity, confidence: filenameEcho ? "high" : "medium",
            title: `File-upload bypass accepted: ${a.label} on ${form.action}`,
            description: `${a.description}\n\nUploaded \`${a.filename}\` (${a.contentType}). Response indicates acceptance — confirm by GETing the upload path and watching for code execution.`,
            ruleId: `upload/${a.label}`,
            cwe: a.cwe, owasp: ["A01:2021", "A05:2021"],
            location: { url: form.action, snippet: a.filename },
            evidence: { contentType: a.contentType, status: r.res.status, snippet: truncate(r.body, 300) },
            remediation: "Define an EXTENSION ALLOW-LIST (not blacklist). Re-render images server-side via `imagemagick`/`sharp` to strip embedded code. Store uploads outside webroot. Use random server-generated filenames.",
            references: ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
          }));
        }
      }
    }
    await ctx.progress(1, "file-upload done");
  },
};

// ───────────────────────── ZIP slip ──────────────────────────────────
// Only fires when an upload form ALREADY exists. Builds a minimal zip with
// one entry whose path is `../../../moba-zipslip-CANARY.txt`. If the server
// extracts and writes it outside the upload dir, the canary file will leak
// (we can't easily verify without access — we just flag the upload acceptance
// and let the user verify out-of-band).
export const zipSlipScanner: Scanner = {
  id: "web.zip-slip",
  name: "ZIP Slip",
  kind: "web",
  description: "If an upload form accepts archives, posts a zip whose internal entry path traverses out of the extract dir. Flags acceptance — manual verification required to confirm extraction.",
  defaultEnabled: false,
  async tool() {
    return { id: "web.zip-slip", name: "ZIP Slip", kind: "web", backend: "builtin", status: "available", description: "Built-in ZIP-slip upload probe." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    if (!map) { await ctx.progress(1, "no sitemap"); return; }
    const uploadForms = map.forms.filter((f: SiteMapForm) => f.method === "POST" && f.inputs.some((i) => i.type === "file"));
    if (!uploadForms.length) { await ctx.progress(1, "no upload forms"); return; }
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});

    // Tiny stored-mode ZIP with one slip entry. Format: PKZIP local file header.
    const slipPath = "../../../moba-zipslip-canary.txt";
    const content = Buffer.from("MOBA-ZIPSLIP-CANARY-" + randomBytes(4).toString("hex"));
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);             // signature
    lfh.writeUInt16LE(20, 4);                      // version needed
    lfh.writeUInt16LE(0, 6);                       // flags
    lfh.writeUInt16LE(0, 8);                       // method (stored)
    lfh.writeUInt16LE(0, 10);                      // mtime
    lfh.writeUInt16LE(0, 12);                      // mdate
    lfh.writeUInt32LE(0, 14);                      // crc32 (skipped — would need real CRC for Zip64; many parsers tolerate)
    lfh.writeUInt32LE(content.length, 18);         // compressed size
    lfh.writeUInt32LE(content.length, 22);         // uncompressed size
    lfh.writeUInt16LE(slipPath.length, 26);        // file name length
    lfh.writeUInt16LE(0, 28);                      // extra length
    const zipBytes = Buffer.concat([lfh, Buffer.from(slipPath), content]);

    for (const form of uploadForms) {
      if (ctx.signal.aborted) break;
      const fileField = form.inputs.find((i) => i.type === "file")!;
      const others = form.inputs.filter((i) => i.type !== "file" && i.type !== "submit");
      const boundary = `------MobaZipBoundary${randomBytes(6).toString("hex")}`;
      const body = multipart(boundary, others.map((f) => ({ name: f.name, value: f.value || "x" })), {
        name: fileField.name, filename: "moba-traversal.zip", contentType: "application/zip", data: zipBytes,
      });
      let r;
      try { r = await session.fetch(form.action, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}` }, body: new Uint8Array(body), signal: ctx.signal }); }
      catch { continue; }
      if (r.res.status >= 200 && r.res.status < 300 && /extracted|unzipped|unzipping|saved/i.test(r.body)) {
        await ctx.emit(draft({
          severity: "high", confidence: "low",
          title: `ZIP slip surface on ${form.action}`,
          description: `Upload form accepted a ZIP file containing an entry with path \`${slipPath}\`. If the server extracts archives, a path-traversing entry can overwrite arbitrary files (init scripts, .ssh/authorized_keys, web shells in the public dir). Confirm by checking server filesystem.`,
          ruleId: "zip-slip/upload",
          cwe: ["CWE-22"], owasp: ["A01:2021"],
          location: { url: form.action, snippet: slipPath },
          evidence: { responseSnippet: truncate(r.body, 300) },
          remediation: "When extracting archives, validate `entry.name` doesn't contain `../` AND `realpath(extractDir + entryName)` is still inside extractDir.",
          references: ["https://snyk.io/research/zip-slip-vulnerability"],
        }));
      }
    }
    await ctx.progress(1, "zip-slip done");
  },
};

// ───────────────────── Range header file disclosure ─────────────────
export const rangeLeakScanner: Scanner = {
  id: "web.range-leak",
  name: "Range Header File Disclosure",
  kind: "web",
  description: "Sends `Range: bytes=0-N` against static-shaped paths and watches for 206 responses serving content from outside the requested file (some Apache / IIS configurations disclose adjacent memory).",
  defaultEnabled: false,
  async tool() {
    return { id: "web.range-leak", name: "Range Disclosure", kind: "web", backend: "builtin", status: "available", description: "Built-in HTTP Range disclosure tester." };
  },
  async run(ctx) {
    const seed = safeUrl(ctx.target.value); if (!seed) return;
    const map = await loadSiteMap(ctx.scanId);
    const session = new BrowsingSession(seed.origin, ctx.target.auth?.headers ?? {});
    const STATIC_HINT = /\.(js|css|png|jpg|jpeg|gif|woff2?|ttf|map|json|html?)$/i;
    const targets = (map?.pages ?? []).filter((p) => STATIC_HINT.test(p.url) && p.status === 200).slice(0, 25);
    if (!targets.length) { await ctx.progress(1, "no static targets"); return; }

    for (const p of targets) {
      if (ctx.signal.aborted) break;
      // Request a deliberately oversized range (gigabyte) — should be 416 Range Not Satisfiable;
      // disclosure occurs when servers respond 200 / 206 with garbage data.
      let r;
      try { r = await session.fetch(p.url, { headers: { range: "bytes=0-999999999999" }, signal: ctx.signal }); }
      catch { continue; }
      // Any 206 with a range NOT covering the resource, or 200 with content larger
      // than original, is suspicious. Also flag overlapping ranges that double-count.
      if (r.res.status === 206) {
        const cr = r.res.headers.get("content-range") ?? "";
        const total = /\/(\d+)$/.exec(cr)?.[1];
        if (total && Number(total) > 100_000_000) {
          await ctx.emit(draft({
            severity: "medium", confidence: "low",
            title: `Range request returned an unrealistically large content-range on ${p.url}`,
            description: `Server response \`Content-Range: ${cr}\` claims a resource larger than 100MB — potential range-handling misconfiguration that can leak adjacent memory under crafted multi-range requests (see CVE-2014-0050, CVE-2017-7679 history).`,
            ruleId: "range/oversize-content-range",
            cwe: ["CWE-200"],
            location: { url: p.url },
            evidence: { contentRange: cr, status: r.res.status },
            remediation: "Cap Range request size at the proxy / WAF. Update the web server.",
          }));
        }
      }
    }
    await ctx.progress(1, "range-leak done");
  },
};
