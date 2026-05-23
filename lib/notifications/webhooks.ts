/**
 * Webhook notifications — fire when a scan finishes.
 *
 * Supported flavors:
 *   - Slack incoming-webhook (auto-detected by `hooks.slack.com` in URL)
 *   - Discord webhook        (auto-detected by `discord.com/api/webhooks`)
 *   - Generic POST           (everything else — sent as raw JSON)
 *
 * Subscribed via `MOBA_WEBHOOK_URL` env var, or via a per-schedule
 * `notify.webhookUrl`. The bus listens for scan-finished events globally;
 * if the env var is set, every scan posts a notification.
 *
 * The bus is initialised on first import and lives for the lifetime of the
 * Node process. Idempotent — multiple imports won't subscribe twice.
 */

import { scanBus } from "../engine/events";
import { listFindings, getScan } from "../store";
import type { Finding, Severity } from "../types";

const SLACK_RE = /hooks\.slack\.com\/services/;
const DISCORD_RE = /discord(app)?\.com\/api\/webhooks/;

function severityIcon(sev: Severity): string {
  return ({ critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" } as const)[sev];
}

function buildSlackPayload(scanId: string, target: string, counts: Record<string, number>, top: Finding[]): unknown {
  const total = Object.values(counts).reduce((a, b) => (a as number) + (b as number), 0);
  const fieldsLine = (["critical","high","medium","low","info"] as const)
    .map((s) => `${severityIcon(s)} ${s}: ${counts[s] ?? 0}`).join("  ");
  return {
    text: `*moba-scanner* — scan complete on \`${target}\` — ${total} findings`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*moba-scanner* — scan complete on \`${target}\`\n${fieldsLine}` } },
      ...(top.length ? [{
        type: "section",
        text: { type: "mrkdwn",
          text: "*Top findings:*\n" + top.slice(0, 5).map((f) => `${severityIcon(f.severity)} *${f.severity.toUpperCase()}* — ${f.title}`).join("\n"),
        },
      }] : []),
      { type: "context", elements: [{ type: "mrkdwn", text: `Scan id: \`${scanId}\`` }] },
    ],
  };
}

function buildDiscordPayload(scanId: string, target: string, counts: Record<string, number>, top: Finding[]): unknown {
  const SEV_COLORS: Record<Severity, number> = { critical: 0xb3261e, high: 0xff8800, medium: 0xffcc00, low: 0x4477aa, info: 0x888888 };
  const dominant = (["critical","high","medium","low","info"] as const).find((s) => (counts[s] ?? 0) > 0) ?? "info";
  return {
    embeds: [{
      title: "moba-scanner — scan complete",
      description: `Target: \`${target}\``,
      color: SEV_COLORS[dominant],
      fields: (["critical","high","medium","low","info"] as const).map((s) => ({
        name: s.toUpperCase(), value: String(counts[s] ?? 0), inline: true,
      })).concat(top.length ? [{
        name: "Top findings",
        value: top.slice(0, 5).map((f) => `${severityIcon(f.severity)} ${f.title.slice(0, 80)}`).join("\n") || "—",
        inline: false,
      }] : []),
      footer: { text: `Scan id: ${scanId}` },
    }],
  };
}

function buildGenericPayload(scanId: string, target: string, counts: Record<string, number>, top: Finding[]): unknown {
  return { event: "scan.finished", scanId, target, counts, topFindings: top.slice(0, 10) };
}

async function deliver(url: string, scanId: string) {
  const scan = await getScan(scanId);
  if (!scan) return;
  const findings = await listFindings(scanId);
  const top = [...findings].sort((a, b) =>
    (({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<Severity, number>)[b.severity] -
     ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<Severity, number>)[a.severity]),
  );
  const target = scan.target.value;
  const counts = scan.counts;
  let body: unknown;
  if (SLACK_RE.test(url)) body = buildSlackPayload(scanId, target, counts, top);
  else if (DISCORD_RE.test(url)) body = buildDiscordPayload(scanId, target, counts, top);
  else body = buildGenericPayload(scanId, target, counts, top);
  try {
    await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) { console.warn("[webhook]", url, e instanceof Error ? e.message : e); }
}

declare global {
  // eslint-disable-next-line no-var
  var __mobaWebhookSubscribed: boolean | undefined;
}

export function startWebhookListener() {
  if (globalThis.__mobaWebhookSubscribed) return;
  globalThis.__mobaWebhookSubscribed = true;
  scanBus.on("*", async (event) => {
    if (event.kind !== "scan-finished") return;
    const url = process.env.MOBA_WEBHOOK_URL;
    if (url) await deliver(url, event.scanId);
  });
}
