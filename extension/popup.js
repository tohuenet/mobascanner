/* moba-scanner browser-extension popup.
 *
 * This is the CAPTCHA-proof capture path: you log in to the target NORMALLY in
 * this Chrome (no automation flags, no remote-debugging port — nothing for
 * Google / Cloudflare / DataDome to detect), then click Capture. The extension
 * reads the live session via the trusted `chrome.cookies` API (decrypted by the
 * browser, immune to app-bound cookie encryption) plus the real User-Agent, and
 * hands them to the scanner so it requests the site AS the logged-in you.
 */

document.getElementById("capture").addEventListener("click", async () => {
  const endpoint = document.getElementById("endpoint").value.replace(/\/$/, "");
  const preset = document.getElementById("preset").value;
  const status = document.getElementById("status");
  status.className = "status";
  status.textContent = "capturing…";

  // 1) Active tab URL.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    status.className = "status err";
    status.textContent = "Open the target tab (http/https) first, logged in.";
    return;
  }
  const url = new URL(tab.url);

  // 2) Cookies for the whole ORIGIN (covers every path the crawl touches), plus
  //    the registrable domain so subdomain sessions come along.
  const seen = new Set();
  const cookies = [];
  const push = (list) => {
    for (const c of list) {
      const k = `${c.domain}|${c.name}`;
      if (!seen.has(k)) { seen.add(k); cookies.push(c); }
    }
  };
  push(await chrome.cookies.getAll({ url: url.origin }));
  const parts = url.hostname.split(".");
  if (parts.length >= 2) {
    const apex = parts.slice(-2).join(".");
    try { push(await chrome.cookies.getAll({ domain: apex })); } catch { /* ignore */ }
  }
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

  // 3) The real browser identity — so scanner requests match this Chrome, not a bot.
  const authHeaders = {};
  if (cookieHeader) authHeaders["cookie"] = cookieHeader;
  authHeaders["user-agent"] = navigator.userAgent;
  try {
    const ch = navigator.userAgentData;
    if (ch) {
      if (Array.isArray(ch.brands)) authHeaders["sec-ch-ua"] = ch.brands.map((b) => `"${b.brand}";v="${b.version}"`).join(", ");
      authHeaders["sec-ch-ua-mobile"] = ch.mobile ? "?1" : "?0";
      if (ch.platform) authHeaders["sec-ch-ua-platform"] = `"${ch.platform}"`;
    }
  } catch { /* client hints optional */ }
  authHeaders["accept-language"] = (navigator.languages && navigator.languages.join(",")) || navigator.language || "en-US,en;q=0.9";

  // 4) Preset selection.
  let presetDef;
  try { presetDef = await (await fetch(`${endpoint}/api/presets`)).json(); }
  catch { status.className = "status err"; status.textContent = `cannot reach moba-scanner at ${endpoint}`; return; }
  const enabled = presetDef.presets[preset]?.enabled ?? [];

  // 5) Start the scan with the captured session.
  status.textContent = `captured ${cookies.length} cookie(s) — starting scan…`;
  try {
    const r = await fetch(`${endpoint}/api/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        kind: "web",
        target: {
          value: url.origin + url.pathname,
          type: "url",
          auth: { headers: authHeaders },
        },
        selection: { enabled, options: presetDef.presets[preset]?.options ?? {} },
      }),
    });
    const j = await r.json();
    if (r.ok) {
      status.className = "status ok";
      status.innerHTML = `Scan started with your session (${cookies.length} cookies): <a href="${endpoint}/scans/${j.id}" target="_blank">${j.id}</a>`;
    } else {
      status.className = "status err";
      status.textContent = `error: ${j.error ?? r.status}`;
    }
  } catch (e) {
    status.className = "status err";
    status.textContent = `error: ${e?.message ?? e}`;
  }
});
