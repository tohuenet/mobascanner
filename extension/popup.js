/* moba-scanner browser-extension popup */

document.getElementById("capture").addEventListener("click", async () => {
  const endpoint = document.getElementById("endpoint").value.replace(/\/$/, "");
  const preset = document.getElementById("preset").value;
  const status = document.getElementById("status");
  status.className = "status";
  status.textContent = "capturing…";

  // 1) Get the active tab's URL.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) { status.className = "status err"; status.textContent = "no active URL"; return; }

  // 2) Pull cookies for that origin.
  const url = new URL(tab.url);
  const cookies = await chrome.cookies.getAll({ url: tab.url });

  // 3) Pull preset definition + selection.
  let presetDef;
  try { presetDef = await (await fetch(`${endpoint}/api/presets`)).json(); }
  catch (e) { status.className = "status err"; status.textContent = `cannot reach moba-scanner at ${endpoint}`; return; }
  const enabled = presetDef.presets[preset]?.enabled ?? [];

  // 4) Build cookie header.
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

  // 5) POST scan.
  const r = await fetch(`${endpoint}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      kind: "web",
      target: { value: url.origin + url.pathname, type: "url",
        ...(cookieHeader ? { auth: { headers: { cookie: cookieHeader } } } : {}) },
      selection: { enabled, options: presetDef.presets[preset]?.options ?? {} },
    }),
  });
  const j = await r.json();
  if (r.ok) {
    status.className = "status ok";
    status.innerHTML = `Scan started: <a href="${endpoint}/scans/${j.id}" target="_blank">${j.id}</a>`;
  } else {
    status.className = "status err";
    status.textContent = `error: ${j.error ?? r.status}`;
  }
});
