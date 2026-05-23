/* moba-scanner companion — background service worker.
 * Currently a no-op; placeholder for future "right-click any element →
 * test this endpoint" context-menu integration.
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus?.create?.({
    id: "moba-scan-this",
    title: "moba-scanner: scan this URL",
    contexts: ["link", "page"],
  });
});

chrome.contextMenus?.onClicked?.addListener?.(async (info) => {
  if (info.menuItemId !== "moba-scan-this") return;
  const url = info.linkUrl ?? info.pageUrl;
  if (!url) return;
  // Default endpoint; user can change in popup.
  const endpoint = "http://localhost:3000";
  try {
    const presetDef = await (await fetch(`${endpoint}/api/presets`)).json();
    const enabled = presetDef.presets["quick"]?.enabled ?? [];
    await fetch(`${endpoint}/api/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind: "web", target: { value: url, type: "url" }, selection: { enabled } }),
    });
  } catch { /* tolerate */ }
});
