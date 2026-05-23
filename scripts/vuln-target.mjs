/**
 * Intentionally vulnerable Node target — for moba-scanner self-tests.
 *
 * EVERY route here is wrong on purpose. Do NOT expose this beyond localhost.
 *
 * Vulnerability checklist (each one is what a scanner SHOULD detect):
 *   [headers]  No HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy
 *   [headers]  Server: vulnserver/1.2.3   (version disclosure)
 *   [headers]  X-Powered-By: Express      (framework disclosure)
 *   [cookies]  Set-Cookie on root: missing Secure / HttpOnly / SameSite
 *   [cookies]  session-shaped name without HttpOnly
 *   [cors]     Reflects arbitrary Origin + ACAC=true
 *   [cors]     ACAO=null trusted with credentials
 *   [tech]     Easy fingerprint via headers + body markers
 *   [crawler]  Multi-page site with internal links and a real form
 *   [active]   Reflected XSS:        /search?q=  echoes q into HTML unencoded
 *   [active]   Error-based SQLi:     /artist?id=  concatenates into in-memory SQL
 *   [active]   Open redirect:        /redirect?next=  Location: <attacker>
 *   [active]   LFI:                  /file?path=  reads + returns /etc/passwd
 *   [active]   Cmd injection:        /ping?host=  shells out to `ping`
 *   [active]   SSRF (AWS IMDS):      /fetch?url=  fetches arbitrary URL
 *   [form]     POST /comment reflects "name" + "msg" into HTML unencoded (real XSS)
 *   [brute]    POST /login accepts admin:admin and sets session cookie + redirects
 *   [verb]     /admin returns 403 on GET, 200 on PUT (verb-tampering bypass)
 *   [verb]     /admin honors X-HTTP-Method-Override: GET when called with POST
 *   [idor]     /profile/{1..3} return different user data, no auth
 *   [param]    /info?debug=1 dumps environment
 *   [content]  /.env, /.git/config, /admin, /server-status reachable
 *   [graphql]  /graphql introspection enabled, returns __schema
 *   [jwt]      /api/me returns Set-Cookie token=<jwt with alg=none>
 *   [csrf]     POST /transfer has no CSRF token
 */

import http from "node:http";
import { URL } from "node:url";
import { randomBytes, createHmac } from "node:crypto";

// Pre-compute a real HS256 JWT signed with the weak secret "secret".
function b64url(b) { return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
const _hdr = b64url(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
const _pl  = b64url(Buffer.from(JSON.stringify({ user: "guest", role: "user" })));
const _sig = b64url(createHmac("sha256", "secret").update(`${_hdr}.${_pl}`).digest());
const HS256_WEAK = `${_hdr}.${_pl}.${_sig}`;

const PORT = Number(process.env.PORT) || 4444;

// ───────────────────────────── seed data ──────────────────────────────
const USERS = [
  { id: 1, name: "Admin",  email: "admin@target.local", secret: "flag{idor-admin}" },
  { id: 2, name: "Alice",  email: "alice@target.local", secret: "flag{idor-alice}" },
  { id: 3, name: "Bob",    email: "bob@target.local",   secret: "flag{idor-bob}" },
];
const ARTISTS = [
  { id: 1, name: "Pink Floyd",    bio: "British rock band" },
  { id: 2, name: "Radiohead",     bio: "Oxford alt rock" },
  { id: 3, name: "Aphex Twin",    bio: "Cornwall electronic" },
];
const COMMENTS = [];
let LOGGED_IN = false; // global because we don't care about session correctness

// ───────────────────────────── helpers ────────────────────────────────
function send(res, status, body, extra = {}) {
  // Intentionally NOT setting any security headers.
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "server": "vulnserver/1.2.3",
    "x-powered-by": "Express",
    ...extra,
  };
  res.writeHead(status, headers);
  res.end(body);
}
function sendJson(res, status, obj, extra = {}) {
  send(res, status, JSON.stringify(obj), { "content-type": "application/json", ...extra });
}
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}
function parseForm(body) {
  const out = {};
  for (const pair of body.split("&")) {
    const [k, v = ""] = pair.split("=");
    if (k) out[decodeURIComponent(k.replace(/\+/g, " "))] = decodeURIComponent(v.replace(/\+/g, " "));
  }
  return out;
}

// ───────────────────────────── pages ──────────────────────────────────
function layout(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<script src="/static/app.js"></script></head>
<body style="font-family:sans-serif;max-width:780px;margin:2em auto;line-height:1.5">
<header><a href="/">home</a> · <a href="/search">search</a> · <a href="/artist?id=1">artist</a> · <a href="/comments">comments</a> · <a href="/login">login</a> · <a href="/admin">admin</a> · <a href="/profile/1">profiles</a> · <a href="/redirect?next=/about">go</a></header>
<hr>${body}<hr>
<footer><small>vulnserver/1.2.3 — Express — for testing only</small></footer>
</body></html>`;
}

// ───────────────────────────── server ─────────────────────────────────
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = u.pathname.replace(/\/+$/, "") || "/";

  // ── CORS: blatantly broken (reflect any origin + creds) ──────────
  const reqOrigin = req.headers.origin;
  if (reqOrigin) {
    res.setHeader("access-control-allow-origin", reqOrigin === "null" ? "null" : reqOrigin);
    res.setHeader("access-control-allow-credentials", "true");
    res.setHeader("vary", "Origin");
  }

  // ── Set a session cookie on every request, missing all the flags ─
  if (!req.headers.cookie || !/session=/.test(req.headers.cookie)) {
    res.setHeader("set-cookie", [
      `session=${randomBytes(8).toString("hex")}; Path=/`,
      // alg=none JWT for the JWT scanner to flag:
      `auth_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.; Path=/`,
      // Crackable HS256 JWT for jwt-crack scanner:
      `signed_token=${HS256_WEAK}; Path=/`,
      // Java serialized object (rO0AB = base64 of magic bytes AC ED 00 05) — for deserialization scanner.
      `state=rO0ABXNyABFVc2VyU2Vzc2lvbkV4YW1wbGUyAQEBAQEBAQECdwIBAXg; Path=/`,
    ]);
  }

  // ── Verb-tampering route ────────────────────────────────────────
  if (pathname === "/admin") {
    const override = (req.headers["x-http-method-override"] || req.headers["x-http-method"] || req.headers["x-method-override"] || "").toString().toUpperCase();
    const effectiveMethod = override || req.method;
    if (effectiveMethod === "GET") {
      // Original GET → 403, but GET via override → 200.
      if (req.method === "GET") return send(res, 403, layout("Admin", "<h1>403 Forbidden</h1><p>Admins only. Use a real auth method.</p>"));
      return send(res, 200, layout("Admin (override)", "<h1>Welcome, admin (via override)</h1><p>flag{verb-tampering-bypass}</p>"));
    }
    if (req.method === "PUT" || req.method === "DELETE" || req.method === "PATCH") {
      // Auth check missing on these methods (verb-tampering vector).
      return send(res, 200, layout("Admin (verb)", `<h1>Admin via ${req.method}</h1><p>flag{verb-tampering-method}</p>`));
    }
    return send(res, 403, layout("Admin", "<h1>403</h1>"));
  }

  // ── Sensitive paths reachable (content-discovery) ───────────────
  if (pathname === "/.env") return send(res, 200, "DATABASE_URL=postgres://admin:hunter2@db.local/prod\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", { "content-type": "text/plain" });
  if (pathname === "/.git/config") return send(res, 200, "[core]\n  repositoryformatversion = 0\n[remote \"origin\"]\n  url = git@github.com:internal/secret-repo.git\n", { "content-type": "text/plain" });
  if (pathname === "/server-status") return send(res, 200, "<h1>Apache Server Status</h1><pre>BusyWorkers: 4\nIdleWorkers: 7</pre>");
  if (pathname === "/robots.txt") return send(res, 200, "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.git\n", { "content-type": "text/plain" });

  // ── GraphQL introspection ──────────────────────────────────────
  if (pathname === "/graphql") {
    if (req.method === "POST") {
      const body = await readBody(req);
      try {
        const q = JSON.parse(body).query ?? "";
        if (/__schema|queryType|mutationType/.test(q)) {
          return sendJson(res, 200, {
            data: {
              __schema: {
                queryType: { name: "Query" },
                mutationType: { name: "Mutation" },
                subscriptionType: null,
                types: [
                  { name: "Query" }, { name: "Mutation" }, { name: "User" }, { name: "Order" }, { name: "Secret" },
                ],
              },
            },
          });
        }
      } catch {}
    }
    return sendJson(res, 200, { data: null, errors: [{ message: "send a query" }] });
  }

  // ── /api/me — returns a JWT alg=none in body too ───────────────
  if (pathname === "/api/me") {
    return sendJson(res, 200, { user: "guest", jwt: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QifQ." });
  }

  // ── /search — reflected XSS in q ────────────────────────────────
  if (pathname === "/search") {
    const q = u.searchParams.get("q") ?? "";
    return send(res, 200, layout("Search",
      `<h1>Search</h1>
      <form method="GET" action="/search"><input name="q" placeholder="search…" value="${q /* INTENTIONALLY UNESCAPED */}"><button>Go</button></form>
      <p>You searched for: ${q /* UNESCAPED */}</p>`));
  }

  // ── /artist?id=N — multi-DBMS SQLi (error / boolean / time / union) ─
  if (pathname === "/artist") {
    const idStr = u.searchParams.get("id") ?? "";
    // Time-based simulation: when payload contains a sleep, actually wait.
    if (/sleep\s*\(\s*(\d+)/i.test(idStr) || /pg_sleep\s*\(\s*(\d+)/i.test(idStr) || /WAITFOR\s+DELAY\s+'0:0:(\d+)/i.test(idStr) || /DBMS_PIPE\.RECEIVE_MESSAGE\(\s*'a',\s*(\d+)/i.test(idStr) || /randomblob\s*\(\s*(\d+)/i.test(idStr)) {
      const m = /sleep\s*\(\s*(\d+)\)/i.exec(idStr) || /pg_sleep\s*\(\s*(\d+)\)/i.exec(idStr) || /WAITFOR\s+DELAY\s+'0:0:(\d+)/i.exec(idStr) || /DBMS_PIPE\.RECEIVE_MESSAGE\(\s*'a',\s*(\d+)\)/i.exec(idStr) || /randomblob\s*\(\s*(\d+)/i.exec(idStr);
      const sec = Math.min(Number(m?.[1] ?? "0"), 8);
      return new Promise((resolve) => {
        setTimeout(() => {
          send(res, 200, layout("Artist", `<h1>Result</h1><p>Slept ${sec}s (timeing oracle)</p>`));
          resolve();
        }, sec * 1000);
      });
    }
    // Error-based: trigger MySQL/Postgres/MSSQL/Oracle/SQLite error strings
    // depending on payload — easy way for the scanner to fingerprint DBMS.
    if (/['"`)\\]/.test(idStr)) {
      const err = idStr.includes("(SELECT @@version)") || idStr.toLowerCase().includes("convert(int")
        ? `Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string '${idStr.replace(/</g, "&lt;")}'.`
        : idStr.toLowerCase().includes("pg_") || idStr.toLowerCase().includes("postgresql")
          ? `PostgreSQL ERROR: syntax error at or near "'${idStr.replace(/</g, "&lt;")}'" at line 1`
          : idStr.toLowerCase().includes("ora-") || /dbms_pipe/i.test(idStr)
            ? `ORA-01756: quoted string not properly terminated near '${idStr.replace(/</g, "&lt;")}'`
            : idStr.toLowerCase().includes("randomblob") || idStr.toLowerCase().includes("sqlite")
              ? `SQLite.Exception: near "'${idStr.replace(/</g, "&lt;")}'": syntax error`
              : `You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '${idStr.replace(/</g, "&lt;")}' at line 1`;
      return send(res, 500, layout("Artist", `<h1>SQL error</h1><pre>${err}</pre>`));
    }
    // Boolean-based: AND 1=1 returns the artist, AND 1=2 returns "no result".
    const isFalseBool = /AND\s+1=2|AND\s+'1'='2|AND\s+\d+=\d+/i.test(idStr) && /AND\s+(?:1=2|'1'='2)/i.test(idStr);
    const isTrueBool  = /AND\s+1=1|AND\s+'1'='1|AND\s+\d+=\d+/i.test(idStr) && /AND\s+(?:1=1|'1'='1)/i.test(idStr);
    // ORDER BY: succeed up to 4 columns, error beyond — column-count discovery.
    const ob = /ORDER\s+BY\s+(\d+)/i.exec(idStr);
    if (ob) {
      const n = Number(ob[1]);
      if (n > 4) return send(res, 500, layout("Artist", `<h1>SQL error</h1><pre>You have an error in your SQL syntax: column ${n} out of range</pre>`));
      // continue to render artist below
    }
    if (isFalseBool) return send(res, 200, layout("Artist", `<h1>No result</h1>`));
    if (isTrueBool || /select|union/i.test(idStr)) {
      const a = ARTISTS[0];
      return send(res, 200, layout("Artist", `<h1>${a.name}</h1><p>${a.bio}</p>`));
    }
    const id = Number(idStr);
    const a = ARTISTS.find((x) => x.id === id) ?? ARTISTS[0];
    return send(res, 200, layout("Artist", `<h1>${a.name}</h1><p>${a.bio}</p>`));
  }

  // ── Header-based SQLi via User-Agent (logged into DB unsanitized) ───
  if (pathname === "/log-ua") {
    const ua = (req.headers["user-agent"] ?? "").toString();
    if (/['"`]/.test(ua)) {
      return send(res, 500, layout("LogUA", `<h1>SQL error</h1><pre>You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '${ua.replace(/</g, "&lt;").slice(0, 100)}' at line 1</pre>`));
    }
    return send(res, 200, layout("LogUA", `<p>UA logged.</p>`));
  }

  // ── CVE-shaped markers ────────────────────────────────────────────
  if (pathname === "/struts2-rest-showcase" || pathname === "/struts2-rest-showcase/") {
    return send(res, 200, layout("Struts2 Rest Showcase", `<h1>Struts2 Rest Showcase</h1>`));
  }
  if (pathname === "/solr/" || pathname === "/solr/admin/cores") {
    return send(res, 200, "<title>Solr Admin</title><body>Apache Solr 7.4.0</body>", { "content-type": "text/html" });
  }
  if (pathname === "/manager/html") {
    return send(res, 401, "<title>Apache Tomcat - 401</title>", { "content-type": "text/html", "www-authenticate": 'Basic realm="Tomcat Manager Application"' });
  }
  if (pathname === "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php") {
    return send(res, 200, "phpunit eval-stdin", { "content-type": "text/plain" });
  }
  if (pathname === "/server-info.action") {
    return send(res, 200, "<title>Confluence Setup</title>");
  }
  if (pathname === "/_cat/indices") {
    return send(res, 200, '"docs.count" 1234', { "content-type": "text/plain" });
  }
  if (pathname === "/script") {
    return send(res, 200, "<title>Jenkins Script Console</title><pre>groovy.lang.Binding</pre>");
  }
  if (pathname === "/wls-wsat/CoordinatorPortType") {
    return send(res, 200, "<title>WebLogic WLS-WSAT</title>");
  }
  if (pathname === "/json/setup-restore.action") {
    return send(res, 200, "<title>Confluence Setup Restore</title>");
  }

  // ── /redirect?next= — open redirect ────────────────────────────
  if (pathname === "/redirect") {
    const next = u.searchParams.get("next") ?? "/";
    res.writeHead(302, { location: next, "server": "vulnserver/1.2.3" });
    return res.end();
  }

  // ── /file?path= — LFI ──────────────────────────────────────────
  if (pathname === "/file") {
    const p = u.searchParams.get("path") ?? "readme.md";
    if (p.includes("etc/passwd") || /\.\./.test(p)) {
      return send(res, 200, "root:x:0:0:root:/root:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\n", { "content-type": "text/plain" });
    }
    if (p.includes("boot.ini")) {
      return send(res, 200, "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n", { "content-type": "text/plain" });
    }
    return send(res, 200, layout("File", `<pre>(would have served ${p})</pre>`));
  }

  // ── /ping?host= — command injection ─────────────────────────────
  if (pathname === "/ping") {
    const h = u.searchParams.get("host") ?? "";
    if (/[;|&`$]/.test(h) && /id\b|whoami|cat\s|uname/i.test(h)) {
      // Pretend we ran the cmd.
      return send(res, 200, layout("Ping", `<pre>PING ${h.split(/[;|&]/)[0]}\nuid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>`));
    }
    return send(res, 200, layout("Ping", `<pre>PING ${h}\n64 bytes from ${h}: icmp_seq=1 ttl=64 time=0.123 ms</pre>`));
  }

  // ── /fetch?url= — SSRF (returns canned IMDS body for AWS) ──────
  if (pathname === "/fetch") {
    const target = u.searchParams.get("url") ?? "";
    if (/169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1/.test(target)) {
      return send(res, 200, "ami-id\nami-launch-index\ninstance-id\ni-0123456789abcdef0\niam/security-credentials/admin-role\n", { "content-type": "text/plain" });
    }
    return send(res, 200, layout("Fetch", `<pre>(would have fetched ${target})</pre>`));
  }

  // ── /comments — POST form, stored XSS ──────────────────────────
  if (pathname === "/comments") {
    if (req.method === "POST") {
      const body = await readBody(req);
      const f = parseForm(body);
      // Reflect input back unescaped + persist for stored XSS.
      COMMENTS.push({ name: f.name ?? "", msg: f.msg ?? "" });
      return send(res, 200, layout("Comments",
        `<h1>Thanks ${f.name /* UNESCAPED */}</h1>
        <p>Your comment: ${f.msg /* UNESCAPED */}</p>
        <p><a href="/comments">back</a></p>`));
    }
    return send(res, 200, layout("Comments",
      `<h1>Comments</h1>
      <form method="POST" action="/comments">
        <input name="name" placeholder="name">
        <textarea name="msg" placeholder="message"></textarea>
        <input name="size" type="hidden" value="default">
        <button>Post</button>
      </form>
      <h2>Recent</h2>
      ${COMMENTS.map((c) => `<div><strong>${c.name}</strong>: ${c.msg}</div>`).join("\n")}`));
  }

  // ── /transfer — POST without CSRF token + mass-assignment surface ──
  if (pathname === "/transfer") {
    if (req.method === "POST") {
      const f = parseForm(await readBody(req));
      // Mass-assignment vuln: blindly reflect every field, including isAdmin.
      const extra = Object.entries(f).filter(([k]) => !["to", "amount"].includes(k))
        .map(([k, v]) => `${k}=${v}`).join(", ");
      return send(res, 200, layout("Transfer",
        `<h1>Transferred ${f.amount ?? 0} to ${f.to ?? ""}</h1>${extra ? `<p>Bonus fields applied: ${extra}</p>` : ""}`));
    }
    return send(res, 200, layout("Transfer",
      `<form method="POST" action="/transfer">
        <input name="to" placeholder="recipient">
        <input name="amount" placeholder="amount" type="number">
        <button>Send</button>
      </form>`));
  }

  // ── /login — accepts admin:admin (default cred) + NoSQLi via JSON ─
  if (pathname === "/login") {
    if (req.method === "POST") {
      const raw = await readBody(req);
      const ct = (req.headers["content-type"] ?? "").toString();
      let f;
      if (ct.includes("application/json")) {
        try { f = JSON.parse(raw); }
        catch { return send(res, 400, layout("Login", "<h1>bad json</h1>")); }
        // NoSQL injection: object types bypass equality.
        if ((typeof f.username === "object" && f.username !== null) || (typeof f.password === "object" && f.password !== null)) {
          LOGGED_IN = true;
          res.setHeader("set-cookie", `auth=admin-nosqli; Path=/`);
          res.writeHead(302, { location: "/dashboard", "server": "vulnserver/1.2.3" });
          return res.end();
        }
      } else {
        f = parseForm(raw);
      }
      // LDAP injection vuln: filter break payloads bypass.
      if (typeof f.username === "string" && /[*)(|&]/.test(f.username) && /\)\(|=\*|\(uid|\(cn/.test(f.username)) {
        LOGGED_IN = true;
        res.setHeader("set-cookie", `auth=admin-ldap-bypass; Path=/`);
        res.writeHead(302, { location: "/dashboard", "server": "vulnserver/1.2.3" });
        return res.end();
      }
      // Username enumeration: known users get distinct error.
      const KNOWN_USERS = ["admin", "test", "guest", "alice", "bob"];
      if (typeof f.username === "string" && KNOWN_USERS.includes(f.username) && f.password !== "admin" && f.password !== "test" && f.password !== "guest") {
        return send(res, 401, layout("Login", `<h1>Wrong password for "${f.username}"</h1><a href="/login">try again</a>`));
      }
      const ok = (f.username === "admin" && f.password === "admin")
              || (f.username === "test"  && f.password === "test")
              || (f.username === "guest" && f.password === "guest");
      if (ok) {
        LOGGED_IN = true;
        res.setHeader("set-cookie", `auth=admin-${randomBytes(4).toString("hex")}; Path=/`);
        res.writeHead(302, { location: "/dashboard", "server": "vulnserver/1.2.3" });
        return res.end();
      }
      return send(res, 401, layout("Login", `<h1>Invalid credentials</h1><a href="/login">try again</a>`));
    }
    return send(res, 200, layout("Login",
      `<form method="POST" action="/login">
        <input name="username" placeholder="username">
        <input name="password" placeholder="password" type="password">
        <button>Sign in</button>
      </form>`));
  }
  if (pathname === "/dashboard") {
    if (!LOGGED_IN) return send(res, 401, layout("Dashboard", "<h1>Login required</h1>"));
    return send(res, 200, layout("Dashboard", "<h1>Welcome, admin</h1><p>logout</p><p>profile</p>"));
  }
  // ── /logout — vulnerably leaves server-side session intact ──────
  if (pathname === "/logout") {
    // Buggy: clear cookie on browser, but DON'T flip LOGGED_IN. Subsequent
    // requests with the same auth cookie still pass the /dashboard auth check.
    res.setHeader("set-cookie", "auth=; Path=/; Max-Age=0");
    res.writeHead(302, { location: "/", "server": "vulnserver/1.2.3" });
    return res.end();
  }
  // ── /oauth/authorize — redirect_uri unchecked ──────────────────
  if (pathname === "/oauth/authorize") {
    const redir = u.searchParams.get("redirect_uri") ?? "";
    // Vulnerable: blindly redirect to whatever redirect_uri says.
    if (redir) {
      res.writeHead(302, { location: redir, "server": "vulnserver/1.2.3" });
      return res.end();
    }
    return send(res, 200, layout("OAuth", `<h1>OAuth authorize</h1><p>Provide redirect_uri.</p>`));
  }

  // ── /profile/{n} — IDOR ─────────────────────────────────────────
  const profileMatch = pathname.match(/^\/profile\/(\d+)$/);
  if (profileMatch) {
    const id = Number(profileMatch[1]);
    const user = USERS.find((x) => x.id === id);
    if (!user) return send(res, 404, layout("Profile", "<h1>Not found</h1>"));
    return send(res, 200, layout(`Profile #${id}`,
      `<h1>${user.name}</h1>
      <p>email: ${user.email}</p>
      <p>secret: ${user.secret}</p>`));
  }

  // ── /greet — SSTI (returns user-controlled into "template"-style string) ─
  if (pathname === "/greet") {
    const name = u.searchParams.get("name") ?? "Guest";
    // Naive "template": evaluate {{N*M}} server-side.
    const rendered = name.replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
    const rendered2 = rendered.replace(/\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}/g, (_, a, b) => String(Number(a) * Number(b)));
    const rendered3 = rendered2.replace(/<%=\s*(\d+)\s*\*\s*(\d+)\s*%>/g, (_, a, b) => String(Number(a) * Number(b)));
    return send(res, 200, layout("Greet", `<h1>Hello, ${rendered3}</h1>`));
  }

  // ── /api/login-json — NoSQL injection via JSON body ─────────────
  if (pathname === "/api/login-json" && req.method === "POST") {
    const body = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(body); } catch { return sendJson(res, 400, { error: "bad json" }); }
    // Vulnerable: passes through Mongo-style operators.
    const userOK = typeof parsed.username === "object" || parsed.username === "admin";
    const passOK = typeof parsed.password === "object" || parsed.password === "admin";
    if (userOK && passOK) {
      res.setHeader("set-cookie", `auth=admin-bypass; Path=/`);
      res.writeHead(302, { location: "/dashboard", "server": "vulnserver/1.2.3" });
      return res.end();
    }
    return sendJson(res, 401, { error: "Invalid credentials" });
  }

  // ── /xml-receive — accepts XML, expands entities (XXE) ──────────
  if (pathname === "/xml-receive" && req.method === "POST") {
    const body = await readBody(req);
    // Vulnerable XML "parser": resolves SYSTEM entities by reading the file.
    const dtMatch = /<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">/i.exec(body);
    let expanded = body;
    if (dtMatch) {
      const [, ent, file] = dtMatch;
      let content = "";
      if (/etc\/passwd/i.test(file)) content = "root:x:0:0:root:/root:/bin/bash\n";
      if (/win\.ini/i.test(file))    content = "[boot loader]\ntimeout=30\n";
      expanded = expanded.replace(new RegExp(`&${ent};`, "g"), content);
    }
    const root = /<r>([\s\S]*?)<\/r>/.exec(expanded);
    return send(res, 200, `<resp>${root ? root[1] : ""}</resp>`, { "content-type": "application/xml" });
  }

  // ── /api/profile — prototype pollution via JSON ────────────────
  // Holds a global "settings" object that subsequent requests read.
  if (pathname === "/api/profile" && req.method === "POST") {
    const body = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(body); } catch { return sendJson(res, 400, { error: "bad json" }); }
    // Vulnerable merge — copies into a SHARED object's prototype.
    function vulnerableMerge(target, source) {
      for (const k of Object.keys(source)) {
        if (source[k] !== null && typeof source[k] === "object") {
          if (!target[k]) target[k] = {};
          vulnerableMerge(target[k], source[k]);
        } else {
          target[k] = source[k];
        }
      }
    }
    if (!global.SETTINGS) global.SETTINGS = {};
    vulnerableMerge(global.SETTINGS, parsed);
    // Subsequent reads expose polluted properties via Object.prototype lookups.
    const newObj = {};
    return sendJson(res, 200, { ok: true, polluted: newObj.polluted ?? null, settings: global.SETTINGS });
  }

  // ── /header-echo — CRLF injection via lang param ────────────────
  if (pathname === "/header-echo") {
    const lang = u.searchParams.get("lang") ?? "en";
    // Vulnerable: writes raw user value into header.
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "server": "vulnserver/1.2.3",
      "content-language": lang, // raw — \r\n in value injects new headers
    });
    return res.end(`<h1>Lang: ${lang}</h1>`);
  }

  // ── /reset — X-Forwarded-Host reflected into reset link ──────────
  if (pathname === "/reset") {
    // Vulnerable: trust X-Forwarded-Host (set by attackers when no proxy validates).
    const host = req.headers["x-forwarded-host"] || req.headers.host || "localhost";
    return send(res, 200, layout("Password Reset", `<h1>Reset link sent</h1><p>Visit https://${host}/reset/confirm?token=abc123 to continue.</p>`));
  }

  // ── /api/jsonp — JSONP callback (data leak vector) ────────────────
  if (pathname === "/api/jsonp") {
    const cb = u.searchParams.get("callback") ?? u.searchParams.get("jsonp") ?? "";
    // Vulnerable: wrap response in attacker-controlled callback name.
    return send(res, 200, `${cb}({"user":"alice","email":"alice@target.local","balance":1234})`, { "content-type": "application/javascript" });
  }
  // ── /search-xml — XPath injection ────────────────────────────────
  if (pathname === "/search-xml") {
    const q = u.searchParams.get("q") ?? "";
    if (/['"]/.test(q)) {
      return send(res, 500, layout("Search XML", `<h1>XPathException: invalid token in xpath at position 12 near '${q.replace(/</g, "&lt;").slice(0, 60)}'</h1>`));
    }
    return send(res, 200, layout("Search XML", `<h1>XML search results for: ${q}</h1>`));
  }
  // ── /tpl?greeting= — SSI injection ───────────────────────────────
  if (pathname === "/tpl") {
    let g = u.searchParams.get("greeting") ?? "Hello";
    // Vulnerable "SSI processor": evaluates #exec cmd="echo X"
    g = g.replace(/<!--#exec\s+cmd="echo\s+([^"]+)"\s*-->/g, (_, cmd) => cmd);
    return send(res, 200, layout("Template", `<h1>${g}</h1>`));
  }
  // ── /static/app.js + /static/app.js.map (source map exposure) ─────
  if (pathname === "/static/app.js") {
    return send(res, 200, "console.log('app');//# sourceMappingURL=/static/app.js.map", { "content-type": "application/javascript" });
  }
  if (pathname === "/static/app.js.map") {
    return send(res, 200, JSON.stringify({ version: 3, sources: ["src/index.ts"], names: [], mappings: "" }), { "content-type": "application/json" });
  }
  // ── /api/duplicate?key=A — HPP demonstration ─────────────────────
  if (pathname === "/api/duplicate") {
    const all = u.searchParams.getAll("key");
    // Vulnerable: pick LAST value, regardless of count. Bypasses front-end filters.
    const value = all[all.length - 1] ?? "";
    return send(res, 200, layout("HPP", `<h1>Last value: ${value}</h1><p>${all.length} values: ${all.join(", ")}</p>`));
  }
  // ── /home — cacheable + reflects X-Forwarded-Host ────────────────
  if (pathname === "/home") {
    const xfh = req.headers["x-forwarded-host"] ?? req.headers.host;
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "server": "vulnserver/1.2.3",
      "cache-control": "public, max-age=600",
    });
    return res.end(layout("Home", `<h1>Welcome</h1><p>Hosted at https://${xfh}/</p>`));
  }
  // ── /info — hidden parameter `debug` ────────────────────────────
  if (pathname === "/info") {
    const debug = u.searchParams.get("debug");
    if (debug === "1" || debug === "true") {
      return send(res, 200, layout("Info (debug)",
        `<h1>Debug info</h1>
        <pre>VERSION=1.2.3
DATABASE_URL=postgres://admin:hunter2@db.local/prod
SESSION_SECRET=keyboardcat
NODE_ENV=production</pre>`));
    }
    return send(res, 200, layout("Info", "<h1>Info</h1><p>About this app.</p>"));
  }

  // ── / — index with multiple internal links ──────────────────────
  if (pathname === "/") {
    return send(res, 200, layout("Vulnerable App",
      `<h1>vulnserver/1.2.3</h1>
      <p>Welcome.</p>
      <ul>
        <li><a href="/search?q=hello">search</a></li>
        <li><a href="/artist?id=1">artist 1</a></li>
        <li><a href="/artist?id=2">artist 2</a></li>
        <li><a href="/comments">comments</a></li>
        <li><a href="/login">login</a></li>
        <li><a href="/admin">admin</a></li>
        <li><a href="/profile/1">profile/1</a></li>
        <li><a href="/profile/2">profile/2</a></li>
        <li><a href="/profile/3">profile/3</a></li>
        <li><a href="/redirect?next=/about">about</a></li>
        <li><a href="/file?path=readme.md">file viewer</a></li>
        <li><a href="/ping?host=example.com">ping</a></li>
        <li><a href="/fetch?url=https://example.com">fetch</a></li>
        <li><a href="/info">info</a></li>
        <li><a href="/transfer">transfer</a></li>
        <li><a href="/api/me">api/me</a></li>
        <li><a href="/greet?name=Guest">greet</a></li>
        <li><a href="/header-echo?lang=en">header-echo</a></li>
        <li><a href="/reset">password reset</a></li>
        <li><a href="/xml-receive">xml-receive</a></li>
        <li><a href="/api/profile">api/profile</a></li>
        <li><a href="/api/login-json">api/login-json</a></li>
        <li><a href="/log-ua">log-ua (UA logger)</a></li>
        <li><a href="/api/jsonp?callback=jQuery">api/jsonp</a></li>
        <li><a href="/search-xml?q=test">search-xml</a></li>
        <li><a href="/tpl?greeting=Hi">template</a></li>
        <li><a href="/static/app.js">static/app.js</a></li>
        <li><a href="/api/duplicate?key=A">api/duplicate (HPP)</a></li>
        <li><a href="/home">home (cacheable)</a></li>
        <li><a href="/logout">logout</a></li>
        <li><a href="/oauth/authorize?client_id=app&redirect_uri=http://localhost:4444/cb">oauth/authorize</a></li>
        <li><a href="http://insecure.example.com" target="_blank">external</a></li>
      </ul>`));
  }

  // ── /about — leaf page ─────────────────────────────────────────
  if (pathname === "/about") return send(res, 200, layout("About", "<h1>About</h1><p>Built on Express. Powered by gunicorn 19.9.0.</p>"));

  send(res, 404, layout("Not found", "<h1>404</h1>"));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`vulnerable target listening at http://127.0.0.1:${PORT}`);
});
