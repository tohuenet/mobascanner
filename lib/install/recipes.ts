/**
 * Structured, fixed install recipes for the external scanner CLIs this app wraps.
 *
 * SECURITY MODEL — read before editing:
 *   Every command below is a *server-side constant*. The install API only ever
 *   accepts a scanner `id` (validated against this map) and an optional method
 *   index — it NEVER accepts a package name, command, or argument from the
 *   client. The resolved command runs through `runCli`, which uses cross-spawn
 *   WITHOUT a shell, so args can't be re-parsed/expanded.
 *
 *   When moba-scanner runs in its Docker image, "install" mutates only the
 *   running container — the host is untouched, and changes are lost on
 *   container recreate (which is the expected behaviour: persistent additions
 *   should be baked into the Dockerfile). When running outside Docker, the
 *   localhost guard in the install route is the boundary.
 *
 * Tools that need an API key, a long-running daemon, or a manual binary download
 * (ZAP, MobSF, CodeQL, Dependency-Track, the threat-intel APIs, …) deliberately
 * have NO recipe here; the UI falls back to showing their installHint to copy.
 */

import { detectCli } from "../scanners/common";

export interface InstallMethod {
  /** Executable to invoke — must already be on PATH. */
  cmd: string;
  /** Fully literal argument vector. Never derived from user input. */
  args: string[];
  /** Human label for the package manager / approach (shown in the UI). */
  label: string;
  /** Optional caveat surfaced to the user (PATH, permissions, prerequisites). */
  note?: string;
}

// ── package-manager detection ────────────────────────────────────────────────
// Map each manager executable to the arg that makes it print a version quickly.
const VERSION_ARG: Record<string, string> = {
  go: "version",
  pip: "--version",
  pip3: "--version",
  pipx: "--version",
  python: "--version",
  py: "--version",
  npm: "--version",
  npx: "--version",
  gem: "--version",
  brew: "--version",
  "apt-get": "--version",
  docker: "--version",
  pwsh: "--version",
};

const detectCache = new Map<string, Promise<boolean>>();

/** True if `cmd` resolves on PATH. Cached for the life of the server process. */
export function cmdAvailable(cmd: string): Promise<boolean> {
  let p = detectCache.get(cmd);
  if (!p) {
    p = detectCli(cmd, VERSION_ARG[cmd] ?? "--version").then((v) => v !== null);
    detectCache.set(cmd, p);
  }
  return p;
}

// ── recipe builders (keep everything literal) ────────────────────────────────
const pipx = (pkg: string): InstallMethod => ({
  cmd: "pipx",
  args: ["install", pkg],
  label: "pipx",
  note: "Installs into /opt/pipx with a shim on PATH (Docker image's setup).",
});

const pip = (pkg: string): InstallMethod[] => [
  { cmd: "pip", args: ["install", pkg], label: "pip" },
  { cmd: "pip3", args: ["install", pkg], label: "pip3" },
  { cmd: "python", args: ["-m", "pip", "install", pkg], label: "python -m pip" },
  { cmd: "py", args: ["-m", "pip", "install", pkg], label: "py -m pip", note: "Windows Python launcher." },
];

const go = (mod: string): InstallMethod => ({
  cmd: "go",
  args: ["install", mod],
  label: "go install",
  note: "Needs Go. The binary lands in `go env GOBIN` (usually ~/go/bin) — make sure that's on your PATH.",
});

const npmGlobal = (pkg: string): InstallMethod => ({
  cmd: "npm",
  args: ["install", "-g", pkg],
  label: "npm -g",
});

const gem = (pkg: string): InstallMethod => ({ cmd: "gem", args: ["install", pkg], label: "gem install" });
const brew = (formula: string): InstallMethod => ({ cmd: "brew", args: ["install", formula], label: "brew" });
const apt = (pkg: string): InstallMethod => ({
  cmd: "apt-get",
  args: ["install", "-y", pkg],
  label: "apt-get",
  note: "Inside the Docker image apt-get runs as root; on a host install run as root or with sudo.",
});

/**
 * id → ordered install methods. The first method whose `cmd` is on PATH wins
 * when the user clicks "Install" without picking a specific one.
 */
export const INSTALL_RECIPES: Record<string, InstallMethod[]> = {
  // ── web · CLI ──
  "web.nuclei": [go("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")],
  "web.ffuf": [go("github.com/ffuf/ffuf/v2@latest")],
  "web.subfinder": [go("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")],
  "web.httpx": [go("github.com/projectdiscovery/httpx/cmd/httpx@latest")],
  "web.katana": [go("github.com/projectdiscovery/katana/cmd/katana@latest")],
  "web.naabu": [go("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")],
  "web.oob-interactsh": [go("github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")],
  "web.wapiti": [pipx("wapiti3"), ...pip("wapiti3")],
  "web.sqlmap": [pipx("sqlmap"), ...pip("sqlmap")],
  "web.nmap": [apt("nmap"), brew("nmap")],
  "web.nikto": [apt("nikto"), brew("nikto")],
  "web.masscan": [apt("masscan"), brew("masscan")],
  "web.testssl": [brew("testssl")],
  "web.dastardly": [
    { cmd: "docker", args: ["pull", "public.ecr.aws/portswigger/dastardly:latest"], label: "docker pull" },
  ],
  "web.dom-xss": [
    { cmd: "npx", args: ["playwright", "install", "chromium"], label: "npx playwright" },
  ],

  // ── source · CLI ──
  "source.semgrep": [pipx("semgrep"), ...pip("semgrep"), brew("semgrep")],
  "source.gitleaks": [go("github.com/gitleaks/gitleaks/v8@latest"), brew("gitleaks")],
  "source.trivy": [apt("trivy"), go("github.com/aquasecurity/trivy/cmd/trivy@latest"), brew("trivy")],
  "source.osv-scanner": [go("github.com/google/osv-scanner/cmd/osv-scanner@latest"), brew("osv-scanner")],
  "source.bandit": [pipx("bandit"), ...pip("bandit")],
  "source.brakeman": [gem("brakeman")],
  "source.checkov": [pipx("checkov"), ...pip("checkov")],
  "source.trufflehog": [go("github.com/trufflesecurity/trufflehog/v3@latest")],
  "source.detect-secrets": [pipx("detect-secrets"), ...pip("detect-secrets")],
  "source.snyk": [npmGlobal("snyk")],
  "source.dockle": [brew("goodwithtech/r/dockle")],
  "source.hadolint": [brew("hadolint")],
  "source.kube-bench": [brew("kube-bench")],
  "source.kube-hunter": [pipx("kube-hunter"), ...pip("kube-hunter")],
  "source.prowler": [pipx("prowler"), ...pip("prowler")],
  "source.scout-suite": [pipx("scoutsuite"), ...pip("scoutsuite")],
  "source.scubagear": [
    {
      cmd: "pwsh",
      args: ["-NoProfile", "-Command", "Install-Module -Name ScubaGear -Force -Scope CurrentUser"],
      label: "PowerShell Install-Module",
      note: "Requires PowerShell 7 (pwsh).",
    },
  ],
};

export function hasRecipe(id: string): boolean {
  return Object.prototype.hasOwnProperty.call(INSTALL_RECIPES, id);
}

export interface InstallPlan {
  id: string;
  methods: InstallMethod[];
  /** Index of the first method whose cmd is on PATH, or null if none are. */
  availableIndex: number | null;
}

export async function getInstallPlan(id: string): Promise<InstallPlan | null> {
  const methods = INSTALL_RECIPES[id];
  if (!methods) return null;
  let availableIndex: number | null = null;
  for (let i = 0; i < methods.length; i++) {
    if (await cmdAvailable(methods[i].cmd)) {
      availableIndex = i;
      break;
    }
  }
  return { id, methods, availableIndex };
}

export async function getAllInstallPlans(): Promise<Record<string, InstallPlan>> {
  const out: Record<string, InstallPlan> = {};
  await Promise.all(
    Object.keys(INSTALL_RECIPES).map(async (id) => {
      const plan = await getInstallPlan(id);
      if (plan) out[id] = plan;
    }),
  );
  return out;
}

/** Map of every manager cmd referenced by a recipe → whether it's installed. */
export async function detectManagers(): Promise<Record<string, boolean>> {
  const cmds = new Set<string>();
  for (const methods of Object.values(INSTALL_RECIPES)) for (const m of methods) cmds.add(m.cmd);
  const entries = await Promise.all([...cmds].map(async (c) => [c, await cmdAvailable(c)] as const));
  return Object.fromEntries(entries);
}

/**
 * Validate a client-supplied (id, methodIndex) pair and return the concrete,
 * server-defined method. Returns null if the id has no recipe or the index is
 * out of range — the API treats null as a hard 400/404.
 */
export function resolveMethod(id: string, methodIndex: number): InstallMethod | null {
  const methods = INSTALL_RECIPES[id];
  if (!methods) return null;
  if (!Number.isInteger(methodIndex) || methodIndex < 0 || methodIndex >= methods.length) return null;
  return methods[methodIndex];
}
