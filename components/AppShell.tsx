"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

const NAV: { href: string; label: string; icon: React.ReactNode; description: string }[] = [
  {
    href: "/",
    label: "Overview",
    description: "Dashboard, recent scans, posture summary",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 12 12 3l9 9" /><path d="M5 10v10a1 1 0 0 0 1 1h4v-7h4v7h4a1 1 0 0 0 1-1V10" />
      </svg>
    ),
  },
  {
    href: "/scan/web",
    label: "Web pentest",
    description: "DAST — crawl, intercept, fuzz",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
      </svg>
    ),
  },
  {
    href: "/scan/source",
    label: "Source pentest",
    description: "SAST / SCA — clone & analyze",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="m9 18-6-6 6-6" /><path d="m15 6 6 6-6 6" /><path d="m13 4-2 16" />
      </svg>
    ),
  },
  {
    href: "/scans",
    label: "Scans",
    description: "All scan runs & their findings",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18M9 4v16" />
      </svg>
    ),
  },
  {
    href: "/tools",
    label: "Tools",
    description: "Scanner CLIs — status & one-click install",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="m21 3-6 6" /><path d="m3 21 6-6" /><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4l-6 6 2.7 2.7 6-6a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.2-2.2z" />
      </svg>
    ),
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="flex flex-1 min-h-screen">
      {/* Sidebar — hidden on mobile, visible md+ */}
      <aside className="hidden md:flex sticky top-0 h-screen w-72 shrink-0 flex-col gap-4 p-4">
        <div className="glass-strong p-4 flex items-center gap-3">
          <div
            aria-hidden
            className="grid place-items-center w-10 h-10 rounded-xl text-[color:var(--md-on-primary)]"
            style={{ background: "linear-gradient(135deg, var(--md-primary), var(--md-tertiary))" }}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2 4 5v7a10 10 0 0 0 8 10 10 10 0 0 0 8-10V5z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div className="flex flex-col">
            <span className="md-title-m">moba scanner</span>
            <span className="md-label-s text-[color:var(--md-on-surface-variant)]">web + source pentest</span>
          </div>
        </div>

        <nav className="glass flex-1 flex flex-col gap-1 p-2">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`state-layer relative flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors ${
                  active
                    ? "bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)]"
                    : "text-[color:var(--md-on-surface)] hover:bg-[color-mix(in_oklab,var(--md-on-surface)_5%,transparent)]"
                }`}
              >
                <span className="grid place-items-center w-9 h-9 rounded-lg bg-[color-mix(in_oklab,var(--md-on-surface)_6%,transparent)]">
                  {item.icon}
                </span>
                <span className="flex flex-col">
                  <span className="md-label-l">{item.label}</span>
                  <span className="md-label-s text-[color:var(--md-on-surface-variant)]">{item.description}</span>
                </span>
              </Link>
            );
          })}
        </nav>

        <div className="glass-thin p-3 md-body-s text-[color:var(--md-on-surface-variant)]">
          Built for authorized testing only. Get written permission before scanning third-party targets.
        </div>
      </aside>

      {/* Main area */}
      <main className="flex-1 flex flex-col min-w-0">
        <header
          className={`sticky top-0 z-10 transition-[box-shadow,background] ${
            scrolled ? "glass-strong" : "glass"
          }`}
          style={{ borderRadius: 0, borderLeft: 0, borderRight: 0, borderTop: 0 }}
        >
          <div className="flex items-center gap-3 px-4 md:px-6 py-3">
            {/* Mobile-only brand */}
            <div className="md:hidden flex items-center gap-2">
              <span
                aria-hidden
                className="grid place-items-center w-8 h-8 rounded-lg text-[color:var(--md-on-primary)]"
                style={{ background: "linear-gradient(135deg, var(--md-primary), var(--md-tertiary))" }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2 4 5v7a10 10 0 0 0 8 10 10 10 0 0 0 8-10V5z" />
                </svg>
              </span>
              <span className="md-title-m">moba</span>
            </div>
            <div className="flex-1" />
            <div className="hidden sm:flex items-center gap-2 md-body-s text-[color:var(--md-on-surface-variant)]">
              <span className="sev-dot" style={{ background: "var(--md-severity-low)", color: "var(--md-severity-low)" }} />
              local · self-hosted
            </div>
          </div>
        </header>

        <div className="flex-1 px-4 md:px-6 lg:px-8 py-6 md:py-8 max-w-7xl w-full mx-auto">
          {children}
        </div>

        <footer className="px-6 py-6 md-body-s text-[color:var(--md-on-surface-variant)] text-center">
          moba-scanner · {new Date().getFullYear()} · open-source security tooling, wrapped in one console
        </footer>
      </main>
    </div>
  );
}
