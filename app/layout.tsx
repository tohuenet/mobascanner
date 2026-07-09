import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AppShell } from "@/components/AppShell";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "moba scanner — web + source pentest console",
  description: "Acunetix-style web pentest + SonarQube-style source code security in one console.",
};

/**
 * No-FOUC theme bootstrap. Runs synchronously, before the browser paints the
 * body, so the correct light/dark tokens are already resolved on first frame.
 *
 * Per the Next.js 16 docs (01-app/02-guides/scripts.md → "Inline Scripts"),
 * inline JS is injected with a raw <script> + dangerouslySetInnerHTML. We render
 * it as the first child of <body> (layout.md forbids hand-adding <head> meta, so
 * the Metadata API keeps owning <head>) — a raw inline script there executes
 * during HTML parse, ahead of hydration. It stamps data-theme on <html> from the
 * saved preference; "system"/unset falls through to @media (prefers-color-scheme)
 * in globals.css. <html> gets suppressHydrationWarning because this attribute is
 * added before React hydrates and would otherwise trip a mismatch warning.
 */
const themeScript = `(function(){try{var t=localStorage.getItem('moba-theme');document.documentElement.setAttribute('data-theme',(t==='light'||t==='dark')?t:'system');}catch(e){}})();`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col text-[color:var(--md-on-background)]">
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
