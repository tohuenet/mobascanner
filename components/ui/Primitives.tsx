/**
 * Lightweight M3-flavoured primitives. We deliberately don't pull a UI lib —
 * the design tokens in globals.css do the heavy lifting; these components are
 * just composition + accessibility wrappers.
 */

"use client";

import * as React from "react";

type ButtonVariant = "filled" | "tonal" | "outlined" | "text" | "elevated";

export const Button = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: ButtonVariant;
    size?: "sm" | "md" | "lg";
    leadingIcon?: React.ReactNode;
    trailingIcon?: React.ReactNode;
    block?: boolean;
  }
>(function Button(
  { variant = "filled", size = "md", leadingIcon, trailingIcon, block, className = "", children, ...rest },
  ref,
) {
  const sizeCls = { sm: "h-9 px-3 md-label-l", md: "h-11 px-5 md-label-l", lg: "h-12 px-6 md-title-m" }[size];
  const base = "state-layer inline-flex items-center justify-center gap-2 rounded-full select-none disabled:opacity-50 disabled:pointer-events-none transition-shadow";
  const variantCls = {
    filled:   "bg-[color:var(--md-primary)] text-[color:var(--md-on-primary)] shadow-sm",
    tonal:    "bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)]",
    outlined: "border border-[color:var(--md-outline)] text-[color:var(--md-on-surface)] bg-transparent",
    text:     "text-[color:var(--md-primary)] bg-transparent",
    elevated: "bg-[color:var(--md-surface-container-high)] text-[color:var(--md-on-surface)] shadow-md",
  }[variant];
  return (
    <button
      ref={ref}
      className={`${base} ${sizeCls} ${variantCls} ${block ? "w-full" : ""} ${className}`}
      {...rest}
    >
      {leadingIcon && <span className="grid place-items-center">{leadingIcon}</span>}
      <span>{children}</span>
      {trailingIcon && <span className="grid place-items-center">{trailingIcon}</span>}
    </button>
  );
});

export function Card({
  glass = "glass",
  className = "",
  children,
  ...rest
}: React.HTMLAttributes<HTMLDivElement> & { glass?: "glass" | "glass-strong" | "glass-thin" | "none" }) {
  const cls = glass === "none" ? "" : glass;
  return (
    <div className={`${cls} p-5 ${className}`} {...rest}>
      {children}
    </div>
  );
}

export function Chip({
  className = "",
  selected,
  children,
  onClick,
  ...rest
}: React.HTMLAttributes<HTMLSpanElement> & { selected?: boolean }) {
  const base = "inline-flex items-center gap-1.5 px-3 h-8 rounded-full md-label-l border transition-colors cursor-default state-layer";
  const tone = selected
    ? "bg-[color:var(--md-secondary-container)] text-[color:var(--md-on-secondary-container)] border-transparent"
    : "bg-[color-mix(in_oklab,var(--md-on-surface)_4%,transparent)] text-[color:var(--md-on-surface-variant)] border-[color:var(--md-outline-variant)]";
  return (
    <span className={`${base} ${tone} ${onClick ? "cursor-pointer" : ""} ${className}`} onClick={onClick} {...rest}>
      {children}
    </span>
  );
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export function SeverityBadge({ severity, children, className = "" }: { severity: Severity; children?: React.ReactNode; className?: string }) {
  const color = `var(--md-severity-${severity})`;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 h-6 rounded-full md-label-s uppercase tracking-wide ${className}`}
      style={{
        color,
        background: `color-mix(in oklab, ${color} 18%, transparent)`,
        border: `1px solid color-mix(in oklab, ${color} 40%, transparent)`,
      }}
    >
      <span className="sev-dot" style={{ background: color, color }} />
      {children ?? severity}
    </span>
  );
}

export function ProgressBar({
  value,
  indeterminate,
  className = "",
}: { value?: number; indeterminate?: boolean; className?: string }) {
  return (
    <div className={`relative w-full h-1.5 rounded-full overflow-hidden bg-[color-mix(in_oklab,var(--md-on-surface)_8%,transparent)] ${className}`}>
      <div
        className={`absolute inset-y-0 left-0 rounded-full ${indeterminate ? "stripe-anim" : ""}`}
        style={{
          width: indeterminate ? "100%" : `${Math.max(0, Math.min(1, value ?? 0)) * 100}%`,
          background: "linear-gradient(90deg, var(--md-primary), var(--md-tertiary))",
          transition: "width 240ms ease",
        }}
      />
    </div>
  );
}

export function TextField({
  label,
  hint,
  error,
  trailing,
  leading,
  className = "",
  ...rest
}: React.InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  error?: string;
  trailing?: React.ReactNode;
  leading?: React.ReactNode;
}) {
  const id = React.useId();
  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={id} className="md-label-l text-[color:var(--md-on-surface-variant)]">
        {label}
      </label>
      <div
        className={`flex items-center gap-2 px-3 h-12 rounded-xl border transition-colors ${
          error
            ? "border-[color:var(--md-error)]"
            : "border-[color:var(--md-outline-variant)] focus-within:border-[color:var(--md-primary)]"
        }`}
        style={{ background: "color-mix(in oklab, var(--md-surface-container-low) 80%, transparent)" }}
      >
        {leading && <span className="text-[color:var(--md-on-surface-variant)]">{leading}</span>}
        <input
          id={id}
          className="flex-1 bg-transparent outline-none placeholder:text-[color:var(--md-on-surface-variant)]/70 md-body-l"
          {...rest}
        />
        {trailing}
      </div>
      {error
        ? <span className="md-body-s text-[color:var(--md-error)]">{error}</span>
        : hint
          ? <span className="md-body-s text-[color:var(--md-on-surface-variant)]">{hint}</span>
          : null}
    </div>
  );
}

export function Switch({
  checked, onChange, label, hint,
}: { checked: boolean; onChange: (next: boolean) => void; label?: string; hint?: string }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <span
        className="relative inline-flex items-center rounded-full transition-colors h-6 w-11 border"
        style={{
          background: checked ? "var(--md-primary)" : "color-mix(in oklab, var(--md-on-surface) 14%, transparent)",
          borderColor: checked ? "var(--md-primary)" : "var(--md-outline)",
        }}
      >
        <input type="checkbox" className="sr-only" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span
          className="absolute h-4 w-4 rounded-full bg-white shadow transition-transform"
          style={{ transform: `translateX(${checked ? "22px" : "4px"})` }}
        />
      </span>
      {(label || hint) && (
        <span className="flex flex-col">
          {label && <span className="md-label-l">{label}</span>}
          {hint && <span className="md-body-s text-[color:var(--md-on-surface-variant)]">{hint}</span>}
        </span>
      )}
    </label>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`rounded-md ${className}`}
      style={{
        background: "linear-gradient(90deg, color-mix(in oklab, var(--md-on-surface) 6%, transparent), color-mix(in oklab, var(--md-on-surface) 12%, transparent), color-mix(in oklab, var(--md-on-surface) 6%, transparent))",
        backgroundSize: "200% 100%",
        animation: "shimmer 1.6s linear infinite",
      }}
    />
  );
}
