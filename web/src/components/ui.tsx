import type { ReactNode } from "react";

// Small shared presentational primitives used across every page so the cards,
// labels and status pills stay visually consistent.

export function Card({
  title,
  icon,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  icon?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-line bg-ink-800/70 shadow-card backdrop-blur-sm ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-200">
            {icon && <span className="text-accent">{icon}</span>}
            {title}
          </h2>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Field({ label, value }: { label: string; value: ReactNode }) {
  const empty = value === "" || value === null || value === undefined;
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line/60 py-2 last:border-0">
      <span className="shrink-0 text-xs uppercase tracking-wide text-muted">{label}</span>
      <span className="text-right font-mono text-sm text-slate-100 break-all">
        {empty ? <span className="text-muted">—</span> : value}
      </span>
    </div>
  );
}

export function StatusBadge({ status }: { status: number }) {
  const tone =
    status >= 200 && status < 300
      ? "border-ok/40 bg-ok/10 text-ok"
      : status >= 300 && status < 400
        ? "border-accent/40 bg-accent/10 text-accent"
        : status >= 400 && status < 500
          ? "border-warn/40 bg-warn/10 text-warn"
          : "border-bad/40 bg-bad/10 text-bad";
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold ${tone}`}
    >
      {status}
    </span>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-8 text-muted">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-line border-t-accent" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <div className="rounded-lg border border-bad/40 bg-bad/10 px-3 py-2 text-sm text-bad">
      {error}
    </div>
  );
}

export function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded border border-line bg-ink-700 px-2 py-0.5 font-mono text-xs text-slate-200">
      {children}
    </span>
  );
}
