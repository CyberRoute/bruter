import { useState } from "react";
import { api } from "../lib/api";
import type { ProbeResult } from "../lib/api";
import { Card, Spinner, ErrorNote, StatusBadge, Pill } from "./ui";
import { TerminalIcon, ShieldIcon } from "./icons";

// ProbePanel runs an active HTTP probe + subdomain-takeover check over the
// supplied hosts and renders the results as a triage table. It is opt-in (a
// button) because probing sends live HTTP requests to every host.
export function ProbePanel({ hosts }: { hosts: string[] }) {
  const [data, setData] = useState<ProbeResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.probe(hosts));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const live = (data ?? []).filter((r) => r.status > 0);
  const takeovers = (data ?? []).filter((r) => r.takeover?.vulnerable);

  return (
    <Card
      icon={<TerminalIcon />}
      title="HTTP Probe & Takeover"
      right={
        <button
          onClick={run}
          disabled={loading || hosts.length === 0}
          className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? "probing…" : data ? "re-probe" : `probe ${hosts.length} host${hosts.length === 1 ? "" : "s"}`}
        </button>
      }
    >
      {!data && !error && !loading && (
        <p className="text-sm text-muted">
          Send a live HTTP request to each host above to capture status, title, server, tech and
          security-header gaps — and flag dangling CNAMEs vulnerable to subdomain takeover.
        </p>
      )}
      {loading && <Spinner label={`Probing ${hosts.length} hosts…`} />}
      {error && <ErrorNote error={`Probe failed — ${error}`} />}

      {data && !loading && (
        <>
          {takeovers.length > 0 && (
            <div className="mb-4 rounded-lg border border-bad/50 bg-bad/10 p-3">
              <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-bad">
                <ShieldIcon />
                {takeovers.length} subdomain-takeover candidate{takeovers.length === 1 ? "" : "s"}
              </h3>
              <ul className="mt-2 space-y-1 text-sm text-slate-200">
                {takeovers.map((r) => (
                  <li key={r.host} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{r.host}</span>
                    <span className="text-muted">→</span>
                    <span className="font-mono text-xs">{r.takeover?.cname}</span>
                    <Pill>{r.takeover?.service}</Pill>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="mb-3 text-xs text-muted">
            Probed <span className="font-mono text-slate-200">{data.length}</span> ·{" "}
            <span className="font-mono text-slate-200">{live.length}</span> responded ·{" "}
            <span className="font-mono text-slate-200">{takeovers.length}</span> takeover
          </p>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-muted">
                  <th className="py-2 pr-3 font-medium">Host</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Title</th>
                  <th className="py-2 pr-3 font-medium">Server / Tech</th>
                  <th className="py-2 pr-3 font-medium">Flags</th>
                </tr>
              </thead>
              <tbody>
                {data.map((r) => (
                  <ProbeRow key={r.host} r={r} />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  );
}

function ProbeRow({ r }: { r: ProbeResult }) {
  const tech = r.tech ?? [];
  const takeoverMatch = r.takeover && !r.takeover.vulnerable;
  return (
    <tr
      className={`border-b border-line/50 align-top ${
        r.takeover?.vulnerable ? "bg-bad/5" : ""
      }`}
    >
      <td className="py-2 pr-3">
        <a
          href={r.url || `https://${r.host}`}
          target="_blank"
          rel="noreferrer"
          className="font-mono text-slate-200 hover:text-accent hover:underline"
          title={r.ip ? `${r.host} (${r.ip})` : r.host}
        >
          {r.host}
        </a>
        {r.redirect_to && (
          <div className="truncate text-xs text-muted" title={r.redirect_to}>
            → {r.redirect_to}
          </div>
        )}
      </td>
      <td className="py-2 pr-3">
        {r.status > 0 ? (
          <StatusBadge status={r.status} />
        ) : (
          <span className="text-xs text-muted" title={r.error}>
            {r.error || "no response"}
          </span>
        )}
      </td>
      <td className="max-w-[16rem] py-2 pr-3">
        <span className="line-clamp-2 text-slate-300" title={r.title}>
          {r.title || <span className="text-muted">—</span>}
        </span>
      </td>
      <td className="py-2 pr-3">
        {r.server && <div className="text-slate-300">{r.server}</div>}
        {tech.length > 0 && (
          <div className="mt-0.5 flex flex-wrap gap-1">
            {tech.map((t) => (
              <span key={t} className="rounded border border-line bg-ink-700 px-1 py-0.5 text-[10px] text-slate-300">
                {t}
              </span>
            ))}
          </div>
        )}
      </td>
      <td className="py-2 pr-3">
        <div className="flex flex-wrap gap-1">
          {r.takeover?.vulnerable && (
            <span className="rounded border border-bad/50 bg-bad/10 px-1 py-0.5 text-[10px] font-semibold uppercase text-bad">
              takeover: {r.takeover.service}
            </span>
          )}
          {takeoverMatch && (
            <span
              className="rounded border border-warn/40 bg-warn/10 px-1 py-0.5 text-[10px] text-warn"
              title={`Points at ${r.takeover?.service} (${r.takeover?.cname}) — verify manually`}
            >
              ⚑ {r.takeover?.service}?
            </span>
          )}
          {r.cors && (
            <span
              className="rounded border border-warn/40 bg-warn/10 px-1 py-0.5 text-[10px] text-warn"
              title={`CORS: ${r.cors}`}
            >
              CORS
            </span>
          )}
          {r.missing_headers && r.missing_headers.length > 0 && (
            <span
              className="rounded border border-line bg-ink-700 px-1 py-0.5 text-[10px] text-muted"
              title={`Missing: ${r.missing_headers.join(", ")}`}
            >
              -{r.missing_headers.length} sec-hdr
            </span>
          )}
        </div>
      </td>
    </tr>
  );
}
