import { useMemo, useState } from "react";
import { api } from "../lib/api";
import type { BruteResult } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Card, Spinner, ErrorNote, Pill } from "../components/ui";
import { SitemapIcon, DownloadIcon } from "../components/icons";
import { ProbePanel } from "../components/ProbePanel";

function str(v: unknown): string {
  return v === null || v === undefined ? "" : String(v);
}

// Normalise a certificate name into a bare hostname: trim, lowercase and drop a
// leading wildcard label so "*.api.foo.com" and "api.foo.com" collapse to one.
function normalizeHost(raw: string): string {
  return raw.trim().toLowerCase().replace(/^\*\./, "");
}

export function Subdomains() {
  // Certificate-transparency records carry the hostnames; the host endpoint
  // gives us the scanned apex so we can scope and name the download.
  const { data, loading, error, reload } = useAsync(() =>
    Promise.all([api.ssl(), api.host().catch(() => null)]),
  );
  const [q, setQ] = useState("");
  const [scopedOnly, setScopedOnly] = useState(true);

  // Active brute-force is opt-in (it is a live DNS probe), so it is triggered
  // by a button rather than run on mount.
  const [brute, setBrute] = useState<BruteResult | null>(null);
  const [bruteLoading, setBruteLoading] = useState(false);
  const [bruteError, setBruteError] = useState<string | null>(null);

  const runBrute = async () => {
    setBruteLoading(true);
    setBruteError(null);
    try {
      setBrute(await api.bruteSubdomains());
    } catch (e) {
      setBruteError(e instanceof Error ? e.message : String(e));
    } finally {
      setBruteLoading(false);
    }
  };

  const [records, host] = data ?? [[], null];
  const apex = host?.domain ?? "";

  // Hosts found by the active brute-force, with their resolved IPs, so the list
  // can tag them and show where they point.
  const activeIPs = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const r of brute?.results ?? []) m.set(normalizeHost(r.host), r.ips ?? []);
    return m;
  }, [brute]);

  // Flatten common_name + name_value from every passive record, then union with
  // the brute-forced hosts, into one sorted, de-duplicated hostname list.
  const allHosts = useMemo(() => {
    const set = new Set<string>();
    for (const r of records) {
      for (const field of [str(r.common_name), str(r.name_value)]) {
        for (const line of field.split(/[\n,]/)) {
          const h = normalizeHost(line);
          if (h && h.includes(".")) set.add(h);
        }
      }
    }
    for (const h of activeIPs.keys()) set.add(h);
    return [...set].sort();
  }, [records, activeIPs]);

  const inScope = (h: string) => !!apex && (h === apex || h.endsWith("." + apex));

  const visible = useMemo(() => {
    let rows = scopedOnly && apex ? allHosts.filter(inScope) : allHosts;
    if (q.trim()) {
      const needle = q.toLowerCase();
      rows = rows.filter((h) => h.includes(needle));
    }
    return rows;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allHosts, q, scopedOnly, apex]);

  const download = () => {
    const blob = new Blob([visible.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${apex || "subdomains"}-subdomains.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  if (loading) return <Spinner label="Collecting subdomains from passive sources…" />;
  if (error)
    return (
      <div className="space-y-3">
        <ErrorNote error={`Subdomain sources unavailable — ${error}`} />
        <button
          onClick={reload}
          className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-sm font-medium text-accent hover:bg-accent/20"
        >
          Retry
        </button>
      </div>
    );

  const bruteButton = (
    <button
      onClick={runBrute}
      disabled={bruteLoading}
      className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {bruteLoading ? "brute-forcing…" : brute ? "re-run brute-force" : "brute-force"}
    </button>
  );

  const noPassive = allHosts.length === 0 && !brute;
  if (noPassive)
    return (
      <div className="space-y-3">
        <ErrorNote error="No subdomains were returned by any passive source for this domain." />
        <p className="text-sm text-muted">
          You can still run an active DNS brute-force of common subdomain labels:
        </p>
        <div className="flex items-center gap-3">
          {bruteButton}
          <button
            onClick={reload}
            className="rounded-lg border border-line bg-ink-700 px-3 py-1.5 text-sm text-slate-200 hover:border-accent hover:text-accent"
          >
            Retry passive
          </button>
        </div>
        {bruteError && <ErrorNote error={`Brute-force failed — ${bruteError}`} />}
      </div>
    );

  return (
    <div className="flex flex-col gap-4">
    <Card
      icon={<SitemapIcon />}
      title="Subdomains"
      right={
        <div className="flex items-center gap-2">
          {bruteButton}
          <button
            onClick={download}
            disabled={visible.length === 0}
            className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <DownloadIcon className="h-3.5 w-3.5" />
            Download list ({visible.length})
          </button>
        </div>
      }
    >
      {bruteError && (
        <div className="mb-3">
          <ErrorNote error={`Brute-force failed — ${bruteError}`} />
        </div>
      )}
      {brute?.wildcard && (
        <div className="mb-3 rounded-lg border border-warn/40 bg-warn/10 px-3 py-2 text-sm text-warn">
          This zone uses <span className="font-mono">wildcard DNS</span> — arbitrary labels resolve.
          Brute-force results are filtered to names whose addresses differ from the wildcard, but
          treat them with extra care.
        </div>
      )}
      {brute && (
        <p className="mb-3 text-xs text-muted">
          Active brute-force tested{" "}
          <span className="font-mono text-slate-200">{brute.tested}</span> labels ·{" "}
          <span className="font-mono text-slate-200">{brute.results.length}</span> resolved.
        </p>
      )}

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted">
          <span className="font-mono text-slate-100">{visible.length}</span> of {allHosts.length}{" "}
          unique hostname{allHosts.length === 1 ? "" : "s"}
          {apex && (
            <>
              {" "}
              · apex <span className="font-mono text-slate-200">{apex}</span>
            </>
          )}
        </p>
        <div className="flex items-center gap-3">
          {apex && (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={scopedOnly}
                onChange={(e) => setScopedOnly(e.target.checked)}
                className="accent-accent"
              />
              only *.{apex}
            </label>
          )}
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter…"
            className="w-48 rounded-lg border border-line bg-ink-800 px-3 py-1.5 font-mono text-sm text-slate-100 outline-none placeholder:text-muted focus:border-accent"
          />
        </div>
      </div>

      {visible.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted">No hostnames match the current filter.</p>
      ) : (
        <ul className="grid gap-x-6 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
          {visible.map((h) => {
            const ips = activeIPs.get(h);
            return (
              <li key={h} className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <a
                    href={`https://${h}`}
                    target="_blank"
                    rel="noreferrer"
                    className="block truncate font-mono text-sm text-slate-200 hover:text-accent hover:underline"
                    title={ips && ips.length ? `${h} → ${ips.join(", ")}` : h}
                  >
                    {h}
                  </a>
                  {ips && (
                    <span className="shrink-0 rounded border border-ok/40 bg-ok/10 px-1 py-0.5 text-[10px] font-semibold uppercase text-ok">
                      live
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {brute && brute.results.length > 0 && (
        <div className="mt-5 border-t border-line pt-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">
            Brute-forced hosts (resolved)
          </h3>
          <ul className="space-y-1">
            {brute.results.map((r) => (
              <li key={r.host} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-slate-200">{r.host}</span>
                <span className="text-muted">→</span>
                {r.ips.map((ip) => (
                  <Pill key={ip}>{ip}</Pill>
                ))}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
    <ProbePanel hosts={visible} />
    </div>
  );
}
