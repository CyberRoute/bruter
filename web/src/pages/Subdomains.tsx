import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Card, Spinner, ErrorNote } from "../components/ui";
import { SitemapIcon, DownloadIcon } from "../components/icons";

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

  const [records, host] = data ?? [[], null];
  const apex = host?.domain ?? "";

  // Flatten common_name + name_value from every record into one sorted,
  // de-duplicated hostname list.
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
    return [...set].sort();
  }, [records]);

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
  if (allHosts.length === 0)
    return (
      <div className="space-y-3">
        <ErrorNote error="No subdomains were returned by any passive source for this domain." />
        <button
          onClick={reload}
          className="rounded-lg border border-line bg-ink-700 px-3 py-1.5 text-sm text-slate-200 hover:border-accent hover:text-accent"
        >
          Retry
        </button>
      </div>
    );

  return (
    <Card
      icon={<SitemapIcon />}
      title="Subdomains"
      right={
        <button
          onClick={download}
          disabled={visible.length === 0}
          className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <DownloadIcon className="h-3.5 w-3.5" />
          Download list ({visible.length})
        </button>
      }
    >
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
          {visible.map((h) => (
            <li key={h} className="min-w-0">
              <a
                href={`https://${h}`}
                target="_blank"
                rel="noreferrer"
                className="block truncate font-mono text-sm text-slate-200 hover:text-accent hover:underline"
                title={h}
              >
                {h}
              </a>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
