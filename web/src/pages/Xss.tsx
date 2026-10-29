import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { CrawlTarget, ScanJob, ScanOptions, XssPoc } from "../lib/api";
import { Card, Spinner, ErrorNote, Pill } from "../components/ui";
import { BugIcon, ShieldIcon, SitemapIcon, SearchIcon } from "../components/icons";

// Xss is the dalfox control panel: crawl a domain + analyse its JS to discover
// the scan surface, curate the target list, configure dalfox, then run an
// automated scan with live progress and streaming findings. Everything here is
// an ACTIVE check — crawling and scanning send live traffic to the target.
export function Xss() {
  // Shared discovery/auth state.
  const [seed, setSeed] = useState("");
  const [depth, setDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(100);
  const [cookie, setCookie] = useState("");

  const [crawling, setCrawling] = useState(false);
  const [crawlErr, setCrawlErr] = useState<string | null>(null);
  const [crawlPages, setCrawlPages] = useState<number | null>(null);

  // Target list (discovered + manually added) and selection.
  const [targets, setTargets] = useState<CrawlTarget[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [manual, setManual] = useState("");

  // Scan options + job. Defaults favour crawl-fed scanning: the crawler already
  // found the parameters, so skip dalfox's (slow, remote-timeout-prone) mining
  // and cap each target with a graceful scan-timeout.
  const [showOpts, setShowOpts] = useState(false);
  const [opts, setOpts] = useState<ScanOptions>({
    skip_mining: true,
    scan_timeout: 90,
    skip_ast: true, // silence dalfox's unverified "[A]" DOM-XSS static noise
    only_poc: "v", // report only verified findings by default
  });
  const [headersText, setHeadersText] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [scanErr, setScanErr] = useState<string | null>(null);

  // Pre-fill the seed from the domain Bruter was started with (-domain CLI).
  useEffect(() => {
    let cancelled = false;
    api
      .target()
      .then((t) => {
        if (!cancelled && t.url) setSeed((s) => (s.trim() === "" ? t.url : s));
      })
      .catch(() => {
        /* no domain configured; leave the field empty */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const mergeTargets = (incoming: CrawlTarget[]) => {
    setTargets((prev) => {
      const byUrl = new Map(prev.map((t) => [t.url + "|" + t.params.join(","), t]));
      for (const t of incoming) byUrl.set(t.url + "|" + t.params.join(","), t);
      return [...byUrl.values()];
    });
  };

  const runCrawl = async () => {
    if (!seed.trim()) return;
    setCrawling(true);
    setCrawlErr(null);
    try {
      const res = await api.crawl({ url: seed.trim(), depth, max_pages: maxPages, cookie });
      setCrawlPages(res.pages);
      mergeTargets(res.targets ?? []);
      // Pre-select everything that carries parameters (the useful surface).
      setSelected((prev) => {
        const next = new Set(prev);
        for (const t of res.targets ?? []) if (t.params.length > 0) next.add(t.url);
        return next;
      });
    } catch (e) {
      setCrawlErr(e instanceof Error ? e.message : String(e));
    } finally {
      setCrawling(false);
    }
  };

  const addManual = () => {
    const u = manual.trim();
    if (!u) return;
    mergeTargets([{ url: u, params: [], source: "manual" }]);
    setSelected((prev) => new Set(prev).add(u));
    setManual("");
  };

  const toggle = (url: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(url) ? next.delete(url) : next.add(url);
      return next;
    });

  const selectedUrls = [...new Set([...selected])].filter((u) =>
    targets.some((t) => t.url === u),
  );

  const startScan = async () => {
    if (selectedUrls.length === 0) return;
    setScanErr(null);
    setJob(null);
    const headers = headersText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    try {
      const { job_id } = await api.startScan(selectedUrls, { ...opts, cookie, headers });
      setJobId(job_id);
    } catch (e) {
      setScanErr(e instanceof Error ? e.message : String(e));
    }
  };

  const stopScan = async () => {
    if (jobId) {
      try {
        await api.stopScan(jobId);
      } catch {
        /* ignore — the poll will reflect the final state */
      }
    }
  };

  // Poll the job while it is running.
  const pollRef = useRef<number | null>(null);
  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const j = await api.scanStatus(jobId);
        if (cancelled) return;
        setJob(j);
        if (["done", "stopped", "error"].includes(j.state) && pollRef.current) {
          window.clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch (e) {
        if (!cancelled) setScanErr(e instanceof Error ? e.message : String(e));
      }
    };
    void tick();
    pollRef.current = window.setInterval(tick, 1500);
    return () => {
      cancelled = true;
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
    };
  }, [jobId]);

  const scanNotInstalled = !!scanErr && /not installed|not on path/i.test(scanErr);
  const running = job?.state === "queued" || job?.state === "running";
  const pct = job && job.total > 0 ? Math.round((job.done / job.total) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* 1. Discover */}
      <Card icon={<SitemapIcon />} title="Discover scan surface">
        <p className="mb-4 text-sm text-muted">
          Crawl a target on its own host and statically analyse its JavaScript to find URLs with
          parameters, forms and endpoints. Crawling and scanning send live traffic — only run
          against systems you are authorised to test.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void runCrawl();
          }}
          className="space-y-3"
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <input
              type="url"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="https://example.com/"
              className="min-w-0 flex-1 rounded-lg border border-line bg-ink-900/60 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-muted focus:border-accent/60 focus:outline-none focus:ring-1 focus:ring-accent/40"
            />
            <button
              type="submit"
              disabled={crawling || seed.trim() === ""}
              className="shrink-0 rounded-lg border border-accent/40 bg-accent/10 px-4 py-2 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {crawling ? "crawling…" : "crawl"}
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-xs text-muted">
            <label className="flex items-center gap-2">
              depth
              <input
                type="number"
                min={1}
                max={5}
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                className="w-16 rounded border border-line bg-ink-900/60 px-2 py-1 text-slate-200"
              />
            </label>
            <label className="flex items-center gap-2">
              max pages
              <input
                type="number"
                min={1}
                max={1000}
                value={maxPages}
                onChange={(e) => setMaxPages(Number(e.target.value))}
                className="w-20 rounded border border-line bg-ink-900/60 px-2 py-1 text-slate-200"
              />
            </label>
          </div>
          <input
            type="text"
            value={cookie}
            onChange={(e) => setCookie(e.target.value)}
            placeholder="Cookie (optional) — e.g. PHPSESSID=…; security=low"
            className="w-full rounded-lg border border-line bg-ink-900/60 px-3 py-2 font-mono text-xs text-slate-200 placeholder:text-muted focus:border-accent/60 focus:outline-none"
          />
        </form>
        {crawling && <div className="mt-3"><Spinner label="Crawling & analysing JS…" /></div>}
        {crawlErr && <div className="mt-3"><ErrorNote error={`Crawl failed — ${crawlErr}`} /></div>}
        {crawlPages !== null && !crawling && (
          <p className="mt-3 text-xs text-muted">
            Crawled <span className="font-mono text-slate-200">{crawlPages}</span> page(s) ·{" "}
            <span className="font-mono text-slate-200">{targets.length}</span> target(s) discovered
          </p>
        )}
      </Card>

      {/* 2. Targets */}
      <Card
        icon={<SearchIcon />}
        title="Targets"
        right={
          <span className="text-xs text-muted">
            <span className="font-mono text-slate-200">{selectedUrls.length}</span> /{" "}
            <span className="font-mono text-slate-200">{targets.length}</span> selected
          </span>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <button
            onClick={() => setSelected(new Set(targets.map((t) => t.url)))}
            disabled={targets.length === 0}
            className="rounded border border-line px-2 py-1 text-xs text-slate-300 hover:bg-ink-700 disabled:opacity-40"
          >
            select all
          </button>
          <button
            onClick={() => setSelected(new Set(targets.filter((t) => t.params.length > 0).map((t) => t.url)))}
            disabled={targets.length === 0}
            className="rounded border border-line px-2 py-1 text-xs text-slate-300 hover:bg-ink-700 disabled:opacity-40"
          >
            only with params
          </button>
          <button
            onClick={() => setSelected(new Set())}
            disabled={selected.size === 0}
            className="rounded border border-line px-2 py-1 text-xs text-slate-300 hover:bg-ink-700 disabled:opacity-40"
          >
            clear
          </button>
          <span className="flex-1" />
          <input
            value={manual}
            onChange={(e) => setManual(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addManual())}
            placeholder="add URL manually"
            className="w-56 rounded border border-line bg-ink-900/60 px-2 py-1 font-mono text-xs text-slate-200 placeholder:text-muted"
          />
          <button
            onClick={addManual}
            className="rounded border border-line px-2 py-1 text-xs text-slate-300 hover:bg-ink-700"
          >
            add
          </button>
        </div>

        {targets.length === 0 ? (
          <p className="text-sm text-muted">No targets yet — crawl a domain above or add a URL.</p>
        ) : (
          <div className="max-h-80 overflow-auto rounded-lg border border-line">
            <table className="w-full border-collapse text-sm">
              <tbody>
                {targets.map((t) => (
                  <tr key={t.url + t.params.join(",")} className="border-b border-line/50">
                    <td className="w-8 py-1.5 pl-3">
                      <input
                        type="checkbox"
                        checked={selected.has(t.url)}
                        onChange={() => toggle(t.url)}
                        className="accent-accent"
                      />
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-slate-200">
                      <span className="break-all">{t.url}</span>
                    </td>
                    <td className="py-1.5 pr-3">
                      {t.params.length > 0 && (
                        <span className="text-[10px] text-muted">{t.params.join(", ")}</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3">
                      <span className="rounded border border-line bg-ink-700 px-1 py-0.5 text-[10px] text-muted">
                        {t.source}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* 3. Options */}
      <Card
        icon={<ShieldIcon />}
        title="Scan options (dalfox)"
        right={
          <button
            onClick={() => setShowOpts((s) => !s)}
            className="rounded border border-line px-2 py-1 text-xs text-slate-300 hover:bg-ink-700"
          >
            {showOpts ? "hide" : "show"}
          </button>
        }
      >
        {showOpts ? (
          <ScanOptionsForm
            opts={opts}
            setOpts={setOpts}
            headersText={headersText}
            setHeadersText={setHeadersText}
          />
        ) : (
          <p className="text-sm text-muted">
            Defaults tuned for low noise: parameter mining <span className="text-slate-300">skipped</span>{" "}
            (the crawler already found the params), AST DOM-XSS analysis{" "}
            <span className="text-slate-300">skipped</span> (it emits unverified{" "}
            <span className="font-mono">[A]</span> guesses), reporting only{" "}
            <span className="text-slate-300">verified</span> findings, and a{" "}
            <span className="text-slate-300">90s</span> per-target scan-timeout. The shared cookie
            applies. Click “show” to change the report filter, mining, headers, blind-XSS callback,
            rate limit, deep scan, WAF evasion and more.
          </p>
        )}
      </Card>

      {/* 4. Run + results */}
      <Card
        icon={<BugIcon />}
        title="Automated scan"
        right={
          running ? (
            <button
              onClick={() => void stopScan()}
              className="rounded-lg border border-bad/50 bg-bad/10 px-3 py-1.5 text-xs font-medium text-bad hover:bg-bad/20"
            >
              stop
            </button>
          ) : (
            <button
              onClick={() => void startScan()}
              disabled={selectedUrls.length === 0}
              className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
            >
              scan {selectedUrls.length} target{selectedUrls.length === 1 ? "" : "s"}
            </button>
          )
        }
      >
        {scanNotInstalled ? (
          <div>
            <p className="text-sm text-slate-300">
              The scan shells out to the <span className="font-mono text-accent">dalfox</span> v3
              binary, which is not installed on the server running Bruter. Install it and restart:
            </p>
            <pre className="mt-3 overflow-x-auto rounded-lg border border-line bg-ink-900/60 p-3 text-xs text-slate-300">
              brew install dalfox
              {"\n"}# or grab a v3 release binary: https://github.com/hahwul/dalfox/releases
            </pre>
          </div>
        ) : scanErr ? (
          <ErrorNote error={`Scan failed — ${scanErr}`} />
        ) : !job ? (
          <p className="text-sm text-muted">
            Select targets above, then start the scan. Progress and findings stream in live.
          </p>
        ) : (
          <ScanProgress job={job} pct={pct} />
        )}
      </Card>
    </div>
  );
}

function ScanProgress({ job, pct }: { job: ScanJob; pct: number }) {
  return (
    <div className="space-y-4">
      <div>
        <div className="mb-1 flex items-center justify-between text-xs text-muted">
          <span>
            {job.state} · <span className="font-mono text-slate-200">{job.done}</span> /{" "}
            <span className="font-mono text-slate-200">{job.total}</span> targets ·{" "}
            <span className="font-mono text-slate-200">{job.findings.length}</span> findings
          </span>
          <span className="font-mono text-slate-200">{pct}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-ink-700">
          <div
            className="h-full rounded-full bg-accent transition-all"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {(job.state === "running" || job.state === "queued") && (
        <div className="flex items-center gap-2 text-xs text-muted">
          <Spinner label="" />
          {(() => {
            const active = job.targets.filter((t) => t.state === "running").map((t) => t.url);
            return active.length > 0 ? (
              <span className="truncate font-mono" title={active.join(", ")}>
                scanning {active[0]}
                {active.length > 1 ? ` (+${active.length - 1} more)` : ""}
              </span>
            ) : (
              <span>working…</span>
            );
          })()}
        </div>
      )}

      {job.findings.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-muted">
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">Type</th>
                <th className="py-2 pr-3 font-medium">Param</th>
                <th className="py-2 pr-3 font-medium">Payload</th>
                <th className="py-2 pr-3 font-medium">PoC</th>
              </tr>
            </thead>
            <tbody>
              {job.findings.map((p, i) => (
                <XssRow key={`${p.param}-${p.message_id}-${i}`} p={p} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Per-target errors (e.g. auth/redirect) help explain empty results. */}
      {job.targets.some((t) => t.state === "error") && (
        <details className="text-xs text-muted">
          <summary className="cursor-pointer">
            {job.targets.filter((t) => t.state === "error").length} target(s) errored
          </summary>
          <ul className="mt-2 space-y-1">
            {job.targets
              .filter((t) => t.state === "error")
              .map((t) => (
                <li key={t.url} className="font-mono">
                  {t.url} — {t.error}
                </li>
              ))}
          </ul>
        </details>
      )}
    </div>
  );
}

type OptsProps = {
  opts: ScanOptions;
  setOpts: React.Dispatch<React.SetStateAction<ScanOptions>>;
  headersText: string;
  setHeadersText: (v: string) => void;
};

function ScanOptionsForm({ opts, setOpts, headersText, setHeadersText }: OptsProps) {
  const set = (patch: Partial<ScanOptions>) => setOpts((o) => ({ ...o, ...patch }));
  const toggle = (k: keyof ScanOptions) => (e: React.ChangeEvent<HTMLInputElement>) =>
    set({ [k]: e.target.checked } as Partial<ScanOptions>);
  const num = (k: keyof ScanOptions) => (e: React.ChangeEvent<HTMLInputElement>) =>
    set({ [k]: Number(e.target.value) } as Partial<ScanOptions>);
  const str = (k: keyof ScanOptions) => (e: React.ChangeEvent<HTMLInputElement>) =>
    set({ [k]: e.target.value } as Partial<ScanOptions>);

  const chk = "accent-accent";
  const field =
    "w-full rounded border border-line bg-ink-900/60 px-2 py-1 font-mono text-xs text-slate-200 placeholder:text-muted";

  return (
    <div className="space-y-4 text-xs text-slate-300">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.skip_mining} onChange={toggle("skip_mining")} /> skip all mining</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.skip_mining_dict} onChange={toggle("skip_mining_dict")} /> skip dict mining</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.skip_mining_dom} onChange={toggle("skip_mining_dom")} /> skip DOM mining</label>
        <label className="flex items-center gap-2" title="Silence dalfox's unverified [A] DOM-XSS static (source→sink) findings."><input type="checkbox" className={chk} checked={!!opts.skip_ast} onChange={toggle("skip_ast")} /> skip AST DOM analysis</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.follow_redirects} onChange={toggle("follow_redirects")} /> follow redirects</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.deep_scan} onChange={toggle("deep_scan")} /> deep scan</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.waf_evasion} onChange={toggle("waf_evasion")} /> WAF evasion</label>
        <label className="flex items-center gap-2"><input type="checkbox" className={chk} checked={!!opts.stored_xss} onChange={toggle("stored_xss")} /> stored XSS</label>
      </div>

      <div className="grid gap-2 sm:grid-cols-2">
        <label className="space-y-1" title="Which dalfox finding types to report. Verified-only hides reflected/AST/informational noise.">
          <span className="text-muted">Report findings</span>
          <select
            className={field}
            value={opts.only_poc ?? ""}
            onChange={(e) => set({ only_poc: e.target.value })}
          >
            <option value="v">verified only (V)</option>
            <option value="v,r">verified + reflected (V, R)</option>
            <option value="v,r,a">verified + reflected + AST (V, R, A)</option>
            <option value="">all types (V, R, A, I)</option>
          </select>
        </label>
        <label className="space-y-1">
          <span className="text-muted">User-Agent</span>
          <input className={field} value={opts.user_agent ?? ""} onChange={str("user_agent")} placeholder="Mozilla/5.0 …" />
        </label>
        <label className="space-y-1">
          <span className="text-muted">Method</span>
          <input className={field} value={opts.method ?? ""} onChange={str("method")} placeholder="GET / POST …" />
        </label>
        <label className="space-y-1">
          <span className="text-muted">Blind-XSS callback (-b)</span>
          <input className={field} value={opts.blind_url ?? ""} onChange={str("blind_url")} placeholder="https://your-oob/" />
        </label>
        <label className="space-y-1">
          <span className="text-muted">Stored-XSS reflection URL</span>
          <input className={field} value={opts.sxss_url ?? ""} onChange={str("sxss_url")} placeholder="https://host/view" />
        </label>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <label className="space-y-1"><span className="text-muted">workers</span><input type="number" min={1} className={field} value={opts.workers ?? ""} onChange={num("workers")} /></label>
        <label className="space-y-1"><span className="text-muted">timeout (s)</span><input type="number" min={1} className={field} value={opts.timeout ?? ""} onChange={num("timeout")} /></label>
        <label className="space-y-1"><span className="text-muted">delay (ms)</span><input type="number" min={0} className={field} value={opts.delay ?? ""} onChange={num("delay")} /></label>
        <label className="space-y-1"><span className="text-muted">rate-limit (rps)</span><input type="number" min={0} className={field} value={opts.rate_limit ?? ""} onChange={num("rate_limit")} /></label>
        <label className="space-y-1" title="Graceful per-target cap for dalfox's scan stage (seconds). Prevents remote targets hanging."><span className="text-muted">scan-timeout (s)</span><input type="number" min={0} className={field} value={opts.scan_timeout ?? ""} onChange={num("scan_timeout")} /></label>
      </div>

      <label className="block space-y-1">
        <span className="text-muted">Extra headers (one “Name: value” per line)</span>
        <textarea
          rows={2}
          className={field}
          value={headersText}
          onChange={(e) => setHeadersText(e.target.value)}
          placeholder={"Authorization: Bearer …\nX-Requested-With: XMLHttpRequest"}
        />
      </label>
    </div>
  );
}

function severityClasses(sev: string): string {
  switch (sev.toLowerCase()) {
    case "high":
    case "critical":
      return "border-bad/50 bg-bad/10 text-bad";
    case "medium":
      return "border-warn/40 bg-warn/10 text-warn";
    default:
      return "border-line bg-ink-700 text-slate-300";
  }
}

function XssRow({ p }: { p: XssPoc }) {
  const verified = p.type.toUpperCase() === "V";
  return (
    <tr className="border-b border-line/50 align-top">
      <td className="py-2 pr-3">
        <span
          className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${severityClasses(
            p.severity,
          )}`}
        >
          {p.severity || "info"}
        </span>
      </td>
      <td className="py-2 pr-3">
        <div className="flex flex-col gap-1">
          {verified ? <Pill>verified</Pill> : p.type && <Pill>{p.type}</Pill>}
          {p.inject_type && <span className="text-xs text-muted">{p.inject_type}</span>}
          {p.confidence && (
            <span className="text-[10px] uppercase tracking-wide text-muted" title={p.confidence_reason}>
              {p.confidence} confidence
            </span>
          )}
        </div>
      </td>
      <td className="py-2 pr-3 font-mono text-slate-200">{p.param || "—"}</td>
      <td className="max-w-[20rem] py-2 pr-3">
        <code className="block overflow-x-auto whitespace-pre text-xs text-slate-300" title={p.payload}>
          {p.payload || "—"}
        </code>
      </td>
      <td className="py-2 pr-3">
        {p.data ? (
          <a
            href={p.data}
            target="_blank"
            rel="noreferrer"
            className="font-mono text-xs text-accent hover:underline"
            title={p.data}
          >
            open ↗
          </a>
        ) : (
          <span className="text-muted">—</span>
        )}
      </td>
    </tr>
  );
}
