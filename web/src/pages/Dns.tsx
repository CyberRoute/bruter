import { useState } from "react";
import { api } from "../lib/api";
import type { ZoneTransfer, EmailAuth, ReverseIp, RobtexIpInfo } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Card, Field, Pill, Spinner, ErrorNote } from "../components/ui";
import { NetworkIcon, ShieldIcon, MailIcon, SitemapIcon } from "../components/icons";

// Renders a list of record values as monospace pills, or an em-dash when the
// record type is absent. DNS values (TXT especially) are attacker-influenceable
// strings; React escapes them as text so there is no injection surface.
function RecordRow({ label, values }: { label: string; values: string[] | null }) {
  const list = values ?? [];
  return (
    <Field
      label={label}
      value={
        list.length ? (
          <span className="flex flex-wrap justify-end gap-1.5">
            {list.map((v, i) => (
              <Pill key={`${v}-${i}`}>{v}</Pill>
            ))}
          </span>
        ) : (
          ""
        )
      }
    />
  );
}

export function Dns() {
  const { data, loading, error } = useAsync(() => api.dns());

  if (loading) return <Spinner label="Resolving DNS records…" />;
  if (error) return <ErrorNote error={error} />;
  if (!data) return <ErrorNote error="No DNS records available for this domain." />;

  const mxEntries = Object.entries(data.mx ?? {}).sort((a, b) => a[1] - b[1]);
  const axfr = data.axfr ?? [];
  const openTransfers = axfr.filter((z) => z.vulnerable);

  return (
    <div className="flex flex-col gap-4">
      {axfr.length > 0 && <ZoneTransferCard axfr={axfr} open={openTransfers} />}
      {data.email && <EmailAuthCard email={data.email} />}
      <Card icon={<NetworkIcon />} title="DNS Records">
      <RecordRow label="A" values={data.a} />
      <RecordRow label="AAAA" values={data.aaaa} />
      <RecordRow label="NS" values={data.ns} />
      <RecordRow label="CNAME" values={data.cname ? [data.cname] : []} />
      <RecordRow label="TXT" values={data.txt} />
      <Field
        label="MX"
        value={
          mxEntries.length ? (
            <span className="flex flex-wrap justify-end gap-1.5">
              {mxEntries.map(([host, pref]) => (
                <Pill key={host}>
                  {pref} {host}
                </Pill>
              ))}
            </span>
          ) : (
            ""
          )
        }
      />
      <RecordRow label="PTR" values={data.ptr} />
      {data.soa && (
        <>
          <Field label="SOA Primary NS" value={data.soa.ns} />
          <Field label="SOA Contact" value={data.soa.mbox} />
          <Field label="SOA Serial" value={String(data.soa.serial)} />
        </>
      )}
      </Card>
      <ReverseIpCard apex={apexFromRecords(data)} />
      <RobtexCard />
    </div>
  );
}

// apexFromRecords derives the scanned host label for the reverse-IP card's
// neighbour comparison: the CNAME target if present, else empty (the card only
// uses it to visually mark the domain's own name among neighbours).
function apexFromRecords(data: { cname: string }): string {
  return data.cname || "";
}

// ReverseIpCard is an opt-in lookup of other host names sharing the domain's IP
// ("neighbours"). It is button-triggered because the external source has a
// small shared daily quota, and because on shared CDN IPs the result is noisy.
function ReverseIpCard({ apex }: { apex: string }) {
  const [data, setData] = useState<ReverseIp | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.reverseIp());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      icon={<SitemapIcon />}
      title="Reverse IP (neighbours)"
      right={
        <button
          onClick={run}
          disabled={loading}
          className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? "looking up…" : data ? "re-run" : "look up"}
        </button>
      }
    >
      {!data && !error && !loading && (
        <p className="text-sm text-muted">
          Find other host names pointing at this domain's IP. Most useful on dedicated hosting;
          shared CDN IPs (Cloudflare, Fastly, …) return unrelated or empty results.
        </p>
      )}
      {loading && <Spinner label="Querying reverse-IP source…" />}
      {error && <ErrorNote error={`Reverse-IP source unavailable — ${error}`} />}
      {data && !loading && (
        <>
          <p className="mb-3 text-sm text-muted">
            <span className="font-mono text-slate-100">{data.hosts.length}</span> host
            {data.hosts.length === 1 ? "" : "s"} on <span className="font-mono">{data.ip}</span>
          </p>
          {data.hosts.length === 0 ? (
            <p className="py-2 text-sm text-muted">No neighbouring hosts reported for this IP.</p>
          ) : (
            <ul className="grid gap-x-6 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
              {data.hosts.map((h) => (
                <li key={h} className="min-w-0">
                  <a
                    href={`https://${h}`}
                    target="_blank"
                    rel="noreferrer"
                    className={`block truncate font-mono text-sm hover:underline ${
                      apex && h === apex ? "text-accent" : "text-slate-200 hover:text-accent"
                    }`}
                    title={h}
                  >
                    {h}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  );
}

// fmtEpoch renders a Unix-seconds timestamp as a short ISO date, or "—" when
// the source gave no time.
function fmtEpoch(t: number): string {
  if (!t) return "—";
  try {
    return new Date(t * 1000).toISOString().slice(0, 10);
  } catch {
    return "—";
  }
}

// RobtexCard is an opt-in "comprehensive IP" lookup: network ownership plus
// active and, most usefully, passive DNS (host names historically seen on the
// IP — including stale/forgotten ones). Opt-in because it is an external,
// rate-limited source.
function RobtexCard() {
  const [data, setData] = useState<RobtexIpInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.robtex());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      icon={<NetworkIcon />}
      title="Robtex (network & passive DNS)"
      right={
        <button
          onClick={run}
          disabled={loading}
          className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? "looking up…" : data ? "re-run" : "look up"}
        </button>
      }
    >
      {!data && !error && !loading && (
        <p className="text-sm text-muted">
          Fetch Robtex's view of this domain's IP: the owning network (ASN / route / whois) and
          active &amp; passive DNS — host names historically observed on the IP, including stale
          ones.
        </p>
      )}
      {loading && <Spinner label="Querying Robtex…" />}
      {error && <ErrorNote error={`Robtex source unavailable — ${error}`} />}
      {data && !loading && (
        <>
          <Field label="IP" value={data.ip} />
          <Field
            label="Network"
            value={
              data.asn ? (
                <span className="flex flex-wrap justify-end gap-1.5">
                  <Pill>AS{data.asn}</Pill>
                  {data.asname && <Pill>{data.asname}</Pill>}
                  {data.bgproute && <Pill>{data.bgproute}</Pill>}
                </span>
              ) : (
                ""
              )
            }
          />
          <Field label="Whois" value={data.whoisdesc || data.routedesc} />

          <RobtexNameList title="Passive DNS (historical)" names={data.passive} />
          <RobtexNameList title="Active DNS" names={data.active} />
        </>
      )}
    </Card>
  );
}

function RobtexNameList({ title, names }: { title: string; names: RobtexIpInfo["passive"] }) {
  if (!names || names.length === 0) return null;
  return (
    <div className="mt-4">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">
        {title} ({names.length})
      </h3>
      <ul className="max-h-72 overflow-auto rounded-lg border border-line bg-ink-900">
        {names.map((n) => (
          <li
            key={n.host}
            className="flex items-center justify-between gap-3 border-b border-line/60 px-3 py-1.5 text-sm last:border-0"
          >
            <a
              href={`https://${n.host}`}
              target="_blank"
              rel="noreferrer"
              className="min-w-0 truncate font-mono text-slate-200 hover:text-accent hover:underline"
              title={n.host}
            >
              {n.host}
            </a>
            <span className="shrink-0 font-mono text-xs text-muted">{fmtEpoch(n.time)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ZoneTransferCard surfaces the AXFR result. An open transfer is a real
// full-zone-disclosure finding, so it is shown as a prominent alert above the
// records; otherwise it is a quiet "closed on all name servers" confirmation.
function ZoneTransferCard({ axfr, open }: { axfr: ZoneTransfer[]; open: ZoneTransfer[] }) {
  if (open.length === 0) {
    return (
      <Card icon={<ShieldIcon />} title="Zone Transfer (AXFR)">
        <p className="text-sm text-ok">
          AXFR refused on all {axfr.length} name server{axfr.length === 1 ? "" : "s"} — zone
          transfer is not exposed.
        </p>
      </Card>
    );
  }
  return (
    <section className="rounded-xl border border-bad/50 bg-bad/10 p-4 shadow-card">
      <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-bad">
        <span>
          <ShieldIcon />
        </span>
        Zone Transfer (AXFR) Exposed
      </h2>
      <p className="mt-2 text-sm text-slate-200">
        {open.length} name server{open.length === 1 ? "" : "s"} handed over the full zone to an
        unauthenticated client — every record below is disclosed. Report as full-zone information
        disclosure.
      </p>
      {open.map((z) => (
        <div key={z.ns} className="mt-3">
          <div className="mb-1 flex items-center gap-2 text-xs text-slate-300">
            <Pill>{z.ns}</Pill>
            <span className="text-muted">
              {z.records?.length ?? 0} records{z.truncated ? " (truncated)" : ""}
            </span>
          </div>
          {/* Zone records are attacker-influenceable; React escapes them as text. */}
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-ink-900 p-3 font-mono text-[12px] leading-relaxed text-slate-200">
            {(z.records ?? []).join("\n")}
          </pre>
        </div>
      ))}
    </section>
  );
}

// EmailAuthCard shows the SPF/DMARC verdict. A spoofable domain (missing/weak
// DMARC) is a commonly-accepted email-spoofing finding, so it is surfaced as a
// warning; a protected domain reads as a quiet confirmation.
function EmailAuthCard({ email }: { email: EmailAuth }) {
  const spoof = email.spoofable;
  const tone = spoof
    ? "border-warn/50 bg-warn/10 text-warn"
    : "border-ok/40 bg-ok/10 text-ok";
  const issues = [...(email.spf?.issues ?? []), ...(email.dmarc?.issues ?? [])];

  return (
    <Card icon={<MailIcon />} title="Email Authentication (SPF / DMARC)">
      <div className={`mb-3 rounded-lg border px-3 py-2 text-sm ${tone}`}>
        <span className="font-semibold uppercase tracking-wide">
          {spoof ? "Spoofable" : "Protected"}
        </span>{" "}
        — {email.summary}
      </div>

      <Field
        label="SPF"
        value={
          email.spf?.present ? (
            <span className="break-all">{email.spf.record}</span>
          ) : (
            <span className="text-warn">not published</span>
          )
        }
      />
      <Field
        label="DMARC"
        value={
          email.dmarc?.present ? (
            <span className="break-all">{email.dmarc.record}</span>
          ) : (
            <span className="text-warn">not published</span>
          )
        }
      />
      {email.dmarc?.present && (
        <Field
          label="DMARC policy"
          value={
            <span className="flex flex-wrap justify-end gap-1.5">
              <Pill>p={email.dmarc.policy || "?"}</Pill>
              {email.dmarc.subdomain_policy && <Pill>sp={email.dmarc.subdomain_policy}</Pill>}
              <Pill>pct={email.dmarc.pct}</Pill>
            </span>
          }
        />
      )}

      {issues.length > 0 && (
        <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-slate-300">
          {issues.map((i, idx) => (
            <li key={idx}>{i}</li>
          ))}
        </ul>
      )}
    </Card>
  );
}
