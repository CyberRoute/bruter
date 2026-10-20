import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Card, Field, Spinner, ErrorNote, Pill } from "../components/ui";
import { GlobeIcon, NetworkIcon, MapIcon, MailIcon, TerminalIcon, ListIcon } from "../components/icons";
import { GeoMap } from "../components/GeoMap";
import { FuzzFeed } from "../components/FuzzFeed";

export function Dashboard() {
  const { data, loading, error } = useAsync(() => api.host());

  if (loading) return <Spinner label="Gathering host intelligence…" />;
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;

  const mx = Object.entries(data.mx ?? {});
  const banners = Object.entries(data.banners ?? {}).filter(([, v]) => v);
  const headers = Object.entries(data.headers ?? {});

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Card icon={<GlobeIcon />} title="Host Information">
          <Field label="Domain" value={data.domain} />
          <Field label="Country" value={data.country} />
          <Field label="City" value={data.city} />
          <Field label="Organization" value={data.org} />
          <Field label="ASN" value={data.asn} />
        </Card>

        <Card icon={<NetworkIcon />} title="Network Information">
          <Field label="ISP" value={data.isp} />
          <Field label="Region" value={data.region_code} />
          <Field label="IPv4" value={data.ipv4} />
          <Field label="IPv6" value={data.ipv6} />
          <Field
            label="Open ports"
            value={
              data.ports?.length ? (
                <span className="flex flex-wrap justify-end gap-1">
                  {data.ports.map((p) => (
                    <Pill key={p}>{p}</Pill>
                  ))}
                </span>
              ) : (
                ""
              )
            }
          />
        </Card>
      </div>

      <Card icon={<MapIcon />} title="Geolocation">
        <GeoMap ipv4={data.ipv4} />
      </Card>

      <FuzzFeed domain={data.domain} />

      {mx.length > 0 && (
        <Card icon={<MailIcon />} title="MX Records">
          <div className="space-y-1">
            {mx
              .sort((a, b) => a[1] - b[1])
              .map(([host, pref]) => (
                <div key={host} className="flex items-center justify-between font-mono text-sm">
                  <span className="break-all text-slate-100">{host}</span>
                  <Pill>pref {pref}</Pill>
                </div>
              ))}
          </div>
        </Card>
      )}

      {banners.length > 0 && (
        <Card icon={<TerminalIcon />} title="Grabbed Banners">
          <div className="space-y-2">
            {banners.map(([svc, text]) => (
              <div key={svc} className="rounded-lg border border-line bg-ink-900 p-3">
                <div className="mb-1 text-xs uppercase tracking-wide text-accent">{svc}</div>
                <div className="whitespace-pre-wrap break-all font-mono text-sm text-slate-200">
                  {text}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {headers.length > 0 && (
        <Card icon={<ListIcon />} title="HTTP Headers">
          <div className="divide-y divide-line/60">
            {headers.map(([name, value]) => (
              <div
                key={name}
                className="grid grid-cols-1 gap-x-3 gap-y-0.5 py-1.5 sm:grid-cols-[minmax(0,15rem)_1fr]"
              >
                <span className="break-words font-mono text-sm font-medium text-accent">
                  {name}
                </span>
                <span className="break-all font-mono text-sm text-slate-200">{value}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
