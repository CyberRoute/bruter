// Typed client for the Bruter Go backend. All endpoints are same-origin: in
// production the SPA is embedded and served by the Go server; in dev, Vite
// proxies these paths to :8080 (see vite.config.ts).

export interface HostInfo {
  domain: string;
  ipv4: string;
  ipv6: string;
  asn: string;
  city: string;
  country: string;
  isp: string;
  org: string;
  region_code: string;
  ports: number[];
  mx: Record<string, number>;
  headers: Record<string, string>;
  banners: Record<string, string>;
}

export interface FuzzUrl {
  id: number;
  path: string;
  status: number;
  progress: number;
  data: string;
  redirectpath: string;
}

export interface SslCert {
  [key: string]: unknown;
}

export interface SoaRecord {
  ns: string;
  mbox: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  min_ttl: number;
}

export interface ZoneTransfer {
  ns: string;
  vulnerable: boolean;
  records?: string[];
  truncated?: boolean;
  error?: string;
}

export interface SubdomainResult {
  host: string;
  ips: string[];
}

export interface BruteResult {
  results: SubdomainResult[];
  wildcard: boolean;
  tested: number;
}

export interface SpfResult {
  present: boolean;
  record: string;
  qualifier: string;
  issues: string[];
}

export interface DmarcResult {
  present: boolean;
  record: string;
  policy: string;
  subdomain_policy: string;
  pct: number;
  issues: string[];
}

export interface EmailAuth {
  spf: SpfResult;
  dmarc: DmarcResult;
  spoofable: boolean;
  summary: string;
}

export interface ReverseIp {
  ip: string;
  hosts: string[];
}

export interface RobtexName {
  host: string;
  time: number;
}

export interface RobtexIpInfo {
  ip: string;
  asn: number;
  asname: string;
  asdesc: string;
  bgproute: string;
  whoisdesc: string;
  routedesc: string;
  country: string;
  city: string;
  active: RobtexName[];
  passive: RobtexName[];
}

export interface DnsRecords {
  a: string[] | null;
  aaaa: string[] | null;
  ns: string[] | null;
  txt: string[] | null;
  cname: string;
  mx: Record<string, number>;
  ptr: string[] | null;
  soa?: SoaRecord;
  axfr?: ZoneTransfer[];
  email?: EmailAuth;
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    // The backend sends { "error": "..." } on failures (e.g. all certificate
    // sources rate-limited); surface that message rather than a bare status.
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && typeof body.error === "string") detail = body.error;
    } catch {
      /* non-JSON error body; keep the status */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

export const api = {
  host: () => getJSON<HostInfo>("/api/host"),
  ssl: () => getJSON<SslCert[]>("/api/ssl"),
  dns: () => getJSON<DnsRecords>("/api/dns"),
  // Active brute-force of common subdomain labels (DNS resolution of guesses).
  bruteSubdomains: () => getJSON<BruteResult>("/api/subdomains/brute"),
  // Reverse-IP neighbours via an external source (small shared daily quota).
  reverseIp: () => getJSON<ReverseIp>("/api/reverseip"),
  // Robtex comprehensive IP view: network ownership + active/passive DNS.
  robtex: () => getJSON<RobtexIpInfo>("/api/robtex"),
  whois: () => getJSON<{ whois: string }>("/api/whois"),
  // The fuzzing feed is a flat array wrapped in { Urls: [...] } by the backend.
  consumer: () => getJSON<{ Urls: FuzzUrl[] | null }>("/consumer"),
};
