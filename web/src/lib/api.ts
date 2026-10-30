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

export interface Takeover {
  vulnerable: boolean;
  service: string;
  cname: string;
  evidence: string;
}

export interface ProbeResult {
  host: string;
  url: string;
  ip: string;
  status: number;
  title: string;
  server: string;
  powered_by: string;
  content_length: number;
  redirect_to: string;
  tech: string[];
  cors: string;
  missing_headers: string[];
  takeover?: Takeover;
  error?: string;
}

export interface XssPoc {
  type: string;
  type_description: string;
  inject_type: string;
  detection_method: string;
  confidence: string;
  confidence_reason: string;
  location: string;
  method: string;
  data: string;
  param: string;
  payload: string;
  evidence: string;
  cwe: string;
  severity: string;
  message_id: number;
  message_str: string;
}

export interface XssTargetSummary {
  target: string;
  // "clean" | "findings" | "skipped" (skipped carries an error_code)
  status: string;
  error_code?: string;
  findings_count: number;
}

export interface XssMeta {
  dalfox_version: string;
  failed_requests: number;
  total_requests: number;
  scan_duration_ms: number;
  incomplete: boolean;
  target_summary?: XssTargetSummary[];
}

export interface XssResult {
  target: string;
  count: number;
  pocs: XssPoc[];
  meta: XssMeta;
}

export interface CrawlTarget {
  url: string;
  params: string[];
  source: string; // "link" | "form" | "js"
  // Set on non-GET forms: how to submit them, and the page they were found on.
  method?: string;
  data?: string;
  reflect_url?: string;
}

// ScanTarget is what /api/scan accepts per target; method and data are
// per-target overrides so a POST form is scanned as a POST.
export type ScanTarget = Pick<CrawlTarget, "url" | "method" | "data" | "reflect_url">;

export interface CrawlResult {
  seed: string;
  pages: number;
  targets: CrawlTarget[];
}

// ScanOptions mirrors the backend scanOptionsReq (pkg/handlers) which maps to
// xss.Options. All fields are optional; omitted ones take dalfox defaults.
export interface ScanOptions {
  cookie?: string;
  headers?: string[];
  user_agent?: string;
  method?: string;
  skip_mining?: boolean;
  skip_mining_dict?: boolean;
  skip_mining_dom?: boolean;
  // skip_ast silences dalfox's unverified "[A]" DOM-XSS static findings.
  skip_ast?: boolean;
  // only_poc filters reported finding types: comma-separated v,r,a,i (e.g. "v").
  only_poc?: string;
  blind_url?: string;
  rate_limit?: number;
  follow_redirects?: boolean;
  deep_scan?: boolean;
  waf_evasion?: boolean;
  stored_xss?: boolean;
  sxss_url?: string;
  workers?: number;
  timeout?: number;
  delay?: number;
  scan_timeout?: number;
}

export interface ScanTargetStatus {
  url: string;
  method?: string;
  state: string; // pending | running | done | error | stopped
  findings: number;
  error?: string;
  // Per-target dalfox report metadata: lets the UI tell a clean scan apart from
  // one that was incomplete.
  meta?: XssMeta;
}

export interface ScanJob {
  id: string;
  state: string; // queued | running | done | stopped | error
  total: number;
  done: number;
  findings: XssPoc[];
  targets: ScanTargetStatus[];
  // True when the findings cap was hit, i.e. not everything was stored.
  truncated?: boolean;
  started_at: string;
  finished_at?: string;
  error?: string;
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

async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const b = await res.json();
      if (b && typeof b.error === "string") detail = b.error;
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
  // Active HTTP probe + takeover check of a caller-supplied host list.
  probe: (hosts: string[]) => postJSON<ProbeResult[]>("/api/probe", { hosts }),
  // Active XSS scan of a single caller-supplied URL via the dalfox binary.
  xss: (url: string, skipMining = false, cookie = "") =>
    postJSON<XssResult>("/api/xss", { url, skip_mining: skipMining, cookie }),
  // Seed URL for the crawler, derived from the -domain the server started with.
  target: () => getJSON<{ domain: string; scheme: string; url: string }>("/api/target"),
  // Crawl a seed URL (same host) + JS analysis to discover the scan surface.
  crawl: (body: { url: string; depth?: number; max_pages?: number; cookie?: string }) =>
    postJSON<CrawlResult>("/api/crawl", body),
  // Start a background scan job over many targets; returns the job id.
  startScan: (targets: ScanTarget[], options: ScanOptions) =>
    postJSON<{ job_id: string }>("/api/scan", { targets, options }),
  // Poll a scan job's live state, progress and findings.
  scanStatus: (id: string) => getJSON<ScanJob>(`/api/scan/${encodeURIComponent(id)}`),
  // Cancel a running scan job.
  stopScan: (id: string) =>
    postJSON<{ stopped: boolean }>(`/api/scan/${encodeURIComponent(id)}/stop`, {}),
  // The fuzzing feed is a flat array wrapped in { Urls: [...] } by the backend.
  consumer: () => getJSON<{ Urls: FuzzUrl[] | null }>("/consumer"),
};
