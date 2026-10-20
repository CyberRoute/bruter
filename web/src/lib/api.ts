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
  whois: () => getJSON<{ whois: string }>("/api/whois"),
  // The fuzzing feed is a flat array wrapped in { Urls: [...] } by the backend.
  consumer: () => getJSON<{ Urls: FuzzUrl[] | null }>("/consumer"),
};
