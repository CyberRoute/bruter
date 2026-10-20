import { useEffect, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup, Polyline } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Leaflet's default marker icons are resolved from the CSS by relative URL,
// which breaks under a bundler; point them at the CDN assets explicitly.
const base = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images";
const destIcon = L.icon({
  iconUrl: `${base}/marker-icon.png`,
  iconRetinaUrl: `${base}/marker-icon-2x.png`,
  shadowUrl: `${base}/marker-shadow.png`,
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
});
const srcIcon = L.icon({
  ...destIcon.options,
  iconUrl: "https://maps.google.com/mapfiles/ms/icons/red-dot.png",
  iconRetinaUrl: "https://maps.google.com/mapfiles/ms/icons/red-dot.png",
  iconSize: [32, 32],
  iconAnchor: [16, 32],
  shadowUrl: undefined,
});

type Geo = { lat: number; lon: number; ip: string };

async function locate(ip?: string): Promise<Geo | null> {
  try {
    const url = ip ? `https://ipapi.co/${ip}/json/` : "https://ipapi.co/json/";
    const res = await fetch(url);
    if (!res.ok) return null;
    const d = await res.json();
    if (typeof d.latitude !== "number" || typeof d.longitude !== "number") return null;
    return { lat: d.latitude, lon: d.longitude, ip: ip ?? d.ip };
  } catch {
    return null;
  }
}

export function GeoMap({ ipv4 }: { ipv4: string }) {
  const [dest, setDest] = useState<Geo | null>(null);
  const [src, setSrc] = useState<Geo | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    if (!ipv4 || ipv4 === "not found") {
      setFailed(true);
      return;
    }
    (async () => {
      const d = await locate(ipv4);
      if (!alive) return;
      if (!d) {
        setFailed(true);
        return;
      }
      setDest(d);
      const s = await locate();
      if (alive && s) setSrc(s);
    })();
    return () => {
      alive = false;
    };
  }, [ipv4]);

  if (failed) {
    return (
      <div className="flex h-[360px] items-center justify-center text-sm text-muted">
        Geolocation unavailable for {ipv4 || "this target"}.
      </div>
    );
  }
  if (!dest) {
    return (
      <div className="flex h-[360px] items-center justify-center text-sm text-muted">
        Locating {ipv4}…
      </div>
    );
  }

  return (
    <div className="h-[360px] overflow-hidden rounded-lg border border-line">
      <MapContainer
        center={[dest.lat, dest.lon]}
        zoom={4}
        scrollWheelZoom={false}
        style={{ height: "100%", width: "100%" }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <Marker position={[dest.lat, dest.lon]} icon={destIcon}>
          <Popup>
            <b>Destination:</b> {dest.ip}
          </Popup>
        </Marker>
        {src && (
          <>
            <Marker position={[src.lat, src.lon]} icon={srcIcon}>
              <Popup>
                <b>Source:</b> {src.ip}
              </Popup>
            </Marker>
            <Polyline positions={[[src.lat, src.lon], [dest.lat, dest.lon]]} color="#22d3ee" />
          </>
        )}
      </MapContainer>
    </div>
  );
}
