import { useEffect, useMemo, useRef, useState } from "react";
import { api, type FuzzUrl } from "../lib/api";
import { Card, StatusBadge } from "./ui";
import { SearchIcon } from "./icons";

const POLL_MS = 1000;

// Live directory-fuzzing feed. Polls /consumer on an interval (matching the
// legacy UI) and renders discovered paths in a terminal-style pane with a
// progress bar driven by the latest entry's progress value.
export function FuzzFeed({ domain }: { domain: string }) {
  const [urls, setUrls] = useState<FuzzUrl[]>([]);
  const [hitsOnly, setHitsOnly] = useState(true);
  const [stalled, setStalled] = useState(false);
  const paneRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const res = await api.consumer();
        if (alive) {
          setUrls(res.Urls ?? []);
          setStalled(false);
        }
      } catch {
        if (alive) setStalled(true);
      }
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const { progress, bytes, visible } = useMemo(() => {
    const last = urls[urls.length - 1];
    const vis = hitsOnly ? urls.filter((u) => u.status >= 200 && u.status < 400) : urls;
    return {
      progress: last ? last.progress : 0,
      bytes: last ? last.data : `${domain}.json: 0 bytes`,
      visible: vis,
    };
  }, [urls, hitsOnly, domain]);

  // Keep the pane pinned to the newest line unless the user has scrolled up.
  useEffect(() => {
    const el = paneRef.current;
    if (el && atBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [visible.length]);

  const done = progress >= 100;

  return (
    <Card
      icon={<SearchIcon />}
      title="Directory Fuzzing"
      right={
        <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={hitsOnly}
            onChange={(e) => setHitsOnly(e.target.checked)}
            className="accent-accent"
          />
          hits only (2xx/3xx)
        </label>
      }
    >
      <div className="mb-3 flex items-center justify-between text-xs text-muted">
        <span className="font-mono">{bytes}</span>
        <span className="font-mono">
          {visible.length} shown · {urls.length} probed
        </span>
      </div>

      <div className="mb-3 h-2.5 overflow-hidden rounded-full border border-line bg-ink-900">
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            done ? "bg-ok" : "bg-gradient-to-r from-accent-dim to-accent"
          }`}
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
      </div>

      <div
        ref={paneRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
        className="h-[380px] overflow-y-auto rounded-lg border border-line bg-ink-900 p-3 font-mono text-[12px] leading-relaxed"
      >
        {stalled && (
          <p className="text-warn">· waiting for scanner… (is the backend running?)</p>
        )}
        {!stalled && visible.length === 0 && (
          <p className="text-muted">· no paths yet — scan in progress…</p>
        )}
        {visible.map((u) => (
          <div key={u.id} className="flex items-start gap-2 py-0.5">
            <span className="w-10 shrink-0 text-right text-muted">{u.id}</span>
            <StatusBadge status={u.status} />
            <a
              href={u.path}
              target="_blank"
              rel="noreferrer"
              className="truncate text-ok hover:text-accent hover:underline"
              title={u.path}
            >
              {u.path}
            </a>
            {u.redirectpath && (
              <span className="truncate text-muted">→ {u.redirectpath}</span>
            )}
          </div>
        ))}
      </div>
      <p className="mt-2 text-right font-mono text-xs text-muted">
        {done ? "scan complete" : `progress ${progress.toFixed(0)}%`}
      </p>
    </Card>
  );
}
