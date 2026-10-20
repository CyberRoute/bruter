import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Card, Spinner, ErrorNote } from "../components/ui";
import { FileIcon } from "../components/icons";

export function Whois() {
  const { data, loading, error } = useAsync(() => api.whois());
  const [copied, setCopied] = useState(false);

  if (loading) return <Spinner label="Running WHOIS lookup…" />;
  if (error) return <ErrorNote error={error} />;

  const text = (data?.whois ?? "").trim();
  if (!text) return <ErrorNote error="No WHOIS information available for this domain." />;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  };

  return (
    <Card
      icon={<FileIcon />}
      title="WHOIS Record"
      right={
        <button
          onClick={copy}
          className="rounded-lg border border-line bg-ink-700 px-3 py-1 text-xs text-slate-200 hover:border-accent hover:text-accent"
        >
          {copied ? "copied ✓" : "copy"}
        </button>
      }
    >
      {/* WHOIS output is untrusted registrar data; React escapes it as text. */}
      <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-ink-900 p-4 font-mono text-[12.5px] leading-relaxed text-slate-200">
        {text}
      </pre>
    </Card>
  );
}
