// Minimal inline stroke icons (Lucide-style geometry) so the UI carries no
// icon-font dependency and both themes stay crisp.
type P = { className?: string };
const base = "h-4 w-4";
const svg = (children: React.ReactNode) => (p: P) => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={p.className ?? base}
    aria-hidden="true"
  >
    {children}
  </svg>
);

export const GlobeIcon = svg(
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3c2.5 2.7 2.5 15.3 0 18M12 3c-2.5 2.7-2.5 15.3 0 18" />
  </>,
);
export const NetworkIcon = svg(
  <>
    <rect x="9" y="3" width="6" height="6" rx="1" />
    <rect x="3" y="15" width="6" height="6" rx="1" />
    <rect x="15" y="15" width="6" height="6" rx="1" />
    <path d="M12 9v3M6 15v-1a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1" />
  </>,
);
export const BugIcon = svg(
  <>
    <rect x="8" y="6" width="8" height="12" rx="4" />
    <path d="M12 6V4M9 4h6M3 9h3M3 14h3M18 9h3M18 14h3M5 19l3-2M19 19l-3-2M5 5l3 2M19 5l-3 2" />
  </>,
);
export const SearchIcon = svg(
  <>
    <circle cx="11" cy="11" r="7" />
    <path d="m21 21-4.3-4.3" />
  </>,
);
export const MailIcon = svg(
  <>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="m3 7 9 6 9-6" />
  </>,
);
export const TerminalIcon = svg(
  <>
    <path d="m5 8 4 4-4 4M13 16h6" />
  </>,
);
export const ListIcon = svg(
  <>
    <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
  </>,
);
export const ShieldIcon = svg(
  <>
    <path d="M12 3 5 6v6c0 4 3 6.5 7 9 4-2.5 7-5 7-9V6l-7-3Z" />
  </>,
);
export const MapIcon = svg(
  <>
    <path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2-6-2Z" />
    <path d="M9 4v14M15 6v14" />
  </>,
);
export const DownloadIcon = svg(
  <>
    <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />
  </>,
);
export const SitemapIcon = svg(
  <>
    <rect x="9" y="3" width="6" height="5" rx="1" />
    <rect x="3" y="16" width="6" height="5" rx="1" />
    <rect x="15" y="16" width="6" height="5" rx="1" />
    <path d="M12 8v4M6 16v-2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2" />
  </>,
);
