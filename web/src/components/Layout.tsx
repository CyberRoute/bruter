import { NavLink, Outlet } from "react-router-dom";
import { GlobeIcon, SitemapIcon, NetworkIcon, BugIcon } from "./icons";
import type { ReactNode } from "react";

const tabs = [
  { to: "/", label: "Dashboard", icon: <GlobeIcon /> },
  { to: "/subdomains", label: "Subdomains", icon: <SitemapIcon /> },
  { to: "/dns", label: "DNS", icon: <NetworkIcon /> },
  { to: "/xss", label: "XSS", icon: <BugIcon /> },
];

function Tab({ to, label, icon }: { to: string; label: string; icon: ReactNode }) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      className={({ isActive }) =>
        `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
          isActive
            ? "bg-accent/10 text-accent ring-1 ring-accent/30"
            : "text-slate-300 hover:bg-ink-700 hover:text-white"
        }`
      }
    >
      <span className="opacity-80">{icon}</span>
      {label}
    </NavLink>
  );
}

export function Layout() {
  return (
    <div className="mx-auto min-h-full max-w-6xl px-4 pb-16">
      <header className="sticky top-0 z-[500] -mx-4 mb-6 border-b border-line bg-ink-900/80 px-4 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <img
              src="/bruter-icon.png"
              alt="Bruter logo"
              className="h-9 w-9 rounded-lg ring-1 ring-line"
            />
            <div>
              <div className="font-semibold tracking-tight text-white">Bruter</div>
              <div className="text-xs text-muted">Scan Report Dashboard</div>
            </div>
          </div>
          <nav className="flex items-center gap-1">
            {tabs.map((t) => (
              <Tab key={t.to} {...t} />
            ))}
          </nav>
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
