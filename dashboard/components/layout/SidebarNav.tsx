"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_LINKS = [
  {
    href: "/dashboard",
    label: "Dashboard",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </svg>
    ),
  },
  {
    href: "/timeline",
    label: "Timeline",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 12h4l3-9 4 18 3-9h4" />
      </svg>
    ),
  },
  {
    href: "/events",
    label: "Events",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
        <rect x="9" y="3" width="6" height="4" rx="1" />
        <path d="M9 12h6M9 16h4" />
      </svg>
    ),
  },
  {
    href: "/agents",
    label: "Agents",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="8" r="4" />
        <path d="M6 20v-1a6 6 0 0112 0v1" />
      </svg>
    ),
  },
  {
    href: "/policies",
    label: "Policies",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <nav
      className="fixed top-0 left-0 h-full w-56 flex flex-col z-40"
      style={{
        background: "linear-gradient(180deg, #070B14 0%, #060910 100%)",
        borderRight: "1px solid #1C2844",
      }}
    >
      {/* Brand */}
      <div className="px-5 py-5" style={{ borderBottom: "1px solid #1C2844" }}>
        <div className="flex items-center gap-3">
          {/* Logo mark */}
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 relative"
            style={{
              background: "linear-gradient(135deg, #4F46E5 0%, #6366F1 100%)",
              boxShadow: "0 0 0 1px rgba(99,102,241,0.3), 0 4px 16px rgba(99,102,241,0.3)",
            }}
          >
            <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.25}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-semibold text-[#E6EDF3] tracking-tight leading-none">AgentGuard</p>
            <p className="text-[10px] text-[#3A4A5C] mt-0.5 tracking-widest uppercase">Security</p>
          </div>
        </div>
      </div>

      {/* Section label */}
      <div className="px-5 pt-5 pb-1.5">
        <p className="text-[10px] font-medium text-[#3A4A5C] uppercase tracking-[0.12em]">Monitoring</p>
      </div>

      {/* Nav items */}
      <ul className="flex-1 px-2.5 space-y-0.5">
        {NAV_LINKS.map(({ href, label, icon }) => {
          const isActive = pathname === href || (href !== "/dashboard" && pathname.startsWith(href));
          return (
            <li key={href}>
              <Link
                href={href}
                className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all duration-150 relative group"
                style={isActive ? {
                  background: "linear-gradient(90deg, rgba(99,102,241,0.12) 0%, rgba(99,102,241,0.04) 100%)",
                  color: "#E6EDF3",
                  fontWeight: 500,
                  borderLeft: "2px solid #6366F1",
                  paddingLeft: "10px",
                } : {
                  color: "#6E7D91",
                }}
              >
                <span
                  className="transition-colors duration-150"
                  style={{ color: isActive ? "#818CF8" : "#3A4A5C" }}
                >
                  {icon}
                </span>
                <span className="tracking-tight">{label}</span>
                {isActive && (
                  <span
                    className="absolute right-2.5 w-1 h-1 rounded-full"
                    style={{ background: "#6366F1", boxShadow: "0 0 4px rgba(99,102,241,0.8)" }}
                  />
                )}
              </Link>
            </li>
          );
        })}
      </ul>

      {/* Footer */}
      <div className="px-5 py-4" style={{ borderTop: "1px solid #1C2844" }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0 pulse" style={{ boxShadow: "0 0 4px rgba(63,185,80,0.8)" }} />
            <p className="text-xs text-[#3A4A5C]">Live</p>
          </div>
          <p className="text-[10px] text-[#3A4A5C] font-mono">v0.8.0</p>
        </div>
      </div>
    </nav>
  );
}
