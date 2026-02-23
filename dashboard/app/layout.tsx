import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AgentGuard — AI Agent Security",
  description: "Runtime detection and response platform for AI agents",
};

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/timeline", label: "Timeline" },
  { href: "/events", label: "Events" },
  { href: "/policies", label: "Policies" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="min-h-screen bg-gray-50">
          <nav className="fixed top-0 left-0 h-full w-56 bg-gray-900 flex flex-col z-40">
            <div className="px-5 py-5 border-b border-gray-700">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 bg-indigo-500 rounded-md flex items-center justify-center">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <span className="font-bold text-white text-lg">AgentGuard</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">AI Security Platform</p>
            </div>
            <ul className="flex-1 px-3 py-4 space-y-1">
              {NAV_LINKS.map(({ href, label }) => (
                <li key={href}>
                  <Link
                    href={href}
                    className="flex items-center gap-2 px-3 py-2 text-sm text-gray-300 rounded-lg hover:bg-gray-800 hover:text-white transition-colors"
                  >
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
            <div className="px-5 py-4 border-t border-gray-700">
              <p className="text-xs text-gray-500">v0.1.0 · Phase 1</p>
            </div>
          </nav>
          <main className="ml-56 min-h-screen p-8">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
