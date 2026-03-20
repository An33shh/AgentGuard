import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { SidebarNav } from "@/components/layout/SidebarNav";

const ibmPlexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600"],
  variable: "--font-sans",
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "AgentGuard — AI Agent Security",
  description: "Runtime detection and response platform for AI agents",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${ibmPlexSans.variable} ${ibmPlexMono.variable}`}>
      <body className="bg-[--base] text-[--text-1]">
        <div className="flex min-h-screen">
          <SidebarNav />
          <main className="flex-1 ml-56 min-h-screen px-8 py-7">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
