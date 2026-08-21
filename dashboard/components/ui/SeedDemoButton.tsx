"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { seedDemo } from "@/lib/api";

export function SeedDemoButton({ className = "" }: { className?: string }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClick = async () => {
    setLoading(true);
    setError(null);
    try {
      await seedDemo();
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={className}>
      <button
        onClick={handleClick}
        disabled={loading}
        className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 disabled:opacity-40 transition-colors"
      >
        {loading ? "Seeding…" : "Seed Demo Data"}
      </button>
      {error && <p className="text-xs text-[#F85149] mt-2">{error}</p>}
    </div>
  );
}
