import type { ReactNode } from "react";

export function Panel({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}
