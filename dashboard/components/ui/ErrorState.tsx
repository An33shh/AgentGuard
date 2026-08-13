import Link from "next/link";

export function ErrorState({
  title,
  message,
  retryHref,
}: {
  title: string;
  message: string;
  retryHref?: string;
}) {
  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#F85149]/20 p-8 text-center space-y-3">
      <h2 className="text-sm font-semibold text-[#F85149]">{title}</h2>
      <p className="text-sm text-[#6E7D91]">{message}</p>
      {retryHref && (
        <Link
          href={retryHref}
          className="inline-block text-xs font-medium text-indigo-400 hover:text-indigo-300 transition-colors"
        >
          Try again
        </Link>
      )}
    </div>
  );
}
