export function WidgetError({ message }: { message: string }) {
  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6 flex items-center justify-center min-h-[120px]">
      <p className="text-xs text-[#6E7D91]">{message}</p>
    </div>
  );
}
