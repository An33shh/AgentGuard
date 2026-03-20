import { getEvents } from "@/lib/api";
import { EventTable } from "@/components/events/EventTable";
import type { Event } from "@/types";

export default async function EventsPage() {
  let events: Event[] = [];
  let apiError = false;

  try {
    events = await getEvents({ limit: 200 });
  } catch {
    apiError = true;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Events</h1>
        <p className="text-sm text-[#484F58] mt-0.5">
          All intercepted agent actions with filtering and search
        </p>
      </div>

      {apiError && (
        <div className="bg-[#E88C30]/8 border border-[#E88C30]/20 rounded-xl p-4 text-sm text-[#E88C30]">
          API unavailable — start the API server first.
        </div>
      )}

      <EventTable initialEvents={events} />
    </div>
  );
}
