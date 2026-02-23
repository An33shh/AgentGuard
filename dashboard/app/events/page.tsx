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
        <h1 className="text-2xl font-bold text-gray-900">Events</h1>
        <p className="text-sm text-gray-500 mt-1">
          All intercepted agent actions with filtering and search
        </p>
      </div>

      {apiError && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-800">
          API unavailable — start the API server first.
        </div>
      )}

      <EventTable events={events} />
    </div>
  );
}
