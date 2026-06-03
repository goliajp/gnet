import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { useApi } from "../../api/ApiContext";
import type { DeviceResponse, NetworkResponse } from "../../api/types";
import type { DispatcherHost } from "../../shells/DispatcherShell";

/**
 * Default page when the user lands on the dispatcher shell — quick
 * read on the network + a count of devices, with links into the
 * detail pages. Cheap to render because both queries are already
 * cached by the sub-pages on subsequent visits.
 */
export default function OverviewPage({ host }: { host: DispatcherHost }) {
  const api = useApi();
  const network = useQuery({
    queryKey: ["network"],
    queryFn: () => api<NetworkResponse>("/api/network"),
  });
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<DeviceResponse[]>("/api/devices"),
  });

  const deviceCount = devices.data?.length;
  const eligibleCount = devices.data?.filter((d) => d.relay_eligible).length;

  return (
    <section className="space-y-6">
      <h2 className="text-xs uppercase tracking-wider text-zinc-500">
        overview
      </h2>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat
          label="version"
          value={`v${host.version}`}
          href={null}
        />
        <Stat
          label="devices"
          value={deviceCount === undefined ? "…" : String(deviceCount)}
          href="../devices"
          sub={
            eligibleCount === undefined
              ? undefined
              : `${eligibleCount} relay-eligible`
          }
        />
        <Stat
          label="network"
          value={network.data?.name ?? "…"}
          href="../network"
          sub={
            network.data
              ? `id ${network.data.id.slice(0, 8)}…`
              : undefined
          }
        />
      </div>
    </section>
  );
}

function Stat({
  label,
  value,
  sub,
  href,
}: {
  label: string;
  value: string;
  sub?: string;
  href: string | null;
}) {
  const inner = (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 transition hover:border-zinc-700">
      <p className="text-xs uppercase tracking-wider text-zinc-500">{label}</p>
      <p className="mt-1 text-lg font-semibold text-zinc-100">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-zinc-500">{sub}</p>}
    </div>
  );
  if (!href) return inner;
  return (
    <Link to={href} className="block">
      {inner}
    </Link>
  );
}
