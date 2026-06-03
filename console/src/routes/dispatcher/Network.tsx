import { useQuery } from "@tanstack/react-query";
import { useApi } from "../../api/ApiContext";
import type { NetworkResponse } from "../../api/types";

export default function NetworkPage() {
  const api = useApi();
  const network = useQuery({
    queryKey: ["network"],
    queryFn: () => api<NetworkResponse>("/api/network"),
  });

  if (!network.data) {
    return <p className="text-zinc-500">…</p>;
  }

  return (
    <section className="space-y-4">
      <h2 className="text-xs uppercase tracking-wider text-zinc-500">
        network
      </h2>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 sm:grid-cols-[max-content_1fr]">
        <Row label="id" value={network.data.id} mono />
        <Row label="name" value={network.data.name} />
        <Row
          label="overlay v4 prefix"
          value={network.data.overlay_v4_prefix_hex}
          mono
        />
        <Row
          label="overlay v6 prefix"
          value={network.data.overlay_v6_prefix_hex}
          mono
        />
        <Row
          label="created"
          value={new Date(network.data.created_at).toISOString()}
          mono
        />
      </dl>
    </section>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-zinc-500">{label}</dt>
      <dd className={mono ? "break-all text-zinc-200" : "text-zinc-200"}>
        {value}
      </dd>
    </>
  );
}
