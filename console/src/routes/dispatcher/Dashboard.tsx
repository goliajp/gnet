import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../../api/client";
import type {
  DeviceResponse,
  MeResponse,
  NetworkResponse,
} from "../../api/types";
import type { DispatcherHost } from "../../shells/DispatcherShell";

export default function Dashboard({
  host,
  me,
}: {
  host: DispatcherHost;
  me: MeResponse;
}) {
  const qc = useQueryClient();
  const network = useQuery({
    queryKey: ["network"],
    queryFn: () => api<NetworkResponse>("/api/network"),
  });
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<DeviceResponse[]>("/api/devices"),
  });

  const logout = useMutation({
    mutationFn: () => api<void>("/api/auth/logout", { method: "POST" }),
    onSuccess: async () => {
      await qc.invalidateQueries();
    },
  });

  return (
    <div className="min-h-screen font-mono text-sm">
      <header className="flex items-center justify-between border-b border-zinc-800 px-6 py-4">
        <div>
          <p className="text-xs uppercase tracking-wider text-zinc-500">
            dispatcher · v{host.version}
          </p>
          <h1 className="text-lg font-semibold text-zinc-100">
            {host.network_name}
          </h1>
        </div>
        <div className="flex items-center gap-3 text-xs text-zinc-400">
          <span>
            {me.username} <span className="text-zinc-500">·</span> {me.role}
          </span>
          <button
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            sign out
          </button>
        </div>
      </header>

      <main className="space-y-8 px-6 py-6">
        <section>
          <h2 className="mb-3 text-xs uppercase tracking-wider text-zinc-500">
            network
          </h2>
          {network.data ? (
            <NetworkCard network={network.data} />
          ) : (
            <p className="text-zinc-500">…</p>
          )}
        </section>

        <section>
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-xs uppercase tracking-wider text-zinc-500">
              devices
            </h2>
            <span className="text-xs text-zinc-500">
              {devices.data?.length ?? "…"}
            </span>
          </div>
          {devices.data ? (
            <DevicesTable devices={devices.data} />
          ) : (
            <p className="text-zinc-500">…</p>
          )}
        </section>
      </main>
    </div>
  );
}

function NetworkCard({ network }: { network: NetworkResponse }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 sm:grid-cols-[max-content_1fr]">
      <Row label="id" value={network.id} mono />
      <Row label="name" value={network.name} />
      <Row label="overlay v4 prefix" value={network.overlay_v4_prefix_hex} mono />
      <Row label="overlay v6 prefix" value={network.overlay_v6_prefix_hex} mono />
      <Row label="created" value={new Date(network.created_at).toISOString()} mono />
    </dl>
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

function DeviceRow({ device }: { device: DeviceResponse }) {
  const qc = useQueryClient();
  const rename = useMutation({
    mutationFn: (alias: string) =>
      api<DeviceResponse>("/api/devices/" + device.id + "/alias", {
        method: "PUT",
        body: JSON.stringify({ alias }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices"] }),
  });

  const onRename = () => {
    const next = window.prompt(`rename "${device.alias}" to:`, device.alias);
    if (next && next !== device.alias) rename.mutate(next);
  };

  const errMsg =
    rename.error instanceof ApiError
      ? rename.error.body || rename.error.message
      : (rename.error as Error | undefined)?.message;

  return (
    <tr className="text-zinc-300">
      <td className="px-4 py-2 text-zinc-100">
        <div className="flex items-center gap-2">
          <span>{device.alias}</span>
          <button
            onClick={onRename}
            disabled={rename.isPending}
            title="rename"
            className="text-xs text-zinc-500 transition hover:text-zinc-100 disabled:opacity-50"
          >
            ✎
          </button>
          {rename.isError && (
            <span className="text-xs text-red-300">{errMsg}</span>
          )}
        </div>
      </td>
      <td className="px-4 py-2">{device.vip_v4}</td>
      <td className="px-4 py-2">{device.vip_v6}</td>
      <td className="px-4 py-2">
        {device.relay_eligible ? (
          <span className="rounded bg-emerald-900/40 px-2 py-0.5 text-xs text-emerald-300">
            eligible
          </span>
        ) : (
          <span className="text-zinc-500">—</span>
        )}
      </td>
      <td className="px-4 py-2 text-zinc-400">
        {device.last_reflexive ?? "—"}
      </td>
      <td className="px-4 py-2 text-zinc-500">
        {new Date(device.created_at).toISOString().slice(0, 10)}
      </td>
    </tr>
  );
}

function DevicesTable({ devices }: { devices: DeviceResponse[] }) {
  if (devices.length === 0) {
    return (
      <p className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 text-zinc-500">
        no devices yet
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="w-full border-collapse text-left">
        <thead className="border-b border-zinc-800 bg-zinc-900/40 text-xs uppercase tracking-wider text-zinc-500">
          <tr>
            <th className="px-4 py-2 font-normal">alias</th>
            <th className="px-4 py-2 font-normal">vip v4</th>
            <th className="px-4 py-2 font-normal">vip v6</th>
            <th className="px-4 py-2 font-normal">relay</th>
            <th className="px-4 py-2 font-normal">last reflexive</th>
            <th className="px-4 py-2 font-normal">created</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {devices.map((d) => (
            <DeviceRow key={d.id} device={d} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
