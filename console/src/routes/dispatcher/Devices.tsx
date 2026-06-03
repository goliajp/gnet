import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useApi } from "../../api/ApiContext";
import { ApiError } from "../../api/client";
import type { DeviceResponse } from "../../api/types";

export default function DevicesPage() {
  const api = useApi();
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<DeviceResponse[]>("/api/devices"),
  });

  return (
    <section className="space-y-4">
      <div className="flex items-baseline justify-between">
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

function DeviceRow({ device }: { device: DeviceResponse }) {
  const api = useApi();
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
