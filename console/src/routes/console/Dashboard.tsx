import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { api } from "../../api/client";
import type {
  ConsoleMeResponse,
  RegisterNetworkRequest,
  RegisterNetworkResponse,
  UserNetworkRow,
} from "../../api/types";
import type { ConsoleHost } from "../../shells/ConsoleShell";
import { ErrorLine, Field } from "./Login";

/**
 * Logged-in console dashboard.
 *
 * Lists the user's federated networks, lets them add a new self-host
 * dispatcher by pasting (label, endpoint) — the server derives the
 * federation token deterministically and returns the plaintext
 * exactly once (the user copies it into their dispatcher's setup
 * UI).
 *
 * Each row carries a "remove" affordance — soft-deletes the row
 * client-side via DELETE /api/networks/{id} (plan §6.3 console-side
 * revocation; the dispatcher-side revocation is independent).
 */
export default function ConsoleDashboard({
  host,
  me,
}: {
  host: ConsoleHost;
  me: ConsoleMeResponse;
}) {
  const qc = useQueryClient();
  const nav = useNavigate();

  const networks = useQuery({
    queryKey: ["console", "networks"],
    queryFn: () => api<UserNetworkRow[]>("/api/networks"),
  });

  const logout = useMutation({
    mutationFn: () =>
      api<void>("/api/auth/logout", { method: "POST" }),
    onSuccess: () => {
      qc.setQueryData(["console", "me"], null);
      qc.invalidateQueries({ queryKey: ["console"] });
      nav("/", { replace: true });
    },
  });

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 pt-8 font-mono text-sm">
        <Link to="/" className="font-semibold text-zinc-100">
          gnet
        </Link>
        <nav className="flex items-center gap-4 text-zinc-400">
          <span className="text-zinc-500">
            v{host.version} · {me.email ?? me.user_id.slice(0, 8)}
          </span>
          <button
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-zinc-200 hover:border-zinc-500 disabled:opacity-50"
          >
            sign out
          </button>
        </nav>
      </header>

      <main className="mx-auto max-w-5xl space-y-12 px-6 pb-24 pt-10">
        <section className="space-y-2">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-zinc-500">
            networks
          </p>
          <h1 className="text-3xl font-semibold text-zinc-100">
            Your federated dispatchers
          </h1>
          <p className="max-w-2xl text-sm text-zinc-400">
            Add the dispatchers you self-host and operate them through
            this console. Tokens are derived per (account · label ·
            endpoint) and shown to you exactly once.
          </p>
        </section>

        <NetworksList
          rows={networks.data}
          isLoading={networks.isLoading}
          error={networks.error}
        />

        <AddNetwork
          onAdded={() => {
            qc.invalidateQueries({ queryKey: ["console", "networks"] });
          }}
        />
      </main>
    </div>
  );
}

function NetworksList({
  rows,
  isLoading,
  error,
}: {
  rows: UserNetworkRow[] | undefined;
  isLoading: boolean;
  error: unknown;
}) {
  const qc = useQueryClient();
  const remove = useMutation({
    mutationFn: (id: string) =>
      api<void>(`/api/networks/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["console", "networks"] });
    },
  });

  if (isLoading) {
    return (
      <p className="font-mono text-xs text-zinc-500">loading…</p>
    );
  }
  if (error) return <ErrorLine err={error} />;
  if (!rows || rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-zinc-800 bg-zinc-900/30 p-8 text-center">
        <p className="font-mono text-sm text-zinc-400">
          no networks yet — add one below.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/40">
      <table className="w-full font-mono text-xs">
        <thead className="bg-zinc-900/60 text-zinc-500">
          <tr>
            <th className="px-4 py-3 text-left">label</th>
            <th className="px-4 py-3 text-left">endpoint</th>
            <th className="px-4 py-3 text-left">mode</th>
            <th className="px-4 py-3 text-right">created</th>
            <th className="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {rows.map((r) => (
            <tr key={r.id} className="text-zinc-200">
              <td className="px-4 py-3">
                <Link
                  to={`/networks/${r.id}`}
                  className="text-zinc-100 underline-offset-4 hover:text-white hover:underline"
                >
                  {r.network_label}
                </Link>
              </td>
              <td className="px-4 py-3 text-zinc-400">
                {r.dispatcher_endpoint}
              </td>
              <td className="px-4 py-3 text-zinc-400">{r.mode}</td>
              <td className="px-4 py-3 text-right text-zinc-500">
                {fmtDate(r.created_at)}
              </td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => {
                    if (
                      confirm(
                        `Revoke federation with ${r.network_label}? You can re-add it later.`,
                      )
                    ) {
                      remove.mutate(r.id);
                    }
                  }}
                  disabled={remove.isPending}
                  className="rounded border border-zinc-800 px-2 py-1 text-zinc-400 hover:border-rose-800 hover:text-rose-300 disabled:opacity-50"
                >
                  remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AddNetwork({ onAdded }: { onAdded: () => void }) {
  const [label, setLabel] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [token, setToken] = useState<string | null>(null);

  const submit = useMutation({
    mutationFn: (body: RegisterNetworkRequest) =>
      api<RegisterNetworkResponse>("/api/networks", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (resp) => {
      setToken(resp.federation_token);
      setLabel("");
      setEndpoint("");
      onAdded();
    },
  });

  return (
    <section className="space-y-4 rounded-lg border border-zinc-800 bg-zinc-900/30 p-6">
      <header>
        <h2 className="font-mono text-sm uppercase tracking-[0.18em] text-zinc-400">
          add a network
        </h2>
        <p className="mt-1 text-xs text-zinc-500">
          point this at the dispatcher you self-host. The label is for
          you; the endpoint is the URL the console talks to (typically{" "}
          <code className="font-mono text-zinc-400">http://…:8765</code>).
        </p>
      </header>

      {token ? (
        <TokenReveal token={token} onDismiss={() => setToken(null)} />
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit.mutate({
              network_label: label.trim(),
              dispatcher_endpoint: endpoint.trim(),
            });
          }}
          className="space-y-4"
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="label"
              type="text"
              value={label}
              onChange={setLabel}
              required
              hint="3-32 chars of [a-z0-9_-]"
            />
            <Field
              label="dispatcher endpoint"
              type="url"
              value={endpoint}
              onChange={setEndpoint}
              required
              hint="http(s)://host:port"
            />
          </div>
          {submit.isError && <ErrorLine err={submit.error} />}
          <button
            type="submit"
            disabled={submit.isPending || !label || !endpoint}
            className="rounded-md bg-zinc-100 px-4 py-2 font-mono text-sm font-medium text-zinc-950 transition disabled:cursor-not-allowed disabled:opacity-50 enabled:hover:bg-white"
          >
            {submit.isPending ? "…" : "register"}
          </button>
        </form>
      )}
    </section>
  );
}

function TokenReveal({
  token,
  onDismiss,
}: {
  token: string;
  onDismiss: () => void;
}) {
  return (
    <div className="space-y-3 rounded-md border border-amber-900/50 bg-amber-950/30 p-4">
      <p className="font-mono text-xs text-amber-300">
        federation token — copy now, this is the only time it's shown
      </p>
      <pre className="overflow-x-auto rounded bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100">
        {token}
      </pre>
      <p className="text-xs text-zinc-400">
        paste this into your dispatcher's{" "}
        <code className="font-mono">/api/federation/register</code> as
        the bearer, then dismiss this banner.
      </p>
      <button
        onClick={onDismiss}
        className="rounded border border-zinc-700 px-3 py-1 font-mono text-xs text-zinc-300 hover:border-zinc-500"
      >
        I've copied it
      </button>
    </div>
  );
}

function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}
