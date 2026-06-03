import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Navigate, Route, Routes } from "react-router";
import { useApi } from "../api/ApiContext";
import { ApiError } from "../api/client";
import type { HostRoleResponse, MeResponse } from "../api/types";
import Login from "../routes/Login";
import OverviewPage from "../routes/dispatcher/Overview";
import NetworkPage from "../routes/dispatcher/Network";
import DevicesPage from "../routes/dispatcher/Devices";

// Narrow the host-role union to the dispatcher variant — the
// dispatcher binary's response is the only one that carries
// `network_name` / `network_id`.
export type DispatcherHost = Extract<HostRoleResponse, { role: "dispatcher" }>;

/**
 * Dispatcher SPA shell.
 *
 * Splits on "is there a session" → Login when not, layout + nested
 * Routes when yes. The "me" probe is what gates everything else;
 * once that's cached, every other endpoint just trusts the session
 * cookie (standalone) or the federation Bearer added by the console
 * proxy (proxy mode).
 *
 * `mode` distinguishes two mounts:
 *
 * - `standalone` (default): App.tsx detected we're on a dispatcher
 *   binary directly. Cookies work; me=null falls back to Login.
 * - `proxy`: mounted under the SaaS console at /networks/:id via the
 *   federation reverse-proxy. The dispatcher session cookie would
 *   live on the dispatcher origin and the browser can't carry it
 *   through the console — so falling back to Login is dead-end UX.
 *   Instead, me=null means the federation Bearer was rejected (token
 *   revoked / expired) and the user must re-link from the console
 *   dashboard.
 *
 * Sub-routes use relative paths ("network", "devices") so the same
 * tree resolves correctly whether the shell is mounted at "/" or
 * "/networks/:id".
 */
export default function DispatcherShell({
  host,
  mode = "standalone",
}: {
  host: DispatcherHost;
  mode?: "standalone" | "proxy";
}) {
  const api = useApi();
  const me = useQuery({
    queryKey: ["auth", "me", mode],
    queryFn: async () => {
      try {
        return await api<MeResponse>("/api/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });

  if (me.isLoading) {
    return (
      <div className="grid min-h-screen place-items-center font-mono text-sm text-zinc-400">
        …
      </div>
    );
  }
  if (!me.data) {
    if (mode === "proxy") {
      return (
        <div className="grid min-h-screen place-items-center px-6 font-mono text-sm text-zinc-400">
          <div className="max-w-md space-y-2 text-center">
            <p className="text-red-300">federation link rejected</p>
            <p className="text-xs text-zinc-500">
              The dispatcher at {host.network_name} did not accept this
              console's federation token. It may have been revoked or
              the network was re-keyed.
            </p>
          </div>
        </div>
      );
    }
    return <Login host={host} />;
  }

  return (
    <Layout host={host} me={me.data} mode={mode}>
      <Routes>
        <Route index element={<OverviewPage host={host} />} />
        <Route path="network" element={<NetworkPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="*" element={<Navigate to="" replace />} />
      </Routes>
    </Layout>
  );
}

function Layout({
  host,
  me,
  mode,
  children,
}: {
  host: DispatcherHost;
  me: MeResponse;
  mode: "standalone" | "proxy";
  children: React.ReactNode;
}) {
  const api = useApi();
  const qc = useQueryClient();
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
          {mode === "standalone" && (
            <button
              onClick={() => logout.mutate()}
              disabled={logout.isPending}
              className="rounded border border-zinc-700 px-2 py-1 text-zinc-300 transition hover:border-zinc-500 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              sign out
            </button>
          )}
        </div>
      </header>

      <div className="grid grid-cols-[10rem_1fr] gap-6 px-6 py-6">
        <Sidebar />
        <main className="min-w-0">{children}</main>
      </div>
    </div>
  );
}

function Sidebar() {
  // Relative paths so the same tree works under both "/" (standalone)
  // and "/networks/:id" (proxy). `end` on the index link prevents it
  // from matching the longer paths.
  return (
    <nav className="flex flex-col gap-1 text-xs">
      <NavItem to="" label="overview" end />
      <NavItem to="network" label="network" />
      <NavItem to="devices" label="devices" />
    </nav>
  );
}

function NavItem({
  to,
  label,
  end,
}: {
  to: string;
  label: string;
  end?: boolean;
}) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        [
          "rounded px-3 py-1.5 transition",
          isActive
            ? "bg-zinc-800 text-zinc-100"
            : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
        ].join(" ")
      }
    >
      {label}
    </NavLink>
  );
}
