import { useQuery } from "@tanstack/react-query";
import { useApi } from "../api/ApiContext";
import { ApiError } from "../api/client";
import type { HostRoleResponse, MeResponse } from "../api/types";
import Login from "../routes/Login";
import Dashboard from "../routes/dispatcher/Dashboard";

// Narrow the host-role union to the dispatcher variant — the
// dispatcher binary's response is the only one that carries
// `network_name` / `network_id`.
export type DispatcherHost = Extract<HostRoleResponse, { role: "dispatcher" }>;

/**
 * Dispatcher SPA shell.
 *
 * Splits on "is there a session" → Login when not, Dashboard when
 * yes. The "me" probe is what gates everything else; once that's
 * cached, every other endpoint just trusts the session cookie.
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
  return <Dashboard host={host} me={me.data} />;
}
