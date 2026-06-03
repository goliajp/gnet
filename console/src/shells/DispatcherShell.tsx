import { useQuery } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import type { HostRoleResponse, MeResponse } from "../api/types";
import Login from "../routes/Login";
import Dashboard from "../routes/dispatcher/Dashboard";

/**
 * Dispatcher SPA shell.
 *
 * Splits on "is there a session" → Login when not, Dashboard when
 * yes. The "me" probe is what gates everything else; once that's
 * cached, every other endpoint just trusts the session cookie.
 */
export default function DispatcherShell({
  host,
}: {
  host: HostRoleResponse;
}) {
  const me = useQuery({
    queryKey: ["auth", "me"],
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
    return <Login host={host} />;
  }
  return <Dashboard host={host} me={me.data} />;
}
