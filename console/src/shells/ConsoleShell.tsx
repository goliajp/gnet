import { useQuery } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router";
import { ApiError, api } from "../api/client";
import type { ConsoleMeResponse, HostRoleResponse } from "../api/types";
import Landing from "../routes/console/Landing";
import ConsoleLogin from "../routes/console/Login";
import ConsoleSignup from "../routes/console/Signup";
import ConsoleDashboard from "../routes/console/Dashboard";

export type ConsoleHost = Extract<HostRoleResponse, { role: "console" }>;

/**
 * SaaS console shell — `gnet.golia.jp`.
 *
 * Auth probe lands once and is cached by react-query; every page
 * gates on the result. Unauthed visitors land on Landing → Signup /
 * Login. Authed visitors land on Dashboard.
 *
 * Routes (react-router):
 *
 *   /          Landing  (public marketing + sign-in CTA)
 *   /login     Login    (email + password; OAuth links inline)
 *   /signup    Signup   (email + password registration)
 *   /dashboard Dashboard (logged-in: networks list, federation ops)
 *
 * Anything else falls through to a redirect home; the dispatcher
 * SPA's deep-link routes (Devices / Network / Relays / etc) are NOT
 * served by the console shell.
 */
export default function ConsoleShell({ host }: { host: ConsoleHost }) {
  const me = useQuery({
    queryKey: ["console", "me"],
    queryFn: async (): Promise<ConsoleMeResponse | null> => {
      try {
        return await api<ConsoleMeResponse>("/api/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });

  if (me.isLoading) {
    return (
      <div className="grid min-h-screen place-items-center font-mono text-sm text-zinc-500">
        …
      </div>
    );
  }

  const authed = me.data != null;

  return (
    <Routes>
      <Route path="/" element={<Landing host={host} authed={authed} />} />
      <Route
        path="/login"
        element={
          authed ? <Navigate to="/dashboard" replace /> : <ConsoleLogin />
        }
      />
      <Route
        path="/signup"
        element={
          authed ? <Navigate to="/dashboard" replace /> : <ConsoleSignup />
        }
      />
      <Route
        path="/dashboard"
        element={
          authed && me.data ? (
            <ConsoleDashboard host={host} me={me.data} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
