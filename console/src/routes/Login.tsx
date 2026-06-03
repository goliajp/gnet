import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useApi } from "../api/ApiContext";
import { ApiError } from "../api/client";
import type { LoginRequest, LoginResponse } from "../api/types";
import type { DispatcherHost } from "../shells/DispatcherShell";

export default function Login({ host }: { host: DispatcherHost }) {
  const api = useApi();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const qc = useQueryClient();

  const submit = useMutation({
    mutationFn: (creds: LoginRequest) =>
      api<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(creds),
      }),
    onSuccess: (me) => {
      // Seed the me cache so the shell doesn't re-fetch immediately
      // after the cookie is set.
      qc.setQueryData(["auth", "me"], me);
    },
  });

  return (
    <div className="grid min-h-screen place-items-center px-6">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({ username, password });
        }}
        className="w-full max-w-sm space-y-6 rounded-lg border border-zinc-800 bg-zinc-900/60 p-8 font-mono text-sm shadow-2xl shadow-black/40"
      >
        <header className="space-y-1">
          <p className="text-xs uppercase tracking-wider text-zinc-500">
            dispatcher · v{host.version}
          </p>
          <h1 className="text-lg font-semibold text-zinc-100">
            {host.network_name}
          </h1>
        </header>

        <label className="block space-y-1">
          <span className="text-xs text-zinc-400">username</span>
          <input
            className="w-full rounded border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100 outline-none focus:border-zinc-500"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            autoComplete="username"
          />
        </label>

        <label className="block space-y-1">
          <span className="text-xs text-zinc-400">password</span>
          <input
            type="password"
            className="w-full rounded border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100 outline-none focus:border-zinc-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>

        {submit.isError && (
          <p className="text-xs text-red-300">
            {submit.error instanceof ApiError && submit.error.status === 401
              ? "invalid credentials"
              : (submit.error as Error).message}
          </p>
        )}

        <button
          type="submit"
          disabled={submit.isPending || !username || !password}
          className="w-full rounded bg-zinc-100 px-3 py-2 text-zinc-900 transition hover:bg-white disabled:cursor-not-allowed disabled:bg-zinc-700 disabled:text-zinc-400"
        >
          {submit.isPending ? "…" : "sign in"}
        </button>
      </form>
    </div>
  );
}
