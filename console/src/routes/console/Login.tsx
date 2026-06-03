import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { ApiError, api } from "../../api/client";
import type {
  ConsoleMeResponse,
  EmailLoginRequest,
} from "../../api/types";

export default function ConsoleLogin() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const qc = useQueryClient();
  const nav = useNavigate();

  const submit = useMutation({
    mutationFn: (creds: EmailLoginRequest) =>
      api<ConsoleMeResponse>("/api/auth/email/login", {
        method: "POST",
        body: JSON.stringify(creds),
      }),
    onSuccess: (me) => {
      qc.setQueryData(["console", "me"], me);
      nav("/dashboard", { replace: true });
    },
  });

  return (
    <AuthShell title="Sign in" subtitle="email + password — OAuth coming soon">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({ email: email.trim().toLowerCase(), password });
        }}
        className="space-y-5"
      >
        <Field
          label="email"
          type="email"
          value={email}
          onChange={setEmail}
          autoComplete="email"
          required
        />
        <Field
          label="password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          required
        />

        {submit.isError && <ErrorLine err={submit.error} />}

        <button
          type="submit"
          disabled={submit.isPending || !email || !password}
          className="w-full rounded-md bg-zinc-100 px-4 py-2.5 font-mono text-sm font-medium text-zinc-950 transition disabled:cursor-not-allowed disabled:opacity-50 enabled:hover:bg-white"
        >
          {submit.isPending ? "…" : "sign in"}
        </button>

        <div className="space-y-2 text-center font-mono text-xs text-zinc-500">
          <p>
            no account?{" "}
            <Link to="/signup" className="text-zinc-300 hover:text-zinc-100">
              create one
            </Link>
          </p>
          <p>
            forgot your password?{" "}
            <Link
              to="/forgot-password"
              className="text-zinc-300 hover:text-zinc-100"
            >
              reset it
            </Link>
          </p>
        </div>
      </form>
    </AuthShell>
  );
}

export function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid min-h-screen place-items-center bg-zinc-950 px-6">
      <div className="w-full max-w-sm space-y-8">
        <div className="space-y-2 text-center">
          <Link
            to="/"
            className="block font-mono text-xs uppercase tracking-[0.2em] text-zinc-500 hover:text-zinc-300"
          >
            ← gnet.golia.jp
          </Link>
          <h1 className="text-xl font-semibold text-zinc-100">{title}</h1>
          <p className="font-mono text-xs text-zinc-500">{subtitle}</p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-8 font-mono text-sm shadow-2xl shadow-black/40">
          {children}
        </div>
      </div>
    </div>
  );
}

export function Field({
  label,
  type,
  value,
  onChange,
  autoComplete,
  required,
  hint,
}: {
  label: string;
  type: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete?: string;
  required?: boolean;
  hint?: string;
}) {
  return (
    <label className="block space-y-1">
      <span className="text-xs text-zinc-400">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        required={required}
        className="w-full rounded border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100 outline-none focus:border-zinc-500"
      />
      {hint && <span className="text-[10px] text-zinc-500">{hint}</span>}
    </label>
  );
}

export function ErrorLine({ err }: { err: unknown }) {
  const msg =
    err instanceof ApiError
      ? err.body || err.message
      : err instanceof Error
        ? err.message
        : "request failed";
  return (
    <p className="rounded border border-rose-900/60 bg-rose-950/40 px-3 py-2 text-xs text-rose-300">
      {msg}
    </p>
  );
}
