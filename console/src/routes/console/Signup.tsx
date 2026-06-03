import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { api } from "../../api/client";
import type {
  ConsoleMeResponse,
  EmailRegisterRequest,
} from "../../api/types";
import { AuthShell, ErrorLine, Field } from "./Login";

export default function ConsoleSignup() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const qc = useQueryClient();
  const nav = useNavigate();

  const submit = useMutation({
    mutationFn: (creds: EmailRegisterRequest) =>
      api<ConsoleMeResponse>("/api/auth/email/register", {
        method: "POST",
        body: JSON.stringify(creds),
      }),
    onSuccess: (me) => {
      qc.setQueryData(["console", "me"], me);
      nav("/dashboard", { replace: true });
    },
  });

  return (
    <AuthShell
      title="Create an account"
      subtitle="email + password — 12+ chars"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({
            email: email.trim().toLowerCase(),
            password,
          });
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
          autoComplete="new-password"
          required
          hint="at least 12 characters"
        />

        {submit.isError && <ErrorLine err={submit.error} />}

        <button
          type="submit"
          disabled={
            submit.isPending || !email || password.length < 12
          }
          className="w-full rounded-md bg-zinc-100 px-4 py-2.5 font-mono text-sm font-medium text-zinc-950 transition disabled:cursor-not-allowed disabled:opacity-50 enabled:hover:bg-white"
        >
          {submit.isPending ? "…" : "create account"}
        </button>

        <p className="text-center font-mono text-xs text-zinc-500">
          already have one?{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
