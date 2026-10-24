import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { api } from "../../api/client";
import { useHumanCheck } from "../../api/humanCheck";
import type {
  ConsoleMeResponse,
  EmailRegisterRequest,
  ResendVerificationRequest,
} from "../../api/types";
import { AuthShell, ErrorLine, Field } from "./Login";

export default function ConsoleSignup() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pendingMailFor, setPendingMailFor] = useState<string | null>(null);
  const qc = useQueryClient();
  const nav = useNavigate();
  const humanCheck = useHumanCheck("register");

  const submit = useMutation({
    mutationFn: async (creds: EmailRegisterRequest) =>
      api<ConsoleMeResponse>("/api/auth/email/register", {
        method: "POST",
        body: JSON.stringify({ ...creds, altcha: await humanCheck() }),
      }),
    onSuccess: (me) => {
      // An unconfirmed signup gets no session; marking it signed in
      // here would bounce it to a dashboard it cannot use. It stays on
      // a "check your mail" prompt until the link is followed.
      if (me.verified) {
        qc.setQueryData(["console", "me"], me);
        nav("/dashboard", { replace: true });
      } else {
        setPendingMailFor(me.email ?? "");
      }
    },
  });

  if (pendingMailFor) {
    return <PendingMail email={pendingMailFor} />;
  }

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

function PendingMail({ email }: { email: string }) {
  const [resentAt, setResentAt] = useState<number | null>(null);
  const humanCheck = useHumanCheck("resend");
  const resend = useMutation({
    mutationFn: async (body: ResendVerificationRequest) =>
      api<void>("/api/auth/email/resend-verification", {
        method: "POST",
        body: JSON.stringify({ ...body, altcha: await humanCheck() }),
      }),
    onSuccess: () => setResentAt(Date.now()),
  });

  return (
    <AuthShell title="Check your inbox" subtitle="verification mail sent">
      <p className="text-zinc-300">
        We sent a sign-in link to{" "}
        <span className="font-mono text-zinc-100">{email}</span>. Open it to
        finish creating your account.
      </p>
      <div className="mt-4 space-y-2 text-xs text-zinc-500">
        <p>
          Didn't see it? Check spam, or{" "}
          <button
            type="button"
            onClick={() => resend.mutate({ email })}
            disabled={
              resend.isPending ||
              (resentAt != null && Date.now() - resentAt < 30_000)
            }
            className="text-zinc-300 hover:text-zinc-100 disabled:opacity-50"
          >
            {resend.isPending
              ? "resending…"
              : resentAt != null
                ? "resent ✓"
                : "send another"}
          </button>
          .
        </p>
        <p>
          Already have an account?{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>
          .
        </p>
      </div>
    </AuthShell>
  );
}
