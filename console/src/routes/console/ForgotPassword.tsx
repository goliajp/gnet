import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../../api/client";
import type { ForgotPasswordRequest } from "../../api/types";
import { AuthShell, ErrorLine, Field } from "./Login";

/**
 * `/forgot-password` — request a reset link.
 *
 * The backend ALWAYS returns 200 (so we can't enumerate accounts
 * from the response), so the page collapses the two outcomes into a
 * single confirmation regardless of whether the email actually
 * matched a row. The user learns the mail status from… the actual
 * mail, not us.
 */
export default function ConsoleForgotPassword() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);

  const submit = useMutation({
    mutationFn: (body: ForgotPasswordRequest) =>
      api<void>("/api/auth/email/forgot-password", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => setSent(true),
  });

  if (sent) {
    return (
      <AuthShell title="Check your inbox" subtitle="if that email is on file">
        <p className="text-zinc-300">
          We just sent a reset link to{" "}
          <span className="font-mono text-zinc-100">{email}</span> if an
          account exists with that address. Open it within the hour to
          finish.
        </p>
        <p className="mt-4 text-xs text-zinc-500">
          Back to{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>
          .
        </p>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Reset password" subtitle="we'll mail you a link">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({ email: email.trim().toLowerCase() });
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

        {submit.isError && <ErrorLine err={submit.error} />}

        <button
          type="submit"
          disabled={submit.isPending || !email}
          className="w-full rounded-md bg-zinc-100 px-4 py-2.5 font-mono text-sm font-medium text-zinc-950 transition disabled:cursor-not-allowed disabled:opacity-50 enabled:hover:bg-white"
        >
          {submit.isPending ? "…" : "send reset link"}
        </button>

        <p className="text-center font-mono text-xs text-zinc-500">
          remembered it?{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
