import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router";
import { ApiError, api } from "../../api/client";
import type { ResetPasswordRequest } from "../../api/types";
import { AuthShell, ErrorLine, Field } from "./Login";

/**
 * `/reset-password?token=<hex>` — consume a reset token and set a
 * new password. The backend also invalidates every live session
 * for the account at the same time, so the user is signed out
 * everywhere; the SPA redirects them to `/login` so they re-auth
 * with the new password.
 */
export default function ConsoleResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const nav = useNavigate();
  const qc = useQueryClient();

  const submit = useMutation({
    mutationFn: (body: ResetPasswordRequest) =>
      api<void>("/api/auth/email/reset-password", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.setQueryData(["console", "me"], null);
      qc.invalidateQueries({ queryKey: ["console"] });
      // brief celebration then send them to log in fresh.
      setTimeout(() => nav("/login", { replace: true }), 1500);
    },
  });

  if (!token) {
    return (
      <AuthShell title="Reset password" subtitle="">
        <p className="text-zinc-300">No token in the URL.</p>
        <p className="mt-3 text-xs text-zinc-500">
          Did the link wrap on the way through your mail client?
          Request a fresh one from{" "}
          <Link
            to="/forgot-password"
            className="text-zinc-300 hover:text-zinc-100"
          >
            forgot-password
          </Link>
          .
        </p>
      </AuthShell>
    );
  }

  if (submit.isSuccess) {
    return (
      <AuthShell title="Password updated" subtitle="all sessions signed out">
        <p className="text-zinc-300">
          Sending you to the sign-in page.
        </p>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Choose a new password"
      subtitle="12+ chars; all other sessions will sign out"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({ token, password });
        }}
        className="space-y-5"
      >
        <Field
          label="new password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
          required
          hint="at least 12 characters"
        />

        {submit.isError && (
          <ErrorLine
            err={
              submit.error instanceof ApiError && submit.error.status === 401
                ? "This link has expired or was already used. Request a new one."
                : submit.error
            }
          />
        )}

        <button
          type="submit"
          disabled={submit.isPending || password.length < 12}
          className="w-full rounded-md bg-zinc-100 px-4 py-2.5 font-mono text-sm font-medium text-zinc-950 transition disabled:cursor-not-allowed disabled:opacity-50 enabled:hover:bg-white"
        >
          {submit.isPending ? "…" : "update password"}
        </button>

        <p className="text-center font-mono text-xs text-zinc-500">
          back to{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
