import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router";
import { ApiError, api } from "../../api/client";
import type {
  VerifyEmailRequest,
  VerifyEmailResponse,
} from "../../api/types";
import { AuthShell } from "./Login";

/**
 * `/verify?token=<hex>` — confirms an email-verification token.
 *
 * The shell shows three states: pending (token POST in flight),
 * success (auto-redirects to /dashboard after 2s), failure (the
 * link expired, was reused, or never existed — collapsed to a
 * single error message so a stolen + already-redeemed link can't
 * be distinguished from a forged one).
 */
export default function ConsoleVerify() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const nav = useNavigate();
  const qc = useQueryClient();
  const [auto, setAuto] = useState(false);

  const submit = useMutation({
    mutationFn: (body: VerifyEmailRequest) =>
      api<VerifyEmailResponse>("/api/auth/email/verify", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["console", "me"] });
      setAuto(true);
    },
  });

  // fire immediately on mount when a token is present
  useEffect(() => {
    if (token && !submit.isPending && !submit.isSuccess && !submit.isError) {
      submit.mutate({ token });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  // auto-redirect to /dashboard on success after a moment
  useEffect(() => {
    if (auto) {
      const t = setTimeout(() => nav("/dashboard", { replace: true }), 2000);
      return () => clearTimeout(t);
    }
  }, [auto, nav]);

  if (!token) {
    return (
      <AuthShell title="Verify email" subtitle="">
        <p className="text-zinc-300">No token in the URL.</p>
        <p className="mt-3 text-xs text-zinc-500">
          Check the link in your mail, or{" "}
          <Link to="/login" className="text-zinc-300 hover:text-zinc-100">
            sign in
          </Link>{" "}
          if you've already confirmed.
        </p>
      </AuthShell>
    );
  }

  if (submit.isPending) {
    return (
      <AuthShell title="Verifying…" subtitle="">
        <p className="text-zinc-400">checking your token</p>
      </AuthShell>
    );
  }

  if (submit.isSuccess) {
    return (
      <AuthShell title="Email confirmed" subtitle="redirecting…">
        <p className="text-zinc-300">
          Thanks. Taking you to your dashboard.
        </p>
        <Link
          to="/dashboard"
          className="mt-4 inline-block text-zinc-200 underline-offset-4 hover:underline"
        >
          continue now →
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Verification failed" subtitle="">
      <p className="text-zinc-300">
        {submit.error instanceof ApiError && submit.error.status === 401
          ? "This link has expired or was already used."
          : "We couldn't confirm this link."}
      </p>
      <p className="mt-3 text-xs text-zinc-500">
        Try signing in. If your account is already confirmed, you'll
        land on the dashboard; if not, a fresh verification mail goes
        out on the next sign-up attempt.
      </p>
      <Link
        to="/login"
        className="mt-4 inline-block text-zinc-200 underline-offset-4 hover:underline"
      >
        sign in →
      </Link>
    </AuthShell>
  );
}
